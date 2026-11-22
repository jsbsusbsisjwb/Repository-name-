import os, time, hmac, hashlib
from urllib.parse import parse_qsl
import requests
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)
BOT_TOKEN = os.getenv('BOT_TOKEN', '').strip()
VERIFY_SECRET = os.getenv('WEB_VERIFY_SECRET', '').strip()
TURNSTILE_SECRET = os.getenv('TURNSTILE_SECRET_KEY', '').strip()
SITE_KEY = os.getenv('TURNSTILE_SITE_KEY', '').strip()


def telegram_init_data_user(init_data: str):
    if not BOT_TOKEN or not init_data:
        return None
    try:
        pairs = dict(parse_qsl(init_data, keep_blank_values=True))
        received_hash = pairs.pop('hash', '')
        auth_date = int(pairs.get('auth_date', '0'))
        if not received_hash or abs(int(time.time()) - auth_date) > 3600:
            return None
        check_string = '\n'.join(f'{k}={v}' for k, v in sorted(pairs.items()))
        secret_key = hmac.new(b'WebAppData', BOT_TOKEN.encode(), hashlib.sha256).digest()
        calculated = hmac.new(secret_key, check_string.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(calculated, received_hash):
            return None
        import json
        user = json.loads(pairs.get('user', '{}'))
        return int(user.get('id', 0)) or None
    except Exception:
        return None


@app.get('/')
def index():
    if not SITE_KEY:
        return 'TURNSTILE_SITE_KEY is not configured', 503
    return render_template('index.html', site_key=SITE_KEY)


@app.post('/verify')
def verify():
    if not (BOT_TOKEN and VERIFY_SECRET and TURNSTILE_SECRET):
        return jsonify(ok=False, error='Server verification settings are incomplete'), 503
    body = request.get_json(silent=True) or {}
    state = str(body.get('state', ''))
    init_data = str(body.get('initData', ''))
    captcha_token = str(body.get('token', ''))
    uid = telegram_init_data_user(init_data)
    if not uid or not state or len(state) > 200 or not captcha_token:
        return jsonify(ok=False, error='Invalid Telegram session or challenge'), 400
    try:
        resp = requests.post('https://challenges.cloudflare.com/turnstile/v0/siteverify',
            data={'secret': TURNSTILE_SECRET, 'response': captcha_token,
                  'remoteip': request.headers.get('CF-Connecting-IP', request.remote_addr)}, timeout=12)
        result = resp.json()
    except Exception:
        return jsonify(ok=False, error='Could not contact verification provider'), 502
    if not result.get('success'):
        return jsonify(ok=False, error='Human verification failed. Please try again.'), 403
    ts = int(time.time())
    raw = f'{uid}|{state}|{ts}'.encode()
    proof = hmac.new(VERIFY_SECRET.encode(), raw, hashlib.sha256).hexdigest()
    return jsonify(ok=True, uid=uid, state=state, ts=ts, proof=proof)


@app.get('/health')
def health():
    return jsonify(ok=True)
