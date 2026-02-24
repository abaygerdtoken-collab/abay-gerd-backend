import json
import base64
import hashlib
from urllib.parse import urlencode
from flask import Flask, request, jsonify, redirect
from flask_cors import CORS
from web3 import Web3
from eth_keys import keys
import os
import requests
import firebase_admin
from firebase_admin import credentials, firestore
from datetime import datetime, timedelta, date
import secrets
import hmac
import time
from google.api_core.exceptions import AlreadyExists

app = Flask(__name__)
CORS(app, resources={r"/*": {
    "origins": ["https://www.abaygerdtoken.com", "https://abaygerdtoken.com"],
    "supports_credentials": True
}})

# ==========================================================
# TradingView -> MEXC Executor (in-memory idempotency)
# ==========================================================

TV_PASSPHRASE = os.getenv("TV_PASSPHRASE", "")
MEXC_API_KEY = os.getenv("MEXC_API_KEY", "")
MEXC_API_SECRET = os.getenv("MEXC_API_SECRET", "")
MEXC_FUTURES_BASE = os.getenv("MEXC_FUTURES_BASE", "https://api.mexc.com")
DRY_RUN = os.getenv("DRY_RUN", "true").lower() == "true"

ALLOWED_SYMBOLS = set(s.strip().upper() for s in os.getenv("ALLOWED_SYMBOLS", "BTC_USDT,ETH_USDT").split(","))
RECV_WINDOW_MS = int(os.getenv("RECV_WINDOW_MS", "10000"))
MAX_SIGNAL_AGE_SEC = int(os.getenv("MAX_SIGNAL_AGE_SEC", "90"))
COOLDOWN_SECONDS = int(os.getenv("COOLDOWN_SECONDS", "10"))
PRICE_PROTECT = int(os.getenv("PRICE_PROTECT", "1"))

_last_trade_ts = {}      # symbol -> last trade time
_seen_client_oids = {}   # oid -> first seen time

def _now_ms() -> int:
    return int(time.time() * 1000)

def _to_mexc_symbol(tv_symbol: str) -> str:
    s = tv_symbol.upper().replace(".P", "").replace("-", "").replace("/", "")
    if s.endswith("USDT") and "_" not in s:
        return s[:-4] + "_USDT"
    return s

def _cooldown_ok(symbol: str) -> bool:
    ts = _last_trade_ts.get(symbol, 0.0)
    return (time.time() - ts) >= COOLDOWN_SECONDS

def _set_cooldown(symbol: str):
    _last_trade_ts[symbol] = time.time()

def _is_dup_oid(oid: str) -> bool:
    return oid in _seen_client_oids

def _remember_oid(oid: str):
    _seen_client_oids[oid] = time.time()
    cutoff = time.time() - 24 * 3600
    for k, v in list(_seen_client_oids.items()):
        if v < cutoff:
            _seen_client_oids.pop(k, None)

def _hmac_sha256_hex(secret: str, msg: str) -> str:
    return hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()

def _mexc_request(method: str, path: str, params=None, body=None):
    """
    MEXC Futures OPEN-API signing (headers-based).
    - GET/DELETE: sign sorted querystring
    - POST: sign raw JSON string and send the exact same bytes
    """
    if not DRY_RUN and (not MEXC_API_KEY or not MEXC_API_SECRET):
        raise Exception("Missing MEXC_API_KEY / MEXC_API_SECRET")

    params = params or {}
    body = body or {}
    ts = str(_now_ms())

    raw_json = None  # only used for POST

    if method.upper() in ("GET", "DELETE"):
        items = [(k, params[k]) for k in sorted(params.keys()) if params[k] is not None]
        param_str = "&".join([f"{k}={v}" for k, v in items])
    else:
        body = {k: v for k, v in body.items() if v is not None}
        raw_json = json.dumps(body, separators=(",", ":"), ensure_ascii=False)
        param_str = raw_json

    sign_payload = f"{MEXC_API_KEY}{ts}{param_str}"
    signature = _hmac_sha256_hex(MEXC_API_SECRET, sign_payload)

    url = f"{MEXC_FUTURES_BASE}{path}"

    # MEXC expects the recv window in SECONDS (1..60), and the header key is Revc-Window
    recv_window_sec = max(1, min(60, int(RECV_WINDOW_MS / 1000)))

    headers = {
        "Content-Type": "application/json",
        "ApiKey": MEXC_API_KEY,
        "Request-Time": ts,
        "Signature": signature,
        "Revc-Window": str(recv_window_sec),
    }

    if DRY_RUN:
        return {
            "dry_run": True,
            "method": method.upper(),
            "url": url,
            "params": params if method.upper() in ("GET", "DELETE") else None,
            "body": body if method.upper() == "POST" else None,
            "raw_json": raw_json,
        }

    r = requests.request(
        method.upper(),
        url,
        params=params if method.upper() in ("GET", "DELETE") else None,
        data=raw_json if method.upper() == "POST" else None,
        headers=headers,
        timeout=20,
    )

    try:
        data = r.json()
    except Exception:
        raise Exception(f"Non-JSON from MEXC: {r.status_code} {r.text[:300]}")

    if r.status_code >= 400 or (isinstance(data, dict) and data.get("success") is False):
        raise Exception(f"MEXC error: {data}")

    return data


def _validate_tv_payload(p: dict) -> dict:
    if not TV_PASSPHRASE:
        raise Exception("TV_PASSPHRASE missing")

    if p.get("passphrase") != TV_PASSPHRASE:
        raise Exception("Invalid passphrase")

    symbol_tv = str(p.get("symbol", "")).upper().replace(".P", "")
    if symbol_tv not in ALLOWED_SYMBOLS:
        raise Exception(f"Symbol not allowed: {symbol_tv}")


    if not _cooldown_ok(symbol_tv):
        raise Exception(f"Cooldown active for {symbol_tv}")

    direction = str(p.get("direction", "")).upper()
    if direction not in ("LONG", "SHORT"):
        raise Exception("direction must be LONG or SHORT")

    qty = float(p.get("qty", 0) or 0)
    if qty <= 0:
        raise Exception("qty must be > 0")

    leverage = int(p.get("leverage", 1) or 1)
    if leverage < 1 or leverage > 500:
        raise Exception("Invalid leverage")

    margin_mode = str(p.get("marginMode", "ISOLATED")).upper()
    if margin_mode not in ("ISOLATED", "CROSS", "CROSSED"):
        raise Exception("marginMode must be ISOLATED or CROSS")
 
    time_close = int(p.get("timeClose", 0) or 0)
    if time_close <= 0:
        raise Exception("timeClose (ms) is required")

    now = _now_ms()

    # Reject timestamps too far in the future (clock glitches)
    if time_close > now + 5000:
        raise Exception("timeClose is in the future (more than 5s). Rejecting for safety.")

    # Reject stale signals
    age_sec = (now - time_close) / 1000.0
    if age_sec > MAX_SIGNAL_AGE_SEC:
        raise Exception(f"Stale signal: age {age_sec:.1f}s > {MAX_SIGNAL_AGE_SEC}s")

    client_oid = str(p.get("clientOrderId", "")).strip()
    if not client_oid:
        raise Exception("clientOrderId is required")
    if _is_dup_oid(client_oid):
        raise Exception("Duplicate clientOrderId")

    entry = float(p.get("entry", 0) or 0)
    stop_loss = float(p.get("stopLoss", 0) or 0)
    take_profit = float(p.get("takeProfit", 0) or 0)
    if entry <= 0 or stop_loss <= 0 or take_profit <= 0:
        raise Exception("entry/stopLoss/takeProfit must be > 0")
    # Sanity check: bracket must make sense
    if direction == "LONG":
        if not (stop_loss < entry < take_profit):
            raise Exception("Invalid LONG bracket: must be stopLoss < entry < takeProfit")
    else:  # SHORT
        if not (take_profit < entry < stop_loss):
            raise Exception("Invalid SHORT bracket: must be takeProfit < entry < stopLoss")

    mexc_symbol = _to_mexc_symbol(symbol_tv)
    open_type = 1 if margin_mode == "ISOLATED" else 2  # 1 isolated, 2 cross
    side = 1 if direction == "LONG" else 3             # 1 open long, 3 open short

    return {
        "symbol_tv": symbol_tv,
        "symbol": mexc_symbol,
        "qty": qty,
        "leverage": leverage,
        "openType": open_type,
        "side": side,
        "entry": entry,
        "stopLoss": stop_loss,
        "takeProfit": take_profit,
        "clientOrderId": client_oid,
    }



WEB3_PROVIDER = os.environ.get("WEB3_PROVIDER")
PRIVATE_KEY = os.environ.get("PRIVATE_KEY")
SENDER_ADDRESS = os.environ.get("SENDER_ADDRESS")
TOKEN_CONTRACT_ADDRESS = os.environ.get("TOKEN_CONTRACT_ADDRESS")
TOKEN_DECIMALS = int(os.environ.get("TOKEN_DECIMALS", 2))
RECAPTCHA_SECRET_KEY = os.environ.get("RECAPTCHA_SECRET_KEY")
RECAPTCHA_ALLOWED_HOSTNAMES = {
    h.strip().lower()
    for h in os.environ.get("RECAPTCHA_ALLOWED_HOSTNAMES", "www.abaygerdtoken.com,abaygerdtoken.com").split(",")
    if h.strip()
}
RECAPTCHA_EXPECTED_ACTION = os.environ.get("RECAPTCHA_EXPECTED_ACTION", "claim").strip().lower()
RECAPTCHA_MIN_SCORE = float(os.environ.get("RECAPTCHA_MIN_SCORE", "0.5"))
RECAPTCHA_ENFORCE_V3 = os.environ.get("RECAPTCHA_ENFORCE_V3", "false").lower() == "true"
IPINFO_TOKEN = os.environ.get("IPINFO_TOKEN")


def _get_client_ip() -> str:
    x_forwarded_for = request.headers.get('X-Forwarded-For', '')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.remote_addr or ''


def _is_inapp_or_webview(user_agent: str) -> bool:
    ua = (user_agent or "").lower()

    bad_markers = [
        "okex-guanwang", "okapp/(okex", "brokerdomain/www.okx.com",
        "metamask", "trust", "trustwallet", "coinbasewallet", "cbwallet",
        "binance", "bnb", "safepal", "tokenpocket", "imtoken", "bitget",
        "bybit", "gateio", "kucoin", "huobi", "mexc", "okx",
        " wv", "webview", "; wv)", "version/4.0",
        "line/", "micromessenger", "fbav", "fban", "instagram", "tiktok",
        "snapchat", "pinterest", "telegram", "discord",
    ]

    return any(marker in ua for marker in bad_markers)

COUNTRY_CODE_TO_NAME = {
    "AF": "Afghanistan",
    "AL": "Albania",
    "DZ": "Algeria",
    "AS": "American Samoa",
    "AD": "Andorra",
    "AO": "Angola",
    "AI": "Anguilla",
    "AQ": "Antarctica",
    "AG": "Antigua and Barbuda",
    "AR": "Argentina",
    "AM": "Armenia",
    "AW": "Aruba",
    "AU": "Australia",
    "AT": "Austria",
    "AZ": "Azerbaijan",
    "BS": "Bahamas",
    "BH": "Bahrain",
    "BD": "Bangladesh",
    "BB": "Barbados",
    "BY": "Belarus",
    "BE": "Belgium",
    "BZ": "Belize",
    "BJ": "Benin",
    "BM": "Bermuda",
    "BT": "Bhutan",
    "BO": "Bolivia, Plurinational State of",
    "BQ": "Bonaire, Sint Eustatius and Saba",
    "BA": "Bosnia and Herzegovina",
    "BW": "Botswana",
    "BV": "Bouvet Island",
    "BR": "Brazil",
    "IO": "British Indian Ocean Territory",
    "BN": "Brunei Darussalam",
    "BG": "Bulgaria",
    "BF": "Burkina Faso",
    "BI": "Burundi",
    "CV": "Cabo Verde",
    "KH": "Cambodia",
    "CM": "Cameroon",
    "CA": "Canada",
    "KY": "Cayman Islands",
    "CF": "Central African Republic",
    "TD": "Chad",
    "CL": "Chile",
    "CN": "China",
    "CX": "Christmas Island",
    "CC": "Cocos (Keeling) Islands",
    "CO": "Colombia",
    "KM": "Comoros",
    "CG": "Congo",
    "CD": "Congo, The Democratic Republic of the",
    "CK": "Cook Islands",
    "CR": "Costa Rica",
    "HR": "Croatia",
    "CU": "Cuba",
    "CW": "Curaçao",
    "CY": "Cyprus",
    "CZ": "Czechia",
    "CI": "Côte d'Ivoire",
    "DK": "Denmark",
    "DJ": "Djibouti",
    "DM": "Dominica",
    "DO": "Dominican Republic",
    "EC": "Ecuador",
    "EG": "Egypt",
    "SV": "El Salvador",
    "GQ": "Equatorial Guinea",
    "ER": "Eritrea",
    "EE": "Estonia",
    "SZ": "Eswatini",
    "ET": "Ethiopia",
    "FK": "Falkland Islands (Malvinas)",
    "FO": "Faroe Islands",
    "FJ": "Fiji",
    "FI": "Finland",
    "FR": "France",
    "GF": "French Guiana",
    "PF": "French Polynesia",
    "TF": "French Southern Territories",
    "GA": "Gabon",
    "GM": "Gambia",
    "GE": "Georgia",
    "DE": "Germany",
    "GH": "Ghana",
    "GI": "Gibraltar",
    "GR": "Greece",
    "GL": "Greenland",
    "GD": "Grenada",
    "GP": "Guadeloupe",
    "GU": "Guam",
    "GT": "Guatemala",
    "GG": "Guernsey",
    "GN": "Guinea",
    "GW": "Guinea-Bissau",
    "GY": "Guyana",
    "HT": "Haiti",
    "HM": "Heard Island and McDonald Islands",
    "VA": "Holy See (Vatican City State)",
    "HN": "Honduras",
    "HK": "Hong Kong",
    "HU": "Hungary",
    "IS": "Iceland",
    "IN": "India",
    "ID": "Indonesia",
    "IR": "Iran, Islamic Republic of",
    "IQ": "Iraq",
    "IE": "Ireland",
    "IM": "Isle of Man",
    "IL": "Israel",
    "IT": "Italy",
    "JM": "Jamaica",
    "JP": "Japan",
    "JE": "Jersey",
    "JO": "Jordan",
    "KZ": "Kazakhstan",
    "KE": "Kenya",
    "KI": "Kiribati",
    "KP": "Korea, Democratic People's Republic of",
    "KR": "Korea, Republic of",
    "KW": "Kuwait",
    "KG": "Kyrgyzstan",
    "LA": "Lao People's Democratic Republic",
    "LV": "Latvia",
    "LB": "Lebanon",
    "LS": "Lesotho",
    "LR": "Liberia",
    "LY": "Libya",
    "LI": "Liechtenstein",
    "LT": "Lithuania",
    "LU": "Luxembourg",
    "MO": "Macao",
    "MG": "Madagascar",
    "MW": "Malawi",
    "MY": "Malaysia",
    "MV": "Maldives",
    "ML": "Mali",
    "MT": "Malta",
    "MH": "Marshall Islands",
    "MQ": "Martinique",
    "MR": "Mauritania",
    "MU": "Mauritius",
    "YT": "Mayotte",
    "MX": "Mexico",
    "FM": "Micronesia, Federated States of",
    "MD": "Moldova, Republic of",
    "MC": "Monaco",
    "MN": "Mongolia",
    "ME": "Montenegro",
    "MS": "Montserrat",
    "MA": "Morocco",
    "MZ": "Mozambique",
    "MM": "Myanmar",
    "NA": "Namibia",
    "NR": "Nauru",
    "NP": "Nepal",
    "NL": "Netherlands",
    "NC": "New Caledonia",
    "NZ": "New Zealand",
    "NI": "Nicaragua",
    "NE": "Niger",
    "NG": "Nigeria",
    "NU": "Niue",
    "NF": "Norfolk Island",
    "MK": "North Macedonia",
    "MP": "Northern Mariana Islands",
    "NO": "Norway",
    "OM": "Oman",
    "PK": "Pakistan",
    "PW": "Palau",
    "PS": "Palestine, State of",
    "PA": "Panama",
    "PG": "Papua New Guinea",
    "PY": "Paraguay",
    "PE": "Peru",
    "PH": "Philippines",
    "PN": "Pitcairn",
    "PL": "Poland",
    "PT": "Portugal",
    "PR": "Puerto Rico",
    "QA": "Qatar",
    "RO": "Romania",
    "RU": "Russian Federation",
    "RW": "Rwanda",
    "RE": "Réunion",
    "BL": "Saint Barthélemy",
    "SH": "Saint Helena, Ascension and Tristan da Cunha",
    "KN": "Saint Kitts and Nevis",
    "LC": "Saint Lucia",
    "MF": "Saint Martin (French part)",
    "PM": "Saint Pierre and Miquelon",
    "VC": "Saint Vincent and the Grenadines",
    "WS": "Samoa",
    "SM": "San Marino",
    "ST": "Sao Tome and Principe",
    "SA": "Saudi Arabia",
    "SN": "Senegal",
    "RS": "Serbia",
    "SC": "Seychelles",
    "SL": "Sierra Leone",
    "SG": "Singapore",
    "SX": "Sint Maarten (Dutch part)",
    "SK": "Slovakia",
    "SI": "Slovenia",
    "SB": "Solomon Islands",
    "SO": "Somalia",
    "ZA": "South Africa",
    "GS": "South Georgia and the South Sandwich Islands",
    "SS": "South Sudan",
    "ES": "Spain",
    "LK": "Sri Lanka",
    "SD": "Sudan",
    "SR": "Suriname",
    "SJ": "Svalbard and Jan Mayen",
    "SE": "Sweden",
    "CH": "Switzerland",
    "SY": "Syrian Arab Republic",
    "TW": "Taiwan, Province of China",
    "TJ": "Tajikistan",
    "TZ": "Tanzania, United Republic of",
    "TH": "Thailand",
    "TL": "Timor-Leste",
    "TG": "Togo",
    "TK": "Tokelau",
    "TO": "Tonga",
    "TT": "Trinidad and Tobago",
    "TN": "Tunisia",
    "TR": "Turkey",
    "TM": "Turkmenistan",
    "TC": "Turks and Caicos Islands",
    "TV": "Tuvalu",
    "UG": "Uganda",
    "UA": "Ukraine",
    "AE": "United Arab Emirates",
    "GB": "United Kingdom",
    "US": "United States",
    "UM": "United States Minor Outlying Islands",
    "UY": "Uruguay",
    "UZ": "Uzbekistan",
    "VU": "Vanuatu",
    "VE": "Venezuela, Bolivarian Republic of",
    "VN": "Viet Nam",
    "VG": "Virgin Islands, British",
    "VI": "Virgin Islands, U.S.",
    "WF": "Wallis and Futuna",
    "EH": "Western Sahara",
    "YE": "Yemen",
    "ZM": "Zambia",
    "ZW": "Zimbabwe",
    "AX": "Åland Islands"
}

web3 = Web3(Web3.HTTPProvider(WEB3_PROVIDER))
if not web3.is_connected():
    raise Exception("Failed to connect to Web3 provider!")

SENDER_ADDRESS = Web3.to_checksum_address(SENDER_ADDRESS)
TOKEN_CONTRACT_ADDRESS = Web3.to_checksum_address(TOKEN_CONTRACT_ADDRESS)

TOKEN_ABI = [{
    "constant": False,
    "inputs": [{"name": "_to", "type": "address"}, {"name": "_value", "type": "uint256"}],
    "name": "transfer",
    "outputs": [{"name": "", "type": "bool"}],
    "type": "function"
}]
token_contract = web3.eth.contract(address=TOKEN_CONTRACT_ADDRESS, abi=TOKEN_ABI)

cred_path = os.environ.get("FIREBASE_CRED_PATH")
if not cred_path or not os.path.exists(cred_path):
    raise Exception("FIREBASE_CRED_PATH is missing or invalid")
cred = credentials.Certificate(cred_path)


firebase_admin.initialize_app(cred)
db = firestore.client()

session_tokens = {}

@app.route('/')
def home():
    return "Abay GERD Token API is running."

@app.route("/webhook/tv_trade", methods=["POST"])
def tv_trade():
    payload = request.get_json(silent=True) or {}

    # Log payload safely (don’t leak passphrase)
    safe_payload = dict(payload)
    if "passphrase" in safe_payload:
        safe_payload["passphrase"] = "***"
    print("TV PAYLOAD:", safe_payload)

    # Kill switch
    if os.getenv("TRADING_ENABLED", "true").lower() != "true":
        return jsonify({"accepted": False, "error": "Trading disabled (TRADING_ENABLED!=true)"}), 403

    try:
        data = _validate_tv_payload(payload)

        # Duplicate protection (return 409 instead of generic 400)
        if _is_dup_oid(data["clientOrderId"]):
            return jsonify({"accepted": False, "error": "Duplicate clientOrderId"}), 409

        # Record the client OID before exchange call
        _remember_oid(data["clientOrderId"])

        # Optional hard cap (strongly recommended)
        max_qty = float(os.getenv("MAX_QTY", "999999999"))
        if float(data["qty"]) > max_qty:
            return jsonify({"accepted": False, "error": f"qty exceeds MAX_QTY ({max_qty})"}), 400

        body = {
            "symbol": data["symbol"],
            "price": data["entry"],
            "vol": data["qty"],
            "leverage": data["leverage"],
            "side": data["side"],
            "type": 5,  # market
            "openType": data["openType"],
            "externalOid": data["clientOrderId"],
            "stopLossPrice": data["stopLoss"],
            "takeProfitPrice": data["takeProfit"],
            "lossTrend": 1,
            "profitTrend": 1,
            "priceProtect": PRICE_PROTECT,
        }
        print("MEXC ORDER BODY:", body)

        resp = _mexc_request("POST", "/api/v1/private/order/submit", body=body)

        # Cooldown should use the validated TV symbol (not raw payload)
        _set_cooldown(data["symbol_tv"])

        return jsonify({
            "accepted": True,
            "normalized": data,
            "mexc": resp,
            "dry_run": DRY_RUN
        }), 200

    except Exception as e:
        # Log exact reason so you can debug 400s from Render logs
        print("TV ERROR:", str(e))
        return jsonify({"accepted": False, "error": str(e)}), 400

@app.route('/auth/session', methods=['GET'])
def generate_session_token():
    token = secrets.token_urlsafe(32)
    expiration = datetime.utcnow() + timedelta(minutes=5)
    session_tokens[token] = expiration
    return jsonify({'session_token': token})

@app.route('/send-token', methods=['POST'])
def send_token():
    data = {} 
    wallet_ref = None
    claim_reserved = False
    tx_hash_hex = ''
    try:
        data = request.get_json(silent=True) or {}

        if os.getenv("BLOCK_INAPP_BROWSERS", "true").lower() == "true":
            ua = request.headers.get("User-Agent", "")
            if _is_inapp_or_webview(ua):
                return jsonify({
                    'status': 'error',
                    'message': 'In-app browsers are not supported for claims. Please open this page in Chrome or Safari.'
                }), 403

        session_token = data.get('session_token')
        if not session_token or session_token not in session_tokens:
            return jsonify({'status': 'error', 'message': 'Missing or invalid session token'}), 403
        if datetime.utcnow() > session_tokens[session_token]:
            session_tokens.pop(session_token, None)
            return jsonify({'status': 'error', 'message': 'Session token expired'}), 403
        session_tokens.pop(session_token, None)

        recaptcha_response = data.get('recaptchaToken')
        if not recaptcha_response:
            return jsonify({'status': 'error', 'message': 'Please complete reCAPTCHA'}), 400

        if not RECAPTCHA_SECRET_KEY:
            return jsonify({'status': 'error', 'message': 'reCAPTCHA is not configured on the server'}), 500

        user_ip = _get_client_ip()

        verify_url = "https://www.google.com/recaptcha/api/siteverify"
        try:
            recaptcha_verify = requests.post(
                verify_url,
                data={
                    'secret': RECAPTCHA_SECRET_KEY,
                    'response': recaptcha_response,
                    'remoteip': user_ip
                },
                timeout=10
            ).json()
        except Exception:
            return jsonify({'status': 'error', 'message': 'Failed to verify reCAPTCHA'}), 400

        if not recaptcha_verify.get('success'):
            return jsonify({'status': 'error', 'message': 'Invalid reCAPTCHA'}), 400

        hostname = str(recaptcha_verify.get('hostname', '')).strip().lower()
        if not hostname or hostname not in RECAPTCHA_ALLOWED_HOSTNAMES:
            return jsonify({'status': 'error', 'message': 'Captcha hostname mismatch'}), 400

        action = str(recaptcha_verify.get('action', '')).strip().lower()
        if action:
            if RECAPTCHA_EXPECTED_ACTION and action != RECAPTCHA_EXPECTED_ACTION:
                return jsonify({'status': 'error', 'message': 'Captcha action mismatch'}), 400
        elif RECAPTCHA_ENFORCE_V3:
            return jsonify({'status': 'error', 'message': 'Captcha action missing'}), 400

        score_raw = recaptcha_verify.get('score', None)
        if score_raw is not None:
            try:
                score = float(score_raw)
            except Exception:
                score = 0.0
            if score < RECAPTCHA_MIN_SCORE:
                return jsonify({'status': 'error', 'message': 'Captcha score too low'}), 400
        elif RECAPTCHA_ENFORCE_V3:
            return jsonify({'status': 'error', 'message': 'Captcha score missing'}), 400

        recipient_raw = data.get("recipient")
        if not Web3.is_address(recipient_raw):
            return jsonify({'status': 'error', 'message': 'Invalid wallet address'}), 400

        recipient = Web3.to_checksum_address(recipient_raw)


        wallet_ref = db.collection('wallet_claims').document(recipient)

        country_code = ''
        country_name = ''
        city = ''

        try:
            ipinfo_url = f'https://ipinfo.io/{user_ip}?token={IPINFO_TOKEN}'
            location_data = requests.get(ipinfo_url, timeout=5).json()
            country_code = location_data.get('country', '')
            city = location_data.get('city', '')
        except Exception:
            pass

        try:
            fallback_data = requests.get(f'https://ipapi.co/{user_ip}/json/', timeout=5).json()
            if not country_code:
                country_code = fallback_data.get('country_code', '')
            country_name = fallback_data.get('country_name', '')
            if not city:
                city = fallback_data.get('city', '')
        except Exception:
            pass

        if not country_name:
            country_name = COUNTRY_CODE_TO_NAME.get(country_code, '')

        if not country_code:
            return jsonify({'status': 'error', 'message': 'Could not determine your country. Claim blocked for safety.'}), 400

        today_str = date.today().isoformat()
        ip_claims_ref = db.collection('ip_claims').document(f"{user_ip}_{today_str}")
        ip_claim_doc = ip_claims_ref.get()
        if ip_claim_doc.exists and ip_claim_doc.to_dict().get('count', 0) >= 15:
            return jsonify({'status': 'error', 'message': 'Daily claim limit reached for your IP'}), 429

        amount_tokens = 75000 if country_code == 'ET' else 10000
        amount_scaled = int(amount_tokens * (10 ** TOKEN_DECIMALS))
        amount_str = str(amount_scaled)

        try:
            wallet_ref.create({
                'status': 'pending',
                'created_at': datetime.utcnow().isoformat() + "Z",
                'ip': str(user_ip),
                'country': str(country_name),
                'city': str(city),
                'token_amount': amount_str,
            })
            claim_reserved = True
        except AlreadyExists:
            return jsonify({'status': 'error', 'message': 'This wallet has already claimed its share of GERD token.'}), 400

        nonce = web3.eth.get_transaction_count(SENDER_ADDRESS)
        tx = token_contract.functions.transfer(recipient, amount_scaled).build_transaction({
            'from': SENDER_ADDRESS,
            'nonce': nonce,
            'gas': 53000,
            'gasPrice': web3.to_wei('1', 'gwei')
        })
        signed_tx = web3.eth.account.sign_transaction(tx, private_key=PRIVATE_KEY)
        tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)
        tx_hash_hex = tx_hash.hex()

        wallet_ref.set({
            'status': 'completed',
            'claimed_at': datetime.utcnow().isoformat() + "Z",
            'ip': str(user_ip),
            'country': str(country_name),
            'city': str(city),
            'token_amount': amount_str,
            'tx_hash': tx_hash_hex
        }, merge=True)

        db.collection('user_data').add({
            'wallet_address': str(recipient),
            'ip': str(user_ip),
            'country': str(country_name),
            'city': str(city),
            'token_amount': amount_str,
            'claimed_at': datetime.utcnow().isoformat() + "Z",
            'tx_hash': tx_hash_hex
        })

        if ip_claim_doc.exists:
            ip_claims_ref.update({'count': firestore.Increment(1)})
        else:
            ip_claims_ref.set({'count': 1, 'date': today_str})

        return jsonify({'status': 'success', 'tx_hash': tx_hash_hex})

    except Exception as e:
        if claim_reserved and wallet_ref is not None and not tx_hash_hex:
            try:
                wallet_ref.delete()
            except Exception:
                pass
        db.collection('failed_data').add({
            'wallet_address': data.get('recipient', ''),
            'error': str(e)
        })
        return jsonify({'status': 'error', 'message': str(e)}), 400

# ==========================================================
# ETN Identity OAuth (Authorization Code + PKCE)
# ==========================================================

ETN_CLIENT_ID = os.environ.get("ETN_CLIENT_ID")
ETN_CLIENT_SECRET = os.environ.get("ETN_CLIENT_SECRET")
ETN_REDIRECT_URI = os.environ.get("ETN_REDIRECT_URI")
ETN_SCOPE = os.environ.get("ETN_SCOPE", "openid profile offline_access")

# Provided by you (ETN Developer Portal)
ETN_AUTHORIZE_URL = os.environ.get("ETN_AUTHORIZE_URL", "https://account.etnecosystem.org/authorize")

# Common ETN endpoints (override via env vars if ETN provides different ones)
ETN_TOKEN_URL = os.environ.get("ETN_TOKEN_URL", "https://auth.etnecosystem.org/api/v1/oauth/token")

def _require_etn_env():
    missing = []
    if not ETN_CLIENT_ID:
        missing.append("ETN_CLIENT_ID")
    if not ETN_CLIENT_SECRET:
        missing.append("ETN_CLIENT_SECRET")
    if not ETN_REDIRECT_URI:
        missing.append("ETN_REDIRECT_URI")
    return missing


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _pkce_pair():
    # RFC 7636 S256
    code_verifier = _b64url(secrets.token_bytes(32))
    code_challenge = _b64url(hashlib.sha256(code_verifier.encode("utf-8")).digest())
    return code_verifier, code_challenge


def _decode_jwt_no_verify(jwt_token: str) -> dict:
    """
    Minimal JWT decode (no signature verification).
    ETN requires you to read is_og instantly from id_token for business logic.
    If you want, we can add JWKS signature verification next.
    """
    try:
        parts = jwt_token.split(".")
        if len(parts) < 2:
            return {}
        payload_b64 = parts[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        payload_json = base64.urlsafe_b64decode(payload_b64.encode("utf-8")).decode("utf-8")
        return json.loads(payload_json)
    except Exception:
        return {}


def _save_etn_oauth_state(state: str, data: dict, ttl_minutes: int = 10):
    expires_at = datetime.utcnow() + timedelta(minutes=ttl_minutes)
    db.collection("etn_oauth_states").document(state).set({
        **data,
        "expiresAt": expires_at,
        "createdAt": datetime.utcnow(),
    })


def _consume_etn_oauth_state(state: str):
    ref = db.collection("etn_oauth_states").document(state)
    snap = ref.get()
    if not snap.exists:
        return None
    data = snap.to_dict()
    ref.delete()  # one-time
    exp = data.get("expiresAt")
    try:
        if exp and exp < datetime.utcnow():
            return None
    except Exception:
        pass
    return data


def _create_etn_session(tokens: dict, claims: dict, profile: dict, ttl_days: int = 30) -> str:
    session_id = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(days=ttl_days)
    db.collection("etn_sessions").document(session_id).set({
        "tokens": tokens,
        "claims": claims,
        "profile": profile,
        "expiresAt": expires_at,
        "createdAt": datetime.utcnow(),
    })
    return session_id

def _get_etn_session(session_id: str):
    snap = db.collection("etn_sessions").document(session_id).get()
    if not snap.exists:
        return None
    data = snap.to_dict()
    exp = data.get("expiresAt")
    try:
        if exp and exp < datetime.utcnow():
            db.collection("etn_sessions").document(session_id).delete()
            return None
    except Exception:
        pass
    return data

def _update_etn_session(session_id: str, tokens: dict, claims: dict, profile: dict):
    db.collection("etn_sessions").document(session_id).set({
        "tokens": tokens,
        "claims": claims,
        "profile": profile,
        "updatedAt": datetime.utcnow(),
    }, merge=True)

@app.route("/auth/etn/login", methods=["GET"])
def etn_login():
    missing = _require_etn_env()
    if missing:
        return jsonify({"status": "error", "message": "Missing ETN env vars", "missing": missing}), 500

    # Create OAuth params
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    code_verifier, code_challenge = _pkce_pair()

        # Detect frontend URL at login time
    
    frontend_url = "https://www.abaygerdtoken.com"

    _save_etn_oauth_state(state, {
        "code_verifier": code_verifier,
        "nonce": nonce,
        "ip": request.headers.get("X-Forwarded-For", request.remote_addr),
        "ua": request.headers.get("User-Agent", ""),
        "frontend_url": frontend_url,
    })

    params = {
        "response_type": "code",
        "client_id": ETN_CLIENT_ID,
        "redirect_uri": ETN_REDIRECT_URI,
        "scope": ETN_SCOPE,
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }

    authorize_url = f"{ETN_AUTHORIZE_URL}?{urlencode(params)}"
    return jsonify({"authorizeUrl": authorize_url})


@app.route("/auth/etn/callback", methods=["GET"])
def etn_callback():
    missing = _require_etn_env()
    if missing:
        return jsonify({"status": "error", "message": "Missing ETN env vars", "missing": missing}), 500

    err = request.args.get("error")
    if err:
        return jsonify({"status": "error", "error": err, "error_description": request.args.get("error_description")}), 400

    code = request.args.get("code")
    state = request.args.get("state")
    if not code or not state:
        return jsonify({"status": "error", "message": "Missing code or state"}), 400

    st = _consume_etn_oauth_state(state)
    if not st:
        return jsonify({"status": "error", "message": "Invalid or expired state"}), 400

    # Exchange code -> tokens
    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": ETN_CLIENT_ID,
        "client_secret": ETN_CLIENT_SECRET,
        "redirect_uri": ETN_REDIRECT_URI,
        "code_verifier": st.get("code_verifier"),
    }

    r = requests.post(ETN_TOKEN_URL, json=payload, timeout=20)
    try:
        tokens = r.json()
    except Exception:
        return jsonify({"status": "error", "message": "Token exchange returned non-JSON", "http_status": r.status_code, "body": r.text[:300]}), 502

    if r.status_code >= 400 or tokens.get("error"):
        return jsonify({"status": "error", "message": "Token exchange failed", "details": tokens}), 400

    # Decode id_token ONLY to extract stable ETN user id (sub)
    raw_claims = _decode_jwt_no_verify(tokens.get("id_token", ""))
    user_sub = raw_claims.get("sub")

    if not user_sub:
        return jsonify({"status": "error", "message": "ETN id_token missing 'sub'"}), 400

    # Derive deterministic BSC wallet address from user_sub (same pattern as Web3Auth)
    # This ensures the same user always gets the same wallet address
    private_key_bytes = hashlib.sha256(user_sub.encode()).digest()
    private_key_obj = keys.PrivateKey(private_key_bytes)
    wallet_address = private_key_obj.public_key.to_checksum_address()

    # Minimal session state: store sub and derived wallet address
    claims = {"sub": user_sub, "wallet_address": wallet_address}
    profile = {}  # not needed for wallet creation / claims

    # Create session
    session_id = _create_etn_session(tokens=tokens, claims=claims, profile=profile)

        # Use frontend URL saved during /auth/etn/login
    frontend_base = st.get("frontend_url", "https://www.abaygerdtoken.com")
    frontend_url = f"{frontend_base}/auth?etn_callback=true"

    # Redirect to frontend
    resp = redirect(frontend_url)

    # Set session cookie
    is_prod = os.environ.get("RENDER", "") != ""

    resp.set_cookie(
        "etn_session",
        session_id,
        httponly=True,
        secure=True,
        samesite="None",
        max_age=60 * 60 * 24 * 30,
    )
    return resp


@app.route("/auth/etn/me", methods=["GET"])
def etn_me():
    session_id = request.cookies.get("etn_session") or request.args.get("sessionId")
    if not session_id:
        return jsonify({"status": "error", "message": "Missing session"}), 401

    sess = _get_etn_session(session_id)
    if not sess:
        return jsonify({"status": "error", "message": "Invalid session"}), 401

    claims = sess.get("claims", {})
    return jsonify({
      "status": "success",
      "sub": claims.get("sub"),
      "wallet_address": claims.get("wallet_address")
    })


@app.route("/auth/etn/refresh", methods=["POST"])
def etn_refresh():
    missing = _require_etn_env()
    if missing:
        return jsonify({"status": "error", "message": "Missing ETN env vars", "missing": missing}), 500
    body = request.get_json(silent=True) or {}
    session_id = request.cookies.get("etn_session") or body.get("sessionId")
    if not session_id:
        return jsonify({"status": "error", "message": "Missing session"}), 401

    sess = _get_etn_session(session_id)
    if not sess:
        return jsonify({"status": "error", "message": "Invalid session"}), 401

    tokens = sess.get("tokens", {})
    refresh_token = tokens.get("refresh_token")
    if not refresh_token:
        return jsonify({"status": "error", "message": "No refresh_token available (offline_access missing?)"}), 400

    payload = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": ETN_CLIENT_ID,
        "client_secret": ETN_CLIENT_SECRET,
    }

    r = requests.post(ETN_TOKEN_URL, json=payload, timeout=20)
    try:
        new_tokens = r.json()
    except Exception:
        return jsonify({"status": "error", "message": "Refresh returned non-JSON", "http_status": r.status_code, "body": r.text[:300]}), 502

    if r.status_code >= 400 or new_tokens.get("error"):
        return jsonify({"status": "error", "message": "Refresh failed", "details": new_tokens}), 400

    merged = {**tokens, **new_tokens}

    # Update sub if token rotated (rare, but keep safe)
    claims = sess.get("claims", {})
    if merged.get("id_token"):
        raw_claims = _decode_jwt_no_verify(merged["id_token"])
        if raw_claims.get("sub"):
            claims = {"sub": raw_claims["sub"]}

    profile = {}  # still not needed


    _update_etn_session(session_id=session_id, tokens=merged, claims=claims, profile=profile)

    return jsonify({"status": "success", "claims": claims, "profile": profile})


@app.route("/auth/etn/logout", methods=["POST"])
def etn_logout():
    body = request.get_json(silent=True) or {}
    session_id = request.cookies.get("etn_session") or body.get("sessionId")
    if session_id:
        db.collection("etn_sessions").document(session_id).delete()

    resp = jsonify({"status": "success"})
    resp.set_cookie("etn_session", "", expires=0)
    return resp


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "10000"))
    app.run(host="0.0.0.0", port=port)

