import json
import base64
import hashlib
from urllib.parse import urlencode
from flask import Flask, request, jsonify
from flask_cors import CORS
from web3 import Web3
import os
import requests
import firebase_admin
from firebase_admin import credentials, firestore
from datetime import datetime, timedelta, date
import secrets

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": ["https://www.abaygerdtoken.com", "http://localhost:3000"]}})

WEB3_PROVIDER = os.environ.get("WEB3_PROVIDER")
PRIVATE_KEY = os.environ.get("PRIVATE_KEY")
SENDER_ADDRESS = os.environ.get("SENDER_ADDRESS")
TOKEN_CONTRACT_ADDRESS = os.environ.get("TOKEN_CONTRACT_ADDRESS")
TOKEN_DECIMALS = int(os.environ.get("TOKEN_DECIMALS", 2))
RECAPTCHA_SECRET_KEY = os.environ.get("RECAPTCHA_SECRET_KEY")
IPINFO_TOKEN = os.environ.get("IPINFO_TOKEN")

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

@app.route('/auth/session', methods=['GET'])
def generate_session_token():
    token = secrets.token_urlsafe(32)
    expiration = datetime.utcnow() + timedelta(minutes=5)
    session_tokens[token] = expiration
    return jsonify({'session_token': token})

@app.route('/send-token', methods=['POST'])
def send_token():
    data = {} 
    try:
        data = request.get_json(silent=True) or {}

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

        verify_url = "https://www.google.com/recaptcha/api/siteverify"
        recaptcha_verify = requests.post(
            verify_url,
            data={'secret': RECAPTCHA_SECRET_KEY, 'response': recaptcha_response},
            timeout=10
        ).json()

        if not recaptcha_verify.get('success'):
            return jsonify({'status': 'error', 'message': 'Invalid reCAPTCHA'}), 400

        recipient_raw = data.get("recipient")
        if not Web3.is_address(recipient_raw):
            return jsonify({'status': 'error', 'message': 'Invalid wallet address'}), 400

        recipient = Web3.to_checksum_address(recipient_raw)


        wallet_ref = db.collection('wallet_claims').document(recipient)
        if wallet_ref.get().exists:
            return jsonify({'status': 'error', 'message': 'This wallet has already claimed its share of GERD token.'}), 400

        x_forwarded_for = request.headers.get('X-Forwarded-For', '')
        user_ip = x_forwarded_for.split(',')[0].strip() if x_forwarded_for else request.remote_addr

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

        nonce = web3.eth.get_transaction_count(SENDER_ADDRESS)
        tx = token_contract.functions.transfer(recipient, amount_scaled).build_transaction({
            'from': SENDER_ADDRESS,
            'nonce': nonce,
            'gas': 53000,
            'gasPrice': web3.to_wei('1', 'gwei')
        })
        signed_tx = web3.eth.account.sign_transaction(tx, private_key=PRIVATE_KEY)
        tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)

        db.collection('user_data').add({
            'wallet_address': str(recipient),
            'ip': str(user_ip),
            'country': str(country_name),
            'city': str(city),
            'token_amount': amount_str,
            'claimed_at': datetime.utcnow().isoformat() + "Z",
            'tx_hash': tx_hash.hex()
        })

        wallet_ref.set({
            'claimed_at': datetime.utcnow().isoformat() + "Z",
            'ip': str(user_ip),
            'country': str(country_name),
            'city': str(city),
            'token_amount': amount_str,
            'tx_hash': tx_hash.hex()
        })

        if ip_claim_doc.exists:
            ip_claims_ref.update({'count': firestore.Increment(1)})
        else:
            ip_claims_ref.set({'count': 1, 'date': today_str})

        return jsonify({'status': 'success', 'tx_hash': tx_hash.hex()})

    except Exception as e:
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

    _save_etn_oauth_state(state, {
        "code_verifier": code_verifier,
        "nonce": nonce,
        "ip": request.headers.get("X-Forwarded-For", request.remote_addr),
        "ua": request.headers.get("User-Agent", ""),
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

    # Minimal session state: only store sub (no roles/is_og/profile for now)
    claims = {"sub": user_sub}
    profile = {}  # not needed for wallet creation / claims

    # Create session
    session_id = _create_etn_session(tokens=tokens, claims=claims, profile=profile)


    resp = jsonify({
        "status": "success",
        "sessionId": session_id,
        "claims": claims,
        "profile": profile,
    })

    # Optional cookie for convenience (frontend can also store sessionId)
    is_prod = os.environ.get("RENDER", "") != ""

    resp.set_cookie(
        "etn_session",
        session_id,
        httponly=True,
        secure=is_prod,
        samesite="Lax",
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
      "sub": claims.get("sub")
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

