
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
CORS(app, resources={r"/*": {"origins": "https://www.abaygerdtoken.com"}})

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
    try:
        data = request.json

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
        recaptcha_verify = requests.post(verify_url, data={
            'secret': RECAPTCHA_SECRET_KEY,
            'response': recaptcha_response
        }).json()

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
            location_data = requests.get(ipinfo_url).json()
            country_code = location_data.get('country', '')
            city = location_data.get('city', '')
        except Exception:
            pass

        try:
            fallback_data = requests.get(f'https://ipapi.co/{user_ip}/json/').json()
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

@app.route('/webhook/send-doc', methods=['POST'])
def send_pandadoc():
    import sys
    data = request.json.get('customData', {})  # ✅ Get correct sub-payload from GHL
    print("📦 Incoming customData Payload:", data, file=sys.stdout, flush=True)

    # CLIENT data
    client_first_name = data.get('client_first_name', '')
    client_last_name = data.get('client_last_name', '')
    client_email = data.get('client_email', '')
    client_phone = data.get('client_phone', '')
    client_street = data.get('client_street', '')
    client_city = data.get('client_city', '')
    client_state = data.get('client_state', '')
    client_postal = data.get('client_postal', '')

    # SENDER data
    sender_first_name = data.get('sender_first_name', '')
    sender_last_name = data.get('sender_last_name', '')
    sender_email = data.get('sender_email', '')

    PANDADOC_API_KEY = os.environ.get("PANDADOC_API_KEY")
    TEMPLATE_ID = os.environ.get("PANDADOC_TEMPLATE_ID")
    API_URL = 'https://api.pandadoc.com/public/v1/documents'

    headers = {
        'Authorization': f'API-Key {PANDADOC_API_KEY}',
        'Content-Type': 'application/json'
    }

    payload = {
        "name": f"{client_first_name} {client_last_name} Agreement",
        "template_uuid": TEMPLATE_ID,
        "status": "sent",  # ✅ Send immediately
        "send_email": True,
        "recipients": [
            {
                "email": client_email,
                "first_name": client_first_name,
                "last_name": client_last_name,
                "role": "Client",
                "fields": {
                    "StreetAddress": client_street,
                    "City": client_city,
                    "State": client_state,
                    "PostalCode": client_postal,
                    "Phone": client_phone
                }
            },
            {
                "email": sender_email,
                "first_name": sender_first_name,
                "last_name": sender_last_name,
                "role": "Sender"
            }
        ]
    }

    response = requests.post(API_URL, headers=headers, json=payload)

    try:
        return jsonify(response.json()), response.status_code
    except Exception:
        return {"error": "Non-JSON response from PandaDoc"}, 500


from cryptography.hazmat.primitives import serialization
import time, jwt

USER_ID = "aee6ec85-0785-481e-88fc-76d86997c9f2"
ACCOUNT_ID = "9dc45c0a-8409-49e6-8d87-04dbb7cb5137"
INTEGRATION_KEY = "c3707e9c-c61b-4aa1-a05f-247d9acdebb9"
TEMPLATE_ID = "773bc8b8-9ae7-415e-8fc5-2e36812e4d0b"
BASE_URL = "https://na4.docusign.net"

DOCUSIGN_PRIVATE_KEY = os.environ.get("DOCUSIGN_RSA_PRIVATE_KEY")
if not DOCUSIGN_PRIVATE_KEY:
    raise Exception("Missing DOCUSIGN_RSA_PRIVATE_KEY environment variable.")

def format_currency(value, default="0.00"):
    try:
        return f"{float(str(value).replace(',', '').strip()):,.2f}"
    except (ValueError, TypeError):
        return f"{float(default):,.2f}"

def get_access_token():
    current_time = int(time.time())
    payload = {
        "iss": INTEGRATION_KEY,
        "sub": USER_ID,
        "aud": "account.docusign.com",
        "iat": current_time,
        "exp": current_time + 3600,
        "scope": "signature impersonation"
    }

    private_key_bytes = DOCUSIGN_PRIVATE_KEY.encode("utf-8")
    token = jwt.encode(payload, private_key_bytes, algorithm="RS256")

    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": token
    }

    res = requests.post("https://account.docusign.com/oauth/token", headers=headers, data=data)
    res.raise_for_status()
    return res.json()["access_token"]

@app.route("/webhook/send-docusign", methods=["POST"])
def send_docusign():
    data = request.json.get("customData", {})

    client_email = data.get("client_email")
    client_name = f"{data.get('client_first_name', '')} {data.get('client_last_name', '')}"
    client_seller_name = data.get("client_seller_name")
    if not client_seller_name:
        client_seller_name = client_name

    tabs_sender = {
        "textTabs": [
            {"tabLabel": "FirstName", "value": data.get("client_first_name", ""), "locked": False },
            {"tabLabel": "LastName", "value": data.get("client_last_name", ""), "locked": False},
            {"tabLabel": "StreetAddress", "value": data.get("client_street", ""), "locked": False},
            {"tabLabel": "City", "value": data.get("client_city", ""), "locked": False},
            {"tabLabel": "State", "value": data.get("client_state", ""), "locked": False},
            {"tabLabel": "PostalCode", "value": data.get("client_postal", ""), "locked": False},
            {"tabLabel": "Phone", "value": data.get("client_phone", ""), "locked": False},
            {"tabLabel": "Email", "value": data.get("client_email", ""), "locked": False},
            {"tabLabel": "APN", "value": data.get("client_apn", ""), "locked": False},
            {
             "tabLabel": "PurchasePrice",
             "value": format_currency(data.get('client_price', "0")),
             "locked": False
            },
            {"tabLabel": "CloseOfEscrow", "value": data.get("client_close_date", ""), "locked": False},
            {"tabLabel": "SellerName", "value": data.get("client_seller_name", ""), "locked": False},
            {"tabLabel": "Deposit", "value": format_currency(data.get('client_deposit', "500.00")), "locked": False}
        ]
    }

    tabs_client = {
        "textTabs": [
            {"tabLabel": "FirstName", "value": data.get("client_first_name", ""), "locked": True},
            {"tabLabel": "LastName", "value": data.get("client_last_name", ""), "locked": True},
            {"tabLabel": "StreetAddress", "value": data.get("client_street", ""), "locked": True},
            {"tabLabel": "City", "value": data.get("client_city", ""), "locked": True},
            {"tabLabel": "State", "value": data.get("client_state", ""), "locked": True},
            {"tabLabel": "PostalCode", "value": data.get("client_postal", ""), "locked": True},
            {"tabLabel": "Phone", "value": data.get("client_phone", ""), "locked": True},
            {"tabLabel": "Email", "value": data.get("client_email", ""), "locked": True},
            {"tabLabel": "APN", "value": data.get("client_apn", ""), "locked": True},
            {"tabLabel": "PurchasePrice", "value": data.get("client_price", ""), "locked": True},
            {"tabLabel": "CloseOfEscrow", "value": data.get("client_close_date", ""), "locked": True},
            {"tabLabel": "SellerName", "value": data.get("client_seller_name", ""), "locked": True},
            {"tabLabel": "Deposit", "value": data.get("client_deposit", "500.00"), "locked": True}
        ]
    }

    access_token = get_access_token()

    envelope_payload = {
        "templateId": TEMPLATE_ID,
        "status": "sent",
        "templateRoles": [
            {
                "roleName": "Sender",
                "name": "KarmaExit-Sender",
                "email": "ephremfuffa@gmail.com",
                "routingOrder": "1",
                "tabs": tabs_sender
            },
            {
                "roleName": "Client",
                "name": client_seller_name,
                "email": client_email,
                "routingOrder": "2",
                "tabs": tabs_client
            }
        ]
    }

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    url = f"{BASE_URL}/restapi/v2.1/accounts/{ACCOUNT_ID}/envelopes"
    response = requests.post(url, headers=headers, json=envelope_payload)

    if response.status_code >= 400:
        return jsonify({"error": response.text}), response.status_code

    return jsonify(response.json()), 201

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
