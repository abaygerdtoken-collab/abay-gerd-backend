
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
CORS(app)

WEB3_PROVIDER = os.environ.get("WEB3_PROVIDER")
PRIVATE_KEY = os.environ.get("PRIVATE_KEY")
SENDER_ADDRESS = os.environ.get("SENDER_ADDRESS")
TOKEN_CONTRACT_ADDRESS = os.environ.get("TOKEN_CONTRACT_ADDRESS")
TOKEN_DECIMALS = int(os.environ.get("TOKEN_DECIMALS", 2))
RECAPTCHA_SECRET_KEY = os.environ.get("RECAPTCHA_SECRET_KEY")
IPINFO_TOKEN = os.environ.get("IPINFO_TOKEN")

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

cred = credentials.Certificate('/etc/secrets/abay-firebase.json')
firebase_admin.initialize_app(cred)
db = firestore.client()

session_tokens = {}

@app.route('/')
def home():
    return "Abay GERD Token API v3 is running."

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
            return jsonify({'status': 'error', 'message': 'Missing reCAPTCHA token'}), 400

        verify_url = "https://www.google.com/recaptcha/api/siteverify"
        recaptcha_verify = requests.post(verify_url, data={
            'secret': RECAPTCHA_SECRET_KEY,
            'response': recaptcha_response
        }).json()

        if not recaptcha_verify.get('success'):
            return jsonify({'status': 'error', 'message': 'Invalid reCAPTCHA'}), 400

        recipient = Web3.to_checksum_address(data['recipient'])

        wallet_ref = db.collection('wallet_claims').document(recipient)
        if wallet_ref.get().exists:
            return jsonify({'status': 'error', 'message': 'This wallet has already claimed. Please check your balance'}), 400

        x_forwarded_for = request.headers.get('X-Forwarded-For', '')
        user_ip = x_forwarded_for.split(',')[0].strip() if x_forwarded_for else request.remote_addr
        print("✅ Using IP for geo check:", user_ip, flush=True)

        location_data = {}
        try:
            ipinfo_url = f'https://ipinfo.io/{user_ip}?token={IPINFO_TOKEN}'
            location_data = requests.get(ipinfo_url).json()
        except Exception as e:
            print("⚠️ ipinfo.io failed:", e, flush=True)

        country = location_data.get('country', '')
        city = location_data.get('city', '')
        country_code = country if country else ''

        if not country_code:
            try:
                fallback_data = requests.get(f'https://ipapi.co/{user_ip}/json/').json()
                print("🌍 ipapi.co fallback response:", fallback_data, flush=True)
                country_code = fallback_data.get('country_code', '')
                country = fallback_data.get('country_name', '')
                city = fallback_data.get('city', '')
            except Exception as e:
                print("❌ ipapi.co fallback failed:", e, flush=True)

        print("🧪 Final server-detected country_code:", country_code, flush=True)

        if not country_code:
            return jsonify({'status': 'error', 'message': 'Could not determine your country. Claim blocked for safety.'}), 400

        today_str = date.today().isoformat()
        ip_claims_ref = db.collection('ip_claims').document(f"{user_ip}_{today_str}")
        ip_claim_doc = ip_claims_ref.get()
        if ip_claim_doc.exists and ip_claim_doc.to_dict().get('count', 0) >= 15:
            return jsonify({'status': 'error', 'message': 'Daily claim limit reached for your IP'}), 429

        amount_tokens = 75000 if country_code == 'ET' else 10000
        amount = int(amount_tokens * (10 ** TOKEN_DECIMALS))

        nonce = web3.eth.get_transaction_count(SENDER_ADDRESS)
        tx = token_contract.functions.transfer(recipient, amount).build_transaction({
            'from': SENDER_ADDRESS,
            'nonce': nonce,
            'gas': 52006,
            'gasPrice': web3.to_wei('1', 'gwei')
        })
        signed_tx = web3.eth.account.sign_transaction(tx, private_key=PRIVATE_KEY)
        tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)

        db.collection('user_data').add({
            'wallet_address': str(recipient),
            'ip': str(user_ip),
            'country': str(country),
            'city': str(city),
            'token_amount': str(amount_tokens),
            'claimed_at': datetime.utcnow().isoformat() + "Z",
            'tx_hash': tx_hash.hex()
        })

        wallet_ref.set({
            'claimed_at': datetime.utcnow().isoformat() + "Z",
            'ip': str(user_ip),
            'country': str(country),
            'city': str(city),
            'token_amount': str(amount_tokens),
            'tx_hash': tx_hash.hex()
        })

        if ip_claim_doc.exists:
            ip_claims_ref.update({'count': firestore.Increment(1)})
        else:
            ip_claims_ref.set({'count': 1, 'date': today_str})

        return jsonify({'status': 'success', 'tx_hash': tx_hash.hex()})

    except Exception as e:
        print("❌ Exception occurred:", e, flush=True)
        db.collection('failed_data').add({
            'wallet_address': data.get('recipient', ''),
            'error': str(e)
        })
        return jsonify({'status': 'error', 'message': str(e)}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
