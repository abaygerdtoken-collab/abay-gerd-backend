from flask import Flask, request, jsonify
from flask_cors import CORS
from web3 import Web3
import os
import requests
import firebase_admin
from firebase_admin import credentials, firestore

app = Flask(__name__)
CORS(app)

# Load Environment Variables
WEB3_PROVIDER = os.environ.get("WEB3_PROVIDER")
PRIVATE_KEY = os.environ.get("PRIVATE_KEY")
SENDER_ADDRESS = os.environ.get("SENDER_ADDRESS")
TOKEN_CONTRACT_ADDRESS = os.environ.get("TOKEN_CONTRACT_ADDRESS")
TOKEN_DECIMALS = int(os.environ.get("TOKEN_DECIMALS", 2))
SERVER_SECRET_KEY = os.environ.get("SERVER_SECRET_KEY")
RECAPTCHA_SECRET_KEY = os.environ.get("RECAPTCHA_SECRET_KEY")
BSC_API_KEY = os.environ.get("BSC_API_KEY")
FIREBASE_PROJECT_ID = os.environ.get("FIREBASE_PROJECT_ID")
FIREBASE_PRIVATE_KEY = os.environ.get("FIREBASE_PRIVATE_KEY").replace("\\n", "\n")
FIREBASE_CLIENT_EMAIL = os.environ.get("FIREBASE_CLIENT_EMAIL")

# Validate Environment Variables
required_vars = [WEB3_PROVIDER, PRIVATE_KEY, SENDER_ADDRESS, TOKEN_CONTRACT_ADDRESS,
                 SERVER_SECRET_KEY, RECAPTCHA_SECRET_KEY, BSC_API_KEY,
                 FIREBASE_PROJECT_ID, FIREBASE_PRIVATE_KEY, FIREBASE_CLIENT_EMAIL]
if not all(required_vars):
    raise Exception("Missing one or more required environment variables!")

# Setup Web3
web3 = Web3(Web3.HTTPProvider(WEB3_PROVIDER))
if not web3.is_connected():
    raise Exception("Failed to connect to Web3 provider!")

SENDER_ADDRESS = Web3.to_checksum_address(SENDER_ADDRESS)
TOKEN_CONTRACT_ADDRESS = Web3.to_checksum_address(TOKEN_CONTRACT_ADDRESS)

# Setup Token Contract
TOKEN_ABI = [
    {
        "constant": False,
        "inputs": [
            {"name": "_to", "type": "address"},
            {"name": "_value", "type": "uint256"}
        ],
        "name": "transfer",
        "outputs": [{"name": "", "type": "bool"}],
        "type": "function"
    }
]
token_contract = web3.eth.contract(address=TOKEN_CONTRACT_ADDRESS, abi=TOKEN_ABI)

# Setup Firebase
cred = credentials.Certificate({
    "type": "service_account",
    "project_id": FIREBASE_PROJECT_ID,
    "private_key": FIREBASE_PRIVATE_KEY,
    "client_email": FIREBASE_CLIENT_EMAIL,
    "token_uri": "https://oauth2.googleapis.com/token"
})
firebase_admin.initialize_app(cred)
db = firestore.client()

@app.route('/')
def home():
    return "Abay GERD Token API is running."

@app.route('/send-token', methods=['POST'])
def send_token():
    try:
        data = request.json

        # Step 1: Secret Key Validation
        if data.get('secret') != SERVER_SECRET_KEY:
            return jsonify({'status': 'error', 'message': 'Unauthorized request'}), 401

        # Step 2: reCAPTCHA Validation
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

        # Step 3: Prepare Recipient
        recipient = Web3.to_checksum_address(data['recipient'])
        amount = int(float(data['amount']) * (10 ** TOKEN_DECIMALS))

        # Step 4: Duplicate Check with BscScan
        check_url = f"https://api.bscscan.com/api?module=account&action=tokentx&address={recipient}&contractaddress={TOKEN_CONTRACT_ADDRESS}&apikey={BSC_API_KEY}"
        check_result = requests.get(check_url).json()
        if check_result.get('result') and isinstance(check_result['result'], list) and len(check_result['result']) > 0:
            return jsonify({'status': 'error', 'message': 'Wallet already claimed before.'}), 400

        # Step 5: Send Token Transaction
        nonce = web3.eth.get_transaction_count(SENDER_ADDRESS)
        tx = token_contract.functions.transfer(recipient, amount).build_transaction({
            'from': SENDER_ADDRESS,
            'nonce': nonce,
            'gas': 100000,
            'gasPrice': web3.to_wei('5', 'gwei')
        })
        signed_tx = web3.eth.account.sign_transaction(tx, private_key=PRIVATE_KEY)
        tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)

        # Step 6: Save to Firestore - user_data
        claim_data = {
            'wallet': recipient,
            'ip': data.get('ip', ''),
            'country': data.get('country', ''),
            'city': data.get('city', ''),
            'amount': amount,
            'tx_hash': tx_hash.hex()
        }
        db.collection('user_data').add(claim_data)

        return jsonify({'status': 'success', 'tx_hash': tx_hash.hex()})

    except Exception as e:
        # Save to Firestore - failed_data
        fail_data = {
            'wallet': data.get('recipient', ''),
            'ip': data.get('ip', ''),
            'country': data.get('country', ''),
            'city': data.get('city', ''),
            'error': str(e)
        }
        db.collection('failed_data').add(fail_data)
        return jsonify({'status': 'error', 'message': str(e)}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
