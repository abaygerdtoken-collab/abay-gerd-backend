from flask import Flask, request, jsonify
from flask_cors import CORS
from web3 import Web3
import os

app = Flask(__name__)
CORS(app)

# Load Environment Variables
WEB3_PROVIDER = os.environ.get("WEB3_PROVIDER")
PRIVATE_KEY = os.environ.get("PRIVATE_KEY")
SENDER_ADDRESS = os.environ.get("SENDER_ADDRESS")
TOKEN_CONTRACT_ADDRESS = os.environ.get("TOKEN_CONTRACT_ADDRESS")
TOKEN_DECIMALS = int(os.environ.get("TOKEN_DECIMALS", 2))
SERVER_SECRET_KEY = os.environ.get("SERVER_SECRET_KEY")

# 🔥 Validate Environment Variables
missing_vars = []
if not WEB3_PROVIDER:
    missing_vars.append('WEB3_PROVIDER')
if not PRIVATE_KEY:
    missing_vars.append('PRIVATE_KEY')
if not SENDER_ADDRESS:
    missing_vars.append('SENDER_ADDRESS')
if not TOKEN_CONTRACT_ADDRESS:
    missing_vars.append('TOKEN_CONTRACT_ADDRESS')
if not SERVER_SECRET_KEY:
    missing_vars.append('SERVER_SECRET_KEY')

if missing_vars:
    raise Exception(f"Missing required environment variables: {', '.join(missing_vars)}")

try:
    SENDER_ADDRESS = Web3.to_checksum_address(SENDER_ADDRESS)
except Exception as e:
    raise Exception(f"SENDER_ADDRESS invalid or not checksum format: {e}")

try:
    TOKEN_CONTRACT_ADDRESS = Web3.to_checksum_address(TOKEN_CONTRACT_ADDRESS)
except Exception as e:
    raise Exception(f"TOKEN_CONTRACT_ADDRESS invalid or not checksum format: {e}")

# Connect to BSC via Web3
web3 = Web3(Web3.HTTPProvider(WEB3_PROVIDER))
if not web3.is_connected():
    raise Exception("Failed to connect to Web3 provider!")

# Define ERC20 Token ABI (minimal transfer ABI)
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

@app.route('/')
def home():
    return "Abay GERD Token API is running."

@app.route('/send-token', methods=['POST'])
def send_token():
    try:
        data = request.json
        # Verify server secret to block bots
        if data.get('secret') != SERVER_SECRET_KEY:
            return jsonify({'status': 'error', 'message': 'Unauthorized request'}), 401

        recipient = Web3.to_checksum_address(data['recipient'])
        amount = int(float(data['amount']) * (10 ** TOKEN_DECIMALS))

        nonce = web3.eth.get_transaction_count(SENDER_ADDRESS)
        tx = token_contract.functions.transfer(recipient, amount).build_transaction({
            'from': SENDER_ADDRESS,
            'nonce': nonce,
            'gas': 100000,
            'gasPrice': web3.to_wei('5', 'gwei')
        })

        signed_tx = web3.eth.account.sign_transaction(tx, private_key=PRIVATE_KEY)
        tx_hash = web3.eth.send_raw_transaction(signed_tx.rawTransaction)

        return jsonify({'status': 'success', 'tx_hash': tx_hash.hex()})

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
