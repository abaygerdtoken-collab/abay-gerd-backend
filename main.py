from flask import Flask, request, jsonify
from flask_cors import CORS
from web3 import Web3
import os

app = Flask(__name__)
CORS(app)

WEB3_PROVIDER = os.environ.get("WEB3_PROVIDER")
PRIVATE_KEY = os.environ.get("PRIVATE_KEY")
SENDER_ADDRESS = os.environ.get("SENDER_ADDRESS")
TOKEN_CONTRACT_ADDRESS = os.environ.get("TOKEN_CONTRACT_ADDRESS")
TOKEN_DECIMALS = int(os.environ.get("TOKEN_DECIMALS", 2))

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

web3 = Web3(Web3.HTTPProvider(WEB3_PROVIDER))
token_contract = web3.eth.contract(address=Web3.to_checksum_address(TOKEN_CONTRACT_ADDRESS), abi=TOKEN_ABI)

@app.route('/send-token', methods=['POST'])
def send_token():
    try:
        data = request.json
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

@app.route('/')
def home():
    return "Abay GERD Token API is running."

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
