from flask import Flask, jsonify
from web3 import Web3
from datetime import datetime
import os

app = Flask(__name__)

# === Configuration ===
RPC_URL = "https://data-seed-prebsc-1-s1.binance.org:8545/"
PRIVATE_KEY = os.getenv("GERD_PRIVATE_KEY")
VESTING_CONTRACT_ADDRESS = "0xC3C2b095C3aA55ACecc7fBA44C6B9D3f56dC43Da"

CONTRACT_ABI = [
    {
        "inputs": [],
        "name": "releaseToken",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "canRelease",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "nextReleaseDate",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function"
    }
]

web3 = Web3(Web3.HTTPProvider(RPC_URL))
account = web3.eth.account.from_key(PRIVATE_KEY)
contract = web3.eth.contract(address=VESTING_CONTRACT_ADDRESS, abi=CONTRACT_ABI)

@app.route("/can-release", methods=["GET"])
def can_release():
    try:
        result = contract.functions.canRelease().call()
        return jsonify(canRelease=result)
    except Exception as e:
        return jsonify(canRelease=False, error=str(e)), 500

@app.route("/next-release-date", methods=["GET"])
def next_release_date():
    try:
        timestamp = contract.functions.nextReleaseDate().call()
        human_readable = datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S UTC')
        return jsonify(nextReleaseTimestamp=timestamp, nextReleaseDate=human_readable)
    except Exception as e:
        return jsonify(error=str(e)), 500

@app.route("/release-token", methods=["POST"])
def release_token():
    try:
        if not contract.functions.canRelease().call():
            return jsonify(success=False, message="Release not allowed yet. Please wait until next scheduled time.")

        nonce = web3.eth.get_transaction_count(account.address)
        txn = contract.functions.releaseToken().build_transaction({
            'from': account.address,
            'nonce': nonce,
            'gas': 200000,
            'gasPrice': web3.to_wei('10', 'gwei')
        })

        signed_txn = web3.eth.account.sign_transaction(txn, private_key=PRIVATE_KEY)
        tx_hash = web3.eth.send_raw_transaction(signed_txn.rawTransaction)
        return jsonify(success=True, tx_hash=tx_hash.hex())

    except Exception as e:
        return jsonify(success=False, message=str(e))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
