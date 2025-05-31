from flask import Flask, jsonify, request
from flask_cors import CORS
from web3 import Web3
from datetime import datetime, timezone, timedelta
import os

app = Flask(__name__)
CORS(app)
# === Configuration ===
RPC_URL = "https://data-seed-prebsc-1-s1.binance.org:8545/"
PRIVATE_KEY = os.getenv("GERD_PRIVATE_KEY")
VESTING_CONTRACT_ADDRESS = "0xC3C2b095C3aA55ACecc7fBA44C6B9D3f56dC43Da"

CONTRACT_ABI = [
    {
        "inputs": [],
        "name": "releaseTokens",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "lastReleaseTime",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function"
    }
]

web3 = Web3(Web3.HTTPProvider(RPC_URL))
account = web3.eth.account.from_key(PRIVATE_KEY)
contract = web3.eth.contract(address=VESTING_CONTRACT_ADDRESS, abi=CONTRACT_ABI)

@app.route("/", methods=["GET"])
def home():
    return "GERD Vesting API (adjusted) is running ✅"

@app.route("/last-release-time", methods=["GET"])
def last_release_time():
    try:
        timestamp = contract.functions.lastReleaseTime().call()
        human_readable = datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S UTC')
        return jsonify(lastReleaseTime=timestamp, lastReleaseTimeUTC=human_readable)
    except Exception as e:
        return jsonify(error=str(e)), 500

@app.route("/can-release", methods=["GET"])
def can_release():
    try:
        last_time = contract.functions.lastReleaseTime().call()
        now = datetime.now(timezone.utc)
        last_dt = datetime.utcfromtimestamp(last_time).replace(tzinfo=timezone.utc)
        next_dt = last_dt + timedelta(days=7)
        day_of_week = now.weekday()  # Monday=0, Sunday=6

        eligible = now >= next_dt and day_of_week == 2  # 2 = Wednesday
        return jsonify(canRelease=eligible, nextEligibleUTC=next_dt.strftime('%Y-%m-%d %H:%M:%S UTC'))
    except Exception as e:
        return jsonify(canRelease=False, error=str(e)), 500

@app.route("/release-token", methods=["POST"])
def release_token():
    try:
        # Let smart contract enforce logic — this only submits tx
        nonce = web3.eth.get_transaction_count(account.address)
        txn = contract.functions.releaseTokens().build_transaction({
            'from': account.address,
            'nonce': nonce,
            'gas': 200000,
            'gasPrice': web3.to_wei('10', 'gwei')
        })
        signed_txn = web3.eth.account.sign_transaction(txn, private_key=PRIVATE_KEY)
        tx_hash = web3.eth.send_raw_transaction(signed_txn.raw_transaction)

        return jsonify(success=True, tx_hash=tx_hash.hex())
    except Exception as e:
        return jsonify(success=False, message=str(e))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
