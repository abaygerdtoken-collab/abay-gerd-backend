# GERD Token Claim Backend

This is the backend API for the Abay GERD Token claim system. It handles:

- reCAPTCHA verification
- IP-based geolocation and rate-limiting
- Token transfer via Web3 to Binance Smart Chain
- Logging of claim events to Firebase Firestore

---

## Setup Instructions

### 1. Clone the Repo
```bash
git clone https://github.com/AbayGERDToken/gerd-claim-backend.git
cd gerd-claim-backend
```

### 2. Set Environment Variables
Create a `.env` file:
```
WEB3_PROVIDER=your_web3_provider_url
PRIVATE_KEY=your_private_key
SENDER_ADDRESS=0xYourSenderAddress
TOKEN_CONTRACT_ADDRESS=0xGERDTokenAddress
TOKEN_DECIMALS=2
RECAPTCHA_SECRET_KEY=your_recaptcha_secret
IPINFO_TOKEN=your_ipinfo_token
FIREBASE_CRED_PATH=/etc/secrets/abay-firebase.json
```

### 3. Run Locally
```bash
pip install -r requirements.txt
python main.py
```

### 4. Deploy on Render
Use `render.yaml` to deploy this API using Render's free Python web service.

## License
MIT License
