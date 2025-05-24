Abay GERD Backend
The Abay GERD Backend powers the secure backend infrastructure of the Abay GERD Token ecosystem — including smart contract interactions, token vesting automation, reCAPTCHA verification, and backend-triggered token distribution.

🔧 Features
Smart Contract Integration
Interfaces with GERD Token and Vesting contracts on Binance Smart Chain (BSC Testnet and Mainnet).

Automated Vesting
Handles weekly (testnet) or yearly (mainnet) token releases based on contract rules.

CAPTCHA Verification
Ensures only verified users can claim tokens via secure Google reCAPTCHA validation.

RESTful API
Serves structured endpoints for claim forms, dashboards, and vesting UIs.

Environment Separation
Supports fully isolated deployments for testnet and mainnet, with different logic and credentials.

🚀 Deployment
You can deploy the backend on Render or any Node-compatible hosting service.

Environment Variables
Variable	Description
PRIVATE_KEY	Backend signer private key (testnet only)
VESTING_CONTRACT	Vesting contract address
GERD_TOKEN_ADDRESS	GERD token contract address
RECAPTCHA_SECRET	Google reCAPTCHA secret
ALLOWED_ORIGINS	Comma-separated list of allowed origins

📂 API Endpoints
GET /can-release
Returns whether tokens can be released at the current time.

POST /release-token
Triggers the releaseToken() function using the backend wallet (testnet only).

POST /verify-captcha
Validates a user's reCAPTCHA response.

🧪 Testnet Configuration
To accelerate testing of the real 115-year schedule (1B GERD/year), the testnet vesting contract releases 1B tokens every Wednesday.

Testnet Addresses

Token: 0xb926C538FF1297d5C756309A55F5811740a57caE

Vesting: 0xC3C2b095C3aA55ACecc7fBA44C6B9D3f56dC43Da

🖥️ Local Development
Prerequisites
Node.js v18+

npm or yarn

Setup
bash
Copy
Edit
git clone https://github.com/YOUR-USERNAME/abay-gerd-backend.git
cd abay-gerd-backend
npm install
Running Locally
Create a .env file with the necessary environment variables:

bash
Copy
Edit
cp .env.example .env
Then start the server:

bash
Copy
Edit
npm start
🤝 Contributing
We welcome community developers to improve this backend. To contribute:

Fork the repo

Create a new branch: git checkout -b feature/my-feature

Make your changes

Commit and push: git commit -m "Add my feature" then git push origin feature/my-feature

Submit a pull request

🎁 Contributors may receive GERD token rewards based on the value of their contributions.

📜 License
This project is licensed under the MIT License.
