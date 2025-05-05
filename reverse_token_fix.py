
from firebase_admin import firestore, initialize_app, credentials

# Initialize Firebase
cred = credentials.Certificate("/etc/secrets/abay-firebase.json")
initialize_app(cred)
db = firestore.client()

user_data_ref = db.collection("user_data")
docs = user_data_ref.stream()

target_value = "100000000000"
correction_value = "1000000"

for doc in docs:
    data = doc.to_dict()
    token_amount = data.get("token_amount")
    try:
        if token_amount == target_value:
            user_data_ref.document(doc.id).update({
                "token_amount": correction_value
            })
            print(f"🔁 Corrected {doc.id}: {token_amount} → {correction_value}")
        else:
            print(f"⏩ Skipped {doc.id}: token_amount = {token_amount}")
    except Exception as e:
        print(f"⚠️ Error processing {doc.id}: {e}")
