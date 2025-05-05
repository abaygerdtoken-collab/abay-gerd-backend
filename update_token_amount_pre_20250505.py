
from firebase_admin import firestore, initialize_app, credentials
from datetime import datetime

# Initialize Firebase
cred = credentials.Certificate("/etc/secrets/abay-firebase.json")
initialize_app(cred)
db = firestore.client()

# Cutoff date
cutoff = datetime.fromisoformat("2025-05-05T00:00:00")

# Reference collection
user_data_ref = db.collection("user_data")
docs = user_data_ref.stream()

for doc in docs:
    data = doc.to_dict()
    try:
        claimed_at = datetime.fromisoformat(data.get("claimed_at", "").replace("Z", ""))
        if claimed_at < cutoff:
            original_amount = int(data.get("token_amount", "0"))
            updated_amount = original_amount * 10
            user_data_ref.document(doc.id).update({
                "token_amount": str(updated_amount)
            })
            print(f"✅ Updated {doc.id}: {original_amount} → {updated_amount}")
        else:
            print(f"⏩ Skipped {doc.id} (claimed on or after 2025-05-05)")
    except Exception as e:
        print(f"⚠️ Skipped {doc.id} due to error: {e}")
