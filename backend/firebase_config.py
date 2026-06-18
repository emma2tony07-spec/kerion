import os
import json
import firebase_admin
from firebase_admin import credentials, db

_app_initialized = False

def init_firebase():
    global _app_initialized
    if _app_initialized:
        return

    cred = None
    cred_dict = None

    # For local development: use the JSON file
    if os.path.exists("firebase-credentials.json"):
        with open("firebase-credentials.json") as f:
            cred_dict = json.load(f)
        cred = credentials.Certificate("firebase-credentials.json")
    else:
        # For Render: use environment variable
        firebase_creds = os.environ.get("FIREBASE_CREDENTIALS")
        if not firebase_creds:
            raise Exception(
                "FIREBASE_CREDENTIALS environment variable not set. "
                "On Render, add it in Environment Variables. "
                "Locally, place firebase-credentials.json in the project root."
            )
        cred_dict = json.loads(firebase_creds)
        cred = credentials.Certificate(cred_dict)

    # Get database URL
    database_url = os.environ.get("FIREBASE_DATABASE_URL")
    if not database_url and cred_dict:
        database_url = cred_dict.get("databaseURL", cred_dict.get("database_url"))

    if not database_url:
        raise Exception("FIREBASE_DATABASE_URL not set. Add it to Render environment variables.")

    firebase_admin.initialize_app(cred, {
        'databaseURL': database_url
    })
    _app_initialized = True
    print("Firebase initialized successfully.")

def get_db_ref(path=""):
    """Get a reference to the Firebase Realtime Database at the given path."""
    if not _app_initialized:
        init_firebase()
    return db.reference(path)

# Initialize on import
init_firebase()