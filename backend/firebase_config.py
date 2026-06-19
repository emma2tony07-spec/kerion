import os
import json
import firebase_admin
from firebase_admin import credentials, db

_app_initialized = False


def init_firebase():
    global _app_initialized
    if _app_initialized:
        return

    cred_dict = None

    # 1. Render Secret File (most reliable)
    secret_path = "/etc/secrets/firebase-credentials.json"
    if os.path.exists(secret_path):
        with open(secret_path) as f:
            cred_dict = json.load(f)
            print("Loaded credentials from Render Secret File.")

    # 2. Local file
    if not cred_dict and os.path.exists("firebase-credentials.json"):
        with open("firebase-credentials.json") as f:
            cred_dict = json.load(f)
            print("Loaded credentials from local file.")

    # 3. Fallback: single env var
    if not cred_dict and os.environ.get("FIREBASE_CREDENTIALS"):
        cred_dict = json.loads(os.environ["FIREBASE_CREDENTIALS"])
        print("Loaded credentials from FIREBASE_CREDENTIALS env var.")

    # 4. Fallback: individual env vars
    if not cred_dict and os.environ.get("FIREBASE_PRIVATE_KEY"):
        private_key = os.environ["FIREBASE_PRIVATE_KEY"].replace("\\n", "\n")
        cred_dict = {
            "type": os.environ.get("FIREBASE_TYPE", "service_account"),
            "project_id": os.environ["FIREBASE_PROJECT_ID"],
            "private_key_id": os.environ.get("FIREBASE_PRIVATE_KEY_ID", ""),
            "private_key": private_key,
            "client_email": os.environ["FIREBASE_CLIENT_EMAIL"],
            "client_id": os.environ.get("FIREBASE_CLIENT_ID", ""),
            "token_uri": os.environ.get("FIREBASE_TOKEN_URI", "https://oauth2.googleapis.com/token"),
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_x509_cert_url": f"https://www.googleapis.com/robot/v1/metadata/x509/{os.environ['FIREBASE_CLIENT_EMAIL'].replace('@', '%40')}",
        }
        print("Built credentials from individual env vars.")

    if not cred_dict:
        raise Exception(
            "No Firebase credentials found. "
            "Add a Secret File at /etc/secrets/firebase-credentials.json, "
            "or place firebase-credentials.json in the project root."
        )

    cred = credentials.Certificate(cred_dict)

    database_url = os.environ.get("FIREBASE_DATABASE_URL") or cred_dict.get("databaseURL")
    if not database_url:
        raise Exception("FIREBASE_DATABASE_URL not set.")

    firebase_admin.initialize_app(cred, {"databaseURL": database_url})
    _app_initialized = True
    print("Firebase initialized successfully.")


def get_db_ref(path=""):
    if not _app_initialized:
        init_firebase()
    return db.reference(path)


init_firebase()
