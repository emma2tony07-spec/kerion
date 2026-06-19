import os
import firebase_admin
from firebase_admin import credentials, db

_app_initialized = False


def _build_credentials():
    """Build credentials dict from individual environment variables."""
    private_key = os.environ.get("FIREBASE_PRIVATE_KEY", "")
    
    # Render sometimes escapes newlines as \\n in env vars — fix that
    if "\\n" in private_key:
        private_key = private_key.replace("\\n", "\n")
    
    return {
        "type": os.environ.get("FIREBASE_TYPE", "service_account"),
        "project_id": os.environ.get("FIREBASE_PROJECT_ID", ""),
        "private_key_id": os.environ.get("FIREBASE_PRIVATE_KEY_ID", ""),
        "private_key": private_key,
        "client_email": os.environ.get("FIREBASE_CLIENT_EMAIL", ""),
        "client_id": os.environ.get("FIREBASE_CLIENT_ID", ""),
        "token_uri": os.environ.get("FIREBASE_TOKEN_URI", "https://oauth2.googleapis.com/token"),
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_x509_cert_url": f"https://www.googleapis.com/robot/v1/metadata/x509/{os.environ.get('FIREBASE_CLIENT_EMAIL', '').replace('@', '%40')}",
    }


def init_firebase():
    global _app_initialized
    if _app_initialized:
        return

    # Check required env vars
    required = [
        "FIREBASE_PROJECT_ID",
        "FIREBASE_PRIVATE_KEY",
        "FIREBASE_CLIENT_EMAIL",
    ]
    missing = [r for r in required if not os.environ.get(r)]
    if missing:
        raise Exception(f"Missing environment variables: {', '.join(missing)}")

    cred_dict = _build_credentials()
    cred = credentials.Certificate(cred_dict)

    database_url = os.environ.get("FIREBASE_DATABASE_URL")
    if not database_url:
        raise Exception("FIREBASE_DATABASE_URL not set.")

    firebase_admin.initialize_app(cred, {"databaseURL": database_url})
    _app_initialized = True
    print("Firebase initialized successfully from individual env vars.")


def get_db_ref(path=""):
    if not _app_initialized:
        init_firebase()
    return db.reference(path)


init_firebase()
