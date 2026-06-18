import os
import json
import firebase_admin
from firebase_admin import credentials, db

# Initialize Firebase
def init_firebase():
    try:
        # Check if already initialized
        firebase_admin.get_app()
    except ValueError:
        # Not initialized yet
        cred = None
        
        # For local development: use the JSON file
        if os.path.exists("firebase-credentials.json"):
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
            
            # Parse the JSON from environment variable
            cred_dict = json.loads(firebase_creds)
            cred = credentials.Certificate(cred_dict)
        
        # Initialize the app with Realtime Database URL
        database_url = os.environ.get(
            "FIREBASE_DATABASE_URL",
            cred_dict.get("databaseURL", None) if 'cred_dict' in locals() else None
        )
        
        if not database_url:
            raise Exception("FIREBASE_DATABASE_URL not set. Add it to Render environment variables.")
        
        firebase_admin.initialize_app(cred, {
            'databaseURL': database_url
        })
        print("Firebase initialized successfully.")

# Run on import
init_firebase()

# Helper to get DB reference
def get_db_ref(path=""):
    """Get a reference to the Firebase Realtime Database at the given path."""
    return db.reference(path)