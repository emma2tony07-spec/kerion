from flask import Blueprint, request
import requests
import os
from firebase_config import get_db_ref
from utils.helpers import (
    hash_pin, generate_kr_tag, error_response, 
    success_response, validate_pin, validate_email, validate_phone
)
from datetime import datetime, timezone

auth_bp = Blueprint('auth', __name__)

# Firebase Auth REST API endpoint
FIREBASE_AUTH_URL = "https://identitytoolkit.googleapis.com/v1/accounts"
FIREBASE_API_KEY = os.environ.get("FIREBASE_API_KEY", "")

@auth_bp.route('/api/auth/signup', methods=['POST'])
def signup():
    """Register a new user with Firebase Auth and store profile in Realtime DB."""
    try:
        data = request.get_json()
        
        if not data:
            return error_response("Request body is required.")
        
        # Extract fields
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        name = data.get('name', '').strip()
        phone = data.get('phone', '').strip()
        dob = data.get('dob', '').strip()
        nationality = data.get('nationality', '').strip()
        pin = data.get('pin', '')
        
        # Validate required fields
        if not all([email, password, name, phone, dob, nationality, pin]):
            return error_response("All fields are required: email, password, name, phone, dob, nationality, pin.")
        
        # Validate formats
        if not validate_email(email):
            return error_response("Invalid email format.")
        
        if len(password) < 6:
            return error_response("Password must be at least 6 characters.")
        
        if not validate_phone(phone):
            return error_response("Invalid phone number. Use format: +2348012345678")
        
        if not validate_pin(pin):
            return error_response("PIN must be exactly 4 digits.")
        
        if not FIREBASE_API_KEY:
            return error_response("Server configuration error: FIREBASE_API_KEY not set.", 500)
        
        # 1. Create user in Firebase Auth using REST API
        auth_response = requests.post(
            f"{FIREBASE_AUTH_URL}:signUp",
            params={"key": FIREBASE_API_KEY},
            json={
                "email": email,
                "password": password,
                "returnSecureToken": True
            }
        )
        
        auth_data = auth_response.json()
        
        if auth_response.status_code != 200:
            error_msg = auth_data.get('error', {}).get('message', 'Registration failed.')
            # Make Firebase errors more user-friendly
            if 'EMAIL_EXISTS' in error_msg:
                return error_response("This email is already registered.")
            if 'WEAK_PASSWORD' in error_msg:
                return error_response("Password is too weak. Use at least 6 characters.")
            return error_response(f"Registration failed: {error_msg}")
        
        uid = auth_data['localId']
        id_token = auth_data['idToken']
        
        # 2. Generate unique kr_tag
        try:
            kr_tag = generate_kr_tag()
        except Exception as e:
            # Cleanup: delete the Firebase Auth user if kr_tag generation fails
            requests.post(
                f"{FIREBASE_AUTH_URL}:delete",
                params={"key": FIREBASE_API_KEY},
                json={"idToken": id_token}
            )
            return error_response("Failed to generate account tag. Please try again.", 500)
        
        # 3. Hash the PIN
        pin_hash = hash_pin(pin)
        
        # 4. Create user profile in Realtime Database
        user_data = {
            "email": email,
            "name": name,
            "phone": phone,
            "dob": dob,
            "nationality": nationality,
            "kr_tag": kr_tag,
            "pin_hash": pin_hash,
            "balance": 0.00,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        
        db_ref = get_db_ref()
        
        # Store user profile
        db_ref.child("users").child(uid).set(user_data)
        
        # Store kr_tag → uid mapping for fast lookups
        db_ref.child("kr_tags").child(kr_tag).set(uid)
        
        # 5. Return success with token and user info
        return success_response({
            "token": id_token,
            "user": {
                "uid": uid,
                "name": name,
                "email": email,
                "kr_tag": kr_tag,
                "balance": 0.00
            }
        }, 201)
        
    except requests.exceptions.RequestException as e:
        return error_response(f"Network error during registration. Please try again.", 500)
    except Exception as e:
        return error_response(f"An unexpected error occurred: {str(e)}", 500)


@auth_bp.route('/api/auth/login', methods=['POST'])
def login():
    """Log in user with email and password. Returns Firebase ID token."""
    try:
        data = request.get_json()
        
        if not data:
            return error_response("Request body is required.")
        
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not email or not password:
            return error_response("Email and password are required.")
        
        if not FIREBASE_API_KEY:
            return error_response("Server configuration error: FIREBASE_API_KEY not set.", 500)
        
        # Authenticate with Firebase Auth REST API
        auth_response = requests.post(
            f"{FIREBASE_AUTH_URL}:signInWithPassword",
            params={"key": FIREBASE_API_KEY},
            json={
                "email": email,
                "password": password,
                "returnSecureToken": True
            }
        )
        
        auth_data = auth_response.json()
        
        if auth_response.status_code != 200:
            error_msg = auth_data.get('error', {}).get('message', 'Login failed.')
            if 'EMAIL_NOT_FOUND' in error_msg or 'INVALID_PASSWORD' in error_msg:
                return error_response("Invalid email or password.")
            if 'USER_DISABLED' in error_msg:
                return error_response("This account has been disabled.")
            return error_response(f"Login failed: {error_msg}")
        
        uid = auth_data['localId']
        id_token = auth_data['idToken']
        
        # Fetch user profile from Realtime DB
        user_ref = get_db_ref(f"users/{uid}")
        user_data = user_ref.get()
        
        if not user_data:
            return error_response("User profile not found. Please contact support.", 500)
        
        return success_response({
            "token": id_token,
            "user": {
                "uid": uid,
                "name": user_data.get('name'),
                "email": user_data.get('email'),
                "kr_tag": user_data.get('kr_tag'),
                "balance": user_data.get('balance', 0.00)
            }
        })
        
    except requests.exceptions.RequestException as e:
        return error_response(f"Network error during login. Please try again.", 500)
    except Exception as e:
        return error_response(f"An unexpected error occurred: {str(e)}", 500)