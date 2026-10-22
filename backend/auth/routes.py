from flask import Blueprint, request, current_app
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


def _extract_firebase_error(auth_data):
    """Normalize a Firebase error payload into an uppercased searchable string."""
    error_obj = auth_data.get('error', {}) or {}
    error_msg = error_obj.get('message', '') or ''
    codes = [e.get('message', '') for e in error_obj.get('errors', []) or []]
    combined = ' '.join([error_msg, *codes]).upper()
    return error_msg, combined


@auth_bp.route('/api/auth/signup', methods=['POST'])
def signup():
    """Register a new user with Firebase Auth and store profile in Realtime DB."""
    uid = None
    id_token = None
    try:
        data = request.get_json()

        if not data:
            return error_response("Request body is required.", 400)

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
            return error_response(
                "All fields are required: email, password, name, phone, dob, nationality, pin.",
                400
            )

        # Validate formats
        if not validate_email(email):
            return error_response("Invalid email format.", 400)

        if len(password) < 6:
            return error_response("Password must be at least 6 characters.", 400)

        if not validate_phone(phone):
            return error_response("Invalid phone number. Use format: +2348012345678", 400)

        if not validate_pin(pin):
            return error_response("PIN must be exactly 4 digits.", 400)

        if not FIREBASE_API_KEY:
            current_app.logger.error("FIREBASE_API_KEY is not configured.")
            return error_response("Server configuration error. Please contact support.", 500)

        # 1. Create user in Firebase Auth using REST API
        auth_response = requests.post(
            f"{FIREBASE_AUTH_URL}:signUp",
            params={"key": FIREBASE_API_KEY},
            json={
                "email": email,
                "password": password,
                "returnSecureToken": True
            },
            timeout=10
        )

        auth_data = auth_response.json()

        if auth_response.status_code != 200:
            error_msg, combined = _extract_firebase_error(auth_data)

            if 'EMAIL_EXISTS' in combined:
                return error_response("This email is already registered.", 409)
            if 'WEAK_PASSWORD' in combined:
                return error_response("Password is too weak. Use at least 6 characters.", 400)
            if 'INVALID_EMAIL' in combined:
                return error_response("Invalid email format.", 400)
            if 'OPERATION_NOT_ALLOWED' in combined:
                return error_response("Email/password signup is disabled. Please contact support.", 403)

            current_app.logger.warning("Unhandled Firebase signup error: %s", error_msg)
            return error_response("Registration failed. Please try again.", 400)

        uid = auth_data['localId']
        id_token = auth_data['idToken']

        # 2. Generate unique kr_tag
        kr_tag = generate_kr_tag()

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
        db_ref.child("users").child(uid).set(user_data)
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

    except requests.exceptions.RequestException:
        current_app.logger.exception("Network error during signup.")
        return error_response("Network error during registration. Please try again.", 500)
    except Exception:
        current_app.logger.exception("Unexpected error during signup.")
        return error_response("An unexpected error occurred. Please try again.", 500)
    finally:
        # Cleanup: if we created the auth user but failed before completing the profile
        # write, roll back the auth user so the email isn't orphaned.
        if uid and id_token and not _signup_completed(uid):
            try:
                requests.post(
                    f"{FIREBASE_AUTH_URL}:delete",
                    params={"key": FIREBASE_API_KEY},
                    json={"idToken": id_token},
                    timeout=10
                )
                current_app.logger.warning(
                    "Rolled back orphaned Firebase auth user uid=%s", uid
                )
            except Exception:
                current_app.logger.exception(
                    "Failed to roll back Firebase auth user uid=%s", uid
                )


def _signup_completed(uid):
    """Check whether the user profile was successfully written to Realtime DB."""
    try:
        return bool(get_db_ref(f"users/{uid}").get())
    except Exception:
        return False


@auth_bp.route('/api/auth/login', methods=['POST'])
def login():
    """Log in user with email and password. Returns Firebase ID token."""
    try:
        data = request.get_json()

        if not data:
            return error_response("Request body is required.", 400)

        email = data.get('email', '').strip().lower()
        password = data.get('password', '')

        if not email or not password:
            return error_response("Email and password are required.", 400)

        if not FIREBASE_API_KEY:
            current_app.logger.error("FIREBASE_API_KEY is not configured.")
            return error_response("Server configuration error. Please contact support.", 500)

        # Authenticate with Firebase Auth REST API
        auth_response = requests.post(
            f"{FIREBASE_AUTH_URL}:signInWithPassword",
            params={"key": FIREBASE_API_KEY},
            json={
                "email": email,
                "password": password,
                "returnSecureToken": True
            },
            timeout=10
        )

        auth_data = auth_response.json()

        if auth_response.status_code != 200:
            error_msg, combined = _extract_firebase_error(auth_data)

            if any(c in combined for c in (
                'EMAIL_NOT_FOUND', 'INVALID_PASSWORD', 'INVALID_LOGIN_CREDENTIALS'
            )):
                return error_response("Invalid email or password.", 401)

            if 'USER_DISABLED' in combined:
                return error_response("This account has been disabled.", 403)

            if 'TOO_MANY_ATTEMPTS_TRY_LATER' in combined:
                return error_response("Too many attempts. Try again later.", 429)

            current_app.logger.warning("Unhandled Firebase login error: %s", error_msg)
            return error_response("Login failed. Please try again.", 401)

        uid = auth_data['localId']
        id_token = auth_data['idToken']

        # Fetch user profile from Realtime DB
        user_ref = get_db_ref(f"users/{uid}")
        user_data = user_ref.get()

        if not user_data:
            current_app.logger.error(
                "Auth user %s has no profile in Realtime DB.", uid
            )
            return error_response(
                "User profile not found. Please contact support.", 500
            )

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

    except requests.exceptions.RequestException:
        current_app.logger.exception("Network error during login.")
        return error_response("Network error during login. Please try again.", 500)
    except Exception:
        current_app.logger.exception("Unexpected error during login.")
        return error_response("An unexpected error occurred. Please try again.", 500)
