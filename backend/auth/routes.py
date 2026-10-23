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

# Firebase Auth REST API endpoints
FIREBASE_AUTH_URL = "https://identitytoolkit.googleapis.com/v1/accounts"
FIREBASE_TOKEN_URL = "https://securetoken.googleapis.com/v1/token"
FIREBASE_API_KEY = os.environ.get("FIREBASE_API_KEY", "")


def _extract_firebase_error(auth_data):
    """Normalize a Firebase error payload into an uppercased searchable string."""
    error_obj = auth_data.get('error', {}) or {}
    error_msg = error_obj.get('message', '') or ''
    codes = [e.get('message', '') for e in error_obj.get('errors', []) or []]
    combined = ' '.join([error_msg, *codes]).upper()
    return error_msg, combined


def _text(data, key):
    """Read a string field; anything that isn't a string becomes ''."""
    value = data.get(key, '')
    return value.strip() if isinstance(value, str) else ''


def _profile(uid, user_data):
    """Client-safe profile returned by login and signup."""
    return {
        "uid": uid,
        "name": user_data.get('name'),
        "email": user_data.get('email'),
        "phone": user_data.get('phone'),
        "dob": user_data.get('dob'),
        "nationality": user_data.get('nationality'),
        "kr_tag": user_data.get('kr_tag'),
        "balance": user_data.get('balance', 0.00),
    }


@auth_bp.route('/api/auth/signup', methods=['POST'])
def signup():
    """Register a new user with Firebase Auth and store profile in Realtime DB."""
    uid = None
    id_token = None
    completed = False
    try:
        data = request.get_json(silent=True)

        if not isinstance(data, dict) or not data:
            return error_response("Request body is required.", 400)

        email = _text(data, 'email').lower()
        password = data.get('password', '')
        password = password if isinstance(password, str) else ''
        name = _text(data, 'name')
        phone = _text(data, 'phone')
        dob = _text(data, 'dob')
        nationality = _text(data, 'nationality')
        pin = data.get('pin', '')
        pin = pin if isinstance(pin, str) else ''

        if not all([email, password, name, phone, dob, nationality, pin]):
            return error_response(
                "All fields are required: email, password, name, phone, dob, nationality, pin.",
                400
            )

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

        # 1. Create the user in Firebase Auth
        auth_response = requests.post(
            f"{FIREBASE_AUTH_URL}:signUp",
            params={"key": FIREBASE_API_KEY},
            json={"email": email, "password": password, "returnSecureToken": True},
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
        refresh_token = auth_data.get('refreshToken')

        # 2. Unique kr_tag, 3. hashed PIN
        kr_tag = generate_kr_tag()
        pin_hash = hash_pin(pin)

        # 4. Profile in Realtime Database
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
        completed = True

        # 5. Token, refresh token and profile
        return success_response({
            "token": id_token,
            "refresh_token": refresh_token,
            "user": _profile(uid, user_data),
        }, 201)

    except requests.exceptions.RequestException:
        current_app.logger.exception("Network error during signup.")
        return error_response("Network error during registration. Please try again.", 500)
    except Exception:
        current_app.logger.exception("Unexpected error during signup.")
        return error_response("An unexpected error occurred. Please try again.", 500)
    finally:
        # If the auth user was created but the profile write didn't finish,
        # roll the auth user back so the email isn't orphaned.
        if uid and id_token and not completed and not _signup_completed(uid):
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
    """Log in with email and password. Returns an ID token and a refresh token."""
    try:
        data = request.get_json(silent=True)

        if not isinstance(data, dict) or not data:
            return error_response("Request body is required.", 400)

        email = _text(data, 'email').lower()
        password = data.get('password', '')
        password = password if isinstance(password, str) else ''

        if not email or not password:
            return error_response("Email and password are required.", 400)

        if not FIREBASE_API_KEY:
            current_app.logger.error("FIREBASE_API_KEY is not configured.")
            return error_response("Server configuration error. Please contact support.", 500)

        auth_response = requests.post(
            f"{FIREBASE_AUTH_URL}:signInWithPassword",
            params={"key": FIREBASE_API_KEY},
            json={"email": email, "password": password, "returnSecureToken": True},
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
        refresh_token = auth_data.get('refreshToken')

        user_data = get_db_ref(f"users/{uid}").get()

        if not user_data:
            current_app.logger.error(
                "Auth user %s has no profile in Realtime DB.", uid
            )
            return error_response(
                "User profile not found. Please contact support.", 500
            )

        return success_response({
            "token": id_token,
            "refresh_token": refresh_token,
            "user": _profile(uid, user_data),
        })

    except requests.exceptions.RequestException:
        current_app.logger.exception("Network error during login.")
        return error_response("Network error during login. Please try again.", 500)
    except Exception:
        current_app.logger.exception("Unexpected error during login.")
        return error_response("An unexpected error occurred. Please try again.", 500)


@auth_bp.route('/api/auth/refresh', methods=['POST'])
def refresh():
    """Exchange a Firebase refresh token for a fresh ID token."""
    try:
        data = request.get_json(silent=True)
        data = data if isinstance(data, dict) else {}
        refresh_token = data.get('refresh_token')
        if not isinstance(refresh_token, str) or not refresh_token.strip():
            return error_response("refresh_token is required.", 400)
        refresh_token = refresh_token.strip()

        if not FIREBASE_API_KEY:
            current_app.logger.error("FIREBASE_API_KEY is not configured.")
            return error_response("Server configuration error.", 500)

        resp = requests.post(
            FIREBASE_TOKEN_URL,
            params={"key": FIREBASE_API_KEY},
            data={"grant_type": "refresh_token", "refresh_token": refresh_token},
            timeout=15,
        )
        try:
            body = resp.json()
        except ValueError:
            body = {}

        if resp.status_code != 200:
            msg = str((body.get('error') or {}).get('message', ''))
            definitive = ('TOKEN_EXPIRED', 'USER_DISABLED', 'USER_NOT_FOUND',
                          'INVALID_REFRESH_TOKEN', 'MISSING_REFRESH_TOKEN',
                          'INVALID_GRANT_TYPE')
            if any(k in msg for k in definitive):
                return error_response("Session expired. Please log in again.",
                                      401, code="refresh_rejected")
            current_app.logger.warning("Refresh failed: HTTP %s %s", resp.status_code, msg)
            return error_response("Could not refresh the session.", 502)

        if 'id_token' not in body:
            current_app.logger.error("Refresh response had no id_token.")
            return error_response("Could not refresh the session.", 502)

        return success_response({
            "token": body['id_token'],
            "refresh_token": body.get('refresh_token', refresh_token),
        })
    except requests.exceptions.RequestException:
        current_app.logger.exception("Network error during token refresh.")
        return error_response("Could not refresh the session.", 503)
    except Exception:
        current_app.logger.exception("Unexpected error during token refresh.")
        return error_response("Could not refresh the session.", 500)
