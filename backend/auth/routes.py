from flask import Blueprint, request, current_app
import requests
import os
from firebase_config import get_db_ref
from utils.helpers import (
    hash_pin, generate_kr_tag, error_response,
    success_response, validate_pin, validate_email, validate_phone,
    write_lookup_indexes, rate_limit
)
from datetime import datetime, timezone
from flask import Blueprint, request, current_app, Response

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

def _client_ip():
    return (request.headers.get('X-Forwarded-For', '').split(',')[0].strip()
            or request.remote_addr or 'unknown')

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
        try:
            write_lookup_indexes(uid, email, phone)
        except Exception:
            current_app.logger.exception("Lookup index write failed for uid=%s", uid)
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

@auth_bp.route('/api/auth/forgot-password', methods=['POST'])
def forgot_password():
    """Email a password-reset link. The answer never reveals whether the
    account exists."""
    try:
        data = request.get_json(silent=True)
        data = data if isinstance(data, dict) else {}
        email = _text(data, 'email').lower()
        if len(email) > 254 or not validate_email(email):
            return error_response("Enter a valid email address.", 400)

        if not FIREBASE_API_KEY:
            current_app.logger.error("FIREBASE_API_KEY is not configured.")
            return error_response("Server configuration error. Please contact support.", 500)

        # Behind Render's proxy the client IP is in X-Forwarded-For. The
        # per-email limit is the dependable one; the IP limit is best-effort.
        ip = (request.headers.get('X-Forwarded-For', '').split(',')[0].strip()
              or request.remote_addr or 'unknown')
        if not rate_limit('reset_ip', ip, 10, 3600) or \
                not rate_limit('reset_email', email, 3, 3600):
            return error_response(
                "Too many reset requests. Please try again later.", 429,
                code="reset_rate_limited")

        try:
            resp = requests.post(
                f"{FIREBASE_AUTH_URL}:sendOobCode",
                params={"key": FIREBASE_API_KEY},
                json={"requestType": "PASSWORD_RESET", "email": email},
                timeout=10,
            )
            if resp.status_code != 200:
                # Includes EMAIL_NOT_FOUND. Log it, but don't tell the client.
                current_app.logger.info(
                    "Password reset not sent: HTTP %s", resp.status_code)
        except requests.exceptions.RequestException:
            current_app.logger.exception("Network error sending reset email.")

        return success_response({
            "message": "If an account exists for that email, a reset link has been sent."
        })
    except Exception:
        current_app.logger.exception("Unexpected error in forgot-password.")
        return error_response("Something went wrong. Please try again.", 500)

RESET_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Reset your Kerion password</title>
<style>
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
       background:#0A0F14;color:#EDF2F7;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;padding:20px}
  .card{width:100%;max-width:400px;background:#111820;border:1px solid #1d2630;border-radius:20px;padding:28px}
  .logo{width:48px;height:48px;border-radius:14px;background:#00C49F;color:#0A0F14;font-weight:800;
        font-size:24px;display:flex;align-items:center;justify-content:center;margin:0 auto 14px}
  h1{font-size:20px;margin:0 0 6px;text-align:center}
  p.sub{color:#8B9BB5;font-size:13px;line-height:1.5;text-align:center;margin:0 0 20px}
  label{display:block;font-size:12px;color:#8B9BB5;margin:14px 0 6px}
  input{width:100%;padding:13px 14px;border-radius:10px;border:1px solid #243040;background:#0A0F14;
        color:#EDF2F7;font-size:15px;outline:none}
  input:focus{border-color:#00C49F}
  button{width:100%;margin-top:20px;padding:14px;border:0;border-radius:10px;background:#00C49F;
         color:#0A0F14;font-weight:700;font-size:15px;cursor:pointer}
  button:disabled{opacity:.5;cursor:default}
  .msg{margin-top:14px;font-size:13px;line-height:1.5;text-align:center;min-height:18px}
  .err{color:#FF4D6A}.ok{color:#00C49F}
  .hide{display:none}
</style>
</head>
<body>
<div class="card">
  <div class="logo">K</div>
  <h1 id="title">Choose a new password</h1>
  <p class="sub" id="sub">Enter a new password for your Kerion account.</p>
  <form id="form" autocomplete="off">
    <label for="pw">New password</label>
    <input id="pw" type="password" minlength="6" maxlength="128" required autocomplete="new-password">
    <label for="pw2">Confirm password</label>
    <input id="pw2" type="password" minlength="6" maxlength="128" required autocomplete="new-password">
    <button id="btn" type="submit">Update password</button>
  </form>
  <div class="msg" id="msg"></div>
</div>
<script>
(function () {
  var params = new URLSearchParams(location.search);
  var code = params.get('oobCode');
  var mode = params.get('mode');
  var form = document.getElementById('form');
  var msg = document.getElementById('msg');
  var btn = document.getElementById('btn');

  // Keep the one-time code out of the address bar and history.
  history.replaceState(null, '', location.pathname);

  function show(text, ok) { msg.textContent = text; msg.className = 'msg ' + (ok ? 'ok' : 'err'); }

  if (!code || (mode && mode !== 'resetPassword')) {
    form.className = 'hide';
    document.getElementById('title').textContent = 'Link not valid';
    document.getElementById('sub').textContent =
      'This reset link is incomplete. Request a new one from the Kerion app.';
    return;
  }

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    var pw = document.getElementById('pw').value;
    var pw2 = document.getElementById('pw2').value;
    if (pw.length < 6) { show('Password must be at least 6 characters.', false); return; }
    if (pw !== pw2) { show('The passwords do not match.', false); return; }
    btn.disabled = true; show('Updating...', true);
    fetch('/api/auth/reset-password', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({oob_code: code, new_password: pw})
    }).then(function (r) { return r.json().catch(function () { return {}; }); })
      .then(function (d) {
        if (d.success) {
          form.className = 'hide';
          document.getElementById('title').textContent = 'Password updated';
          document.getElementById('sub').textContent =
            'Return to the Kerion app and log in with your new password.';
          msg.textContent = '';
        } else {
          btn.disabled = false;
          show(d.error || 'Something went wrong. Please try again.', false);
        }
      })
      .catch(function () {
        btn.disabled = false;
        show('Could not reach the server. Check your connection and try again.', false);
      });
  });
})();
</script>
</body>
</html>"""


@auth_bp.route('/reset-password', methods=['GET'])
def reset_password_page():
    """Page the password-reset email links to."""
    resp = Response(RESET_PAGE, mimetype='text/html')
    resp.headers['Cache-Control'] = 'no-store'
    resp.headers['Referrer-Policy'] = 'no-referrer'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['Content-Security-Policy'] = (
        "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
        "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
    return resp


@auth_bp.route('/api/auth/reset-password', methods=['POST'])
def reset_password():
    """Complete a password reset using the one-time code from the email."""
    try:
        data = request.get_json(silent=True)
        data = data if isinstance(data, dict) else {}
        oob_code = data.get('oob_code')
        new_password = data.get('new_password')

        if not isinstance(oob_code, str) or not oob_code.strip() or len(oob_code) > 512:
            return error_response("This reset link is invalid.", 400, code="reset_invalid")
        if not isinstance(new_password, str) or not 6 <= len(new_password) <= 128:
            return error_response("Password must be between 6 and 128 characters.", 400)

        if not FIREBASE_API_KEY:
            current_app.logger.error("FIREBASE_API_KEY is not configured.")
            return error_response("Server configuration error. Please contact support.", 500)

        if not rate_limit('reset_confirm_ip', _client_ip(), 20, 3600):
            return error_response("Too many attempts. Please try again later.", 429,
                                  code="reset_rate_limited")

        resp = requests.post(
            f"{FIREBASE_AUTH_URL}:resetPassword",
            params={"key": FIREBASE_API_KEY},
            json={"oobCode": oob_code.strip(), "newPassword": new_password},
            timeout=10,
        )
        if resp.status_code == 200:
            return success_response({"message": "Password updated."})

        try:
            error_msg, combined = _extract_firebase_error(resp.json())
        except ValueError:
            error_msg, combined = '', ''

        if 'EXPIRED_OOB_CODE' in combined:
            return error_response("This link has expired. Request a new reset email.",
                                  400, code="reset_expired")
        if 'INVALID_OOB_CODE' in combined:
            return error_response("This link is invalid or has already been used.",
                                  400, code="reset_invalid")
        if 'WEAK_PASSWORD' in combined:
            return error_response("Password is too weak. Use at least 6 characters.", 400)

        current_app.logger.warning("Unhandled password reset error: %s", error_msg)
        return error_response("Could not reset the password. Please request a new link.", 400)

    except requests.exceptions.RequestException:
        current_app.logger.exception("Network error during password reset.")
        return error_response("Could not reach the authentication service. Try again.", 503)
    except Exception:
        current_app.logger.exception("Unexpected error during password reset.")
        return error_response("Something went wrong. Please try again.", 500)
