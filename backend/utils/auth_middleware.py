from functools import wraps
from flask import request, g
from firebase_admin import auth
from utils.helpers import error_response


def require_auth(f):
    """Decorator to require Firebase authentication on Flask routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')

        if not auth_header.startswith('Bearer '):
            return error_response(
                "Missing or invalid Authorization header. Use: Bearer <token>",
                401, code="token_missing")

        token = auth_header.split('Bearer ', 1)[1].strip()
        if not token:
            return error_response("Token is empty.", 401, code="token_missing")

        try:
            decoded_token = auth.verify_id_token(token)
            g.user_id = decoded_token['uid']
            g.user_email = decoded_token.get('email', '')

        # ExpiredIdTokenError and RevokedIdTokenError are subclasses of
        # InvalidIdTokenError, so they must be caught first.
        except auth.ExpiredIdTokenError:
            return error_response("Token has expired.", 401, code="token_expired")
        except auth.RevokedIdTokenError:
            return error_response("Token has been revoked.", 401, code="token_revoked")
        except (auth.InvalidIdTokenError, ValueError):
            return error_response("Invalid token.", 401, code="token_invalid")
        except Exception as e:
            # Not the client's fault (e.g. certificate fetch failed), so
            # the client must NOT treat this as an expired session.
            print(f"Token verification unavailable: {e}")
            return error_response(
                "Authentication is temporarily unavailable. Please try again.",
                503, code="auth_unavailable")

        return f(*args, **kwargs)

    return decorated_function
