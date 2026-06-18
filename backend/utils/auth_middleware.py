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
            return error_response("Missing or invalid Authorization header. Use: Bearer <token>", 401)
        
        token = auth_header.split('Bearer ')[1]
        
        if not token:
            return error_response("Token is empty.", 401)
        
        try:
            # Verify the Firebase ID token
            decoded_token = auth.verify_id_token(token)
            g.user_id = decoded_token['uid']  # Store UID in Flask's g object
            g.user_email = decoded_token.get('email', '')
            
        except auth.ExpiredIdTokenError:
            return error_response("Token has expired. Please log in again.", 401)
        except auth.InvalidIdTokenError:
            return error_response("Invalid token. Please log in again.", 401)
        except auth.RevokedIdTokenError:
            return error_response("Token has been revoked.", 401)
        except Exception as e:
            return error_response(f"Authentication failed: {str(e)}", 401)
        
        return f(*args, **kwargs)
    
    return decorated_function