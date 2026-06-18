import bcrypt
import random
import string
import time
from firebase_config import get_db_ref

def hash_pin(pin):
    """Hash a 4-digit PIN using bcrypt."""
    pin_bytes = pin.encode('utf-8')
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(pin_bytes, salt).decode('utf-8')

def verify_pin(pin, pin_hash):
    """Verify a PIN against its hash."""
    return bcrypt.checkpw(pin.encode('utf-8'), pin_hash.encode('utf-8'))

def generate_kr_tag():
    """Generate a unique kr-XXXXXXXXXX tag. Checks Firebase to ensure uniqueness."""
    kr_tags_ref = get_db_ref("kr_tags")
    
    for attempt in range(20):
        digits = ''.join(random.choices(string.digits, k=10))
        kr_tag = f"kr-{digits}"
        
        try:
            existing = kr_tags_ref.child(kr_tag).get()
            if existing is None:
                return kr_tag
        except Exception as e:
            # If Firebase call fails, log it and try again
            print(f"Firebase lookup attempt {attempt + 1} failed: {e}")
            time.sleep(0.2)
    
    raise Exception("Failed to generate unique kr_tag after maximum attempts.")

def error_response(message, status_code=400):
    return {"success": False, "error": message}, status_code

def success_response(data, status_code=200):
    return {"success": True, "data": data}, status_code

def validate_pin(pin):
    return bool(pin and len(pin) == 4 and pin.isdigit())

def validate_email(email):
    import re
    return bool(re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email))

def validate_phone(phone):
    import re
    return bool(re.match(r'^\+?\d{10,15}$', phone))