import bcrypt
import random
import string
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
    attempts = 0
    max_attempts = 10  # Safety limit to prevent infinite loops
    
    while attempts < max_attempts:
        # Generate 10 random digits
        digits = ''.join(random.choices(string.digits, k=10))
        kr_tag = f"kr-{digits}"
        
        # Check if it already exists
        kr_tags_ref = get_db_ref("kr_tags")
        existing = kr_tags_ref.child(kr_tag).get()
        
        if existing is None:
            return kr_tag
        
        attempts += 1
    
    raise Exception("Failed to generate unique kr_tag after maximum attempts.")

def error_response(message, status_code=400):
    """Standardized error response for the API."""
    return {
        "success": False,
        "error": message
    }, status_code

def success_response(data, status_code=200):
    """Standardized success response for the API."""
    return {
        "success": True,
        "data": data
    }, status_code

def validate_pin(pin):
    """Validate PIN format: must be exactly 4 digits."""
    if not pin or len(pin) != 4 or not pin.isdigit():
        return False
    return True

def validate_email(email):
    """Basic email validation."""
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_phone(phone):
    """Basic phone validation - allows + and digits only, min 10 chars."""
    import re
    pattern = r'^\+?\d{10,15}$'
    return re.match(pattern, phone) is not None