import re
import secrets
import string
import time
import hashlib
from math import ceil

import bcrypt
from firebase_config import get_db_ref

PIN_MAX_ATTEMPTS = 5
PIN_LOCK_SECONDS = 15 * 60

# ─── Lookup indexes and rate limiting ─────────────────────────────

LOOKUP_MAX_PER_MINUTE = 30


def _index_key(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def normalize_email(email):
    return email.strip().lower() if isinstance(email, str) else ''


def normalize_phone(phone):
    return re.sub(r'\D', '', phone) if isinstance(phone, str) else ''


def email_index_key(email):
    return _index_key(normalize_email(email))


def phone_index_key(phone):
    return _index_key(normalize_phone(phone))


def write_lookup_indexes(uid, email, phone):
    """Point the email and phone indexes at this user."""
    db = get_db_ref()
    if normalize_email(email):
        db.child("emails").child(email_index_key(email)).set(uid)
    if normalize_phone(phone):
        db.child("phones").child(phone_index_key(phone)).set(uid)


def lookup_allowed(uid):
    """Fixed-window limiter. Fails closed if the counter can't be read."""
    ref = get_db_ref(f"lookup_limits/{uid}")
    outcome = {}

    def tx(current):
        outcome.clear()
        cur = current if isinstance(current, dict) else {}
        now = time.time()
        start = float(cur.get("window_start") or 0)
        count = int(cur.get("count") or 0)
        if now - start >= 60:
            start, count = now, 0
        if count >= LOOKUP_MAX_PER_MINUTE:
            outcome["ok"] = False
            return {"window_start": start, "count": count}
        outcome["ok"] = True
        return {"window_start": start, "count": count + 1}

    try:
        ref.transaction(tx)
    except Exception as e:
        print(f"Lookup limiter failed: {e}")
        return False
    return outcome.get("ok", False)

def hash_pin(pin):
    """Hash a 4-digit PIN using bcrypt."""
    pin_bytes = pin.encode('utf-8')
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(pin_bytes, salt).decode('utf-8')


def verify_pin(pin, pin_hash):
    """Verify a PIN against its hash. A missing or malformed hash is a mismatch."""
    try:
        return bcrypt.checkpw(pin.encode('utf-8'), (pin_hash or '').encode('utf-8'))
    except ValueError:
        return False


def generate_kr_tag():
    """Generate a unique kr-XXXXXXXXXX tag. Checks Firebase to ensure uniqueness."""
    kr_tags_ref = get_db_ref("kr_tags")

    for attempt in range(20):
        digits = ''.join(secrets.choice(string.digits) for _ in range(10))
        kr_tag = f"kr-{digits}"

        try:
            existing = kr_tags_ref.child(kr_tag).get()
            if existing is None:
                return kr_tag
        except Exception as e:
            print(f"Firebase lookup attempt {attempt + 1} failed: {e}")
            time.sleep(0.2)

    raise Exception("Failed to generate unique kr_tag after maximum attempts.")


def error_response(message, status_code=400, code=None):
    body = {"success": False, "error": message}
    if code:
        body["code"] = code
    return body, status_code


def success_response(data, status_code=200):
    return {"success": True, "data": data}, status_code


def validate_pin(pin):
    return bool(isinstance(pin, str) and len(pin) == 4 and pin.isdigit())


def validate_email(email):
    return bool(re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email))


def validate_phone(phone):
    return bool(re.match(r'^\+?\d{10,15}$', phone))


# ─── PIN attempt limiting ─────────────────────────────────────────

def _reserve_pin_attempt(ref):
    """Atomically claim one attempt. Returns a dict describing the outcome.

    The attempt is counted BEFORE the PIN is checked, so parallel guesses
    cannot slip past the limit. The Firebase callback can be re-run on
    conflicts, so it resets its outcome every time.
    """
    outcome = {}

    def tx(current):
        outcome.clear()
        cur = current if isinstance(current, dict) else {}
        now = time.time()
        locked_until = float(cur.get("locked_until") or 0)
        if locked_until > now:
            outcome.update(allowed=False, retry=int(locked_until - now) + 1)
            return cur
        count = int(cur.get("count") or 0) + 1
        if count >= PIN_MAX_ATTEMPTS:
            # This is the last allowed guess: if it fails, the lock stands.
            outcome.update(allowed=True, locked=True, left=0)
            return {"count": 0, "locked_until": now + PIN_LOCK_SECONDS}
        outcome.update(allowed=True, locked=False, left=PIN_MAX_ATTEMPTS - count)
        return {"count": count, "locked_until": 0}

    ref.transaction(tx)
    return outcome


def check_pin(uid, pin, pin_hash):
    """Return None if the PIN is correct, otherwise an error_response tuple."""
    ref = get_db_ref(f"pin_attempts/{uid}")
    try:
        outcome = _reserve_pin_attempt(ref)
    except Exception as e:
        # Fail closed: without the lock record we cannot rate-limit guesses.
        print(f"PIN attempt tracking failed: {e}")
        return error_response("Could not verify your PIN right now. Please try again.",
                              503, code="pin_unavailable")

    if not outcome.get("allowed"):
        minutes = max(1, ceil(outcome["retry"] / 60))
        return error_response(
            f"Too many incorrect PIN attempts. Try again in {minutes} minute(s).",
            429, code="pin_locked")

    if verify_pin(pin, pin_hash):
        try:
            ref.delete()  # a correct PIN resets the counter and any lock
        except Exception as e:
            print(f"PIN counter reset failed: {e}")
        return None

    if outcome.get("locked"):
        return error_response(
            f"Too many incorrect PIN attempts. PIN locked for {PIN_LOCK_SECONDS // 60} minutes.",
            429, code="pin_locked")
    return error_response(
        f"Incorrect PIN. {outcome['left']} attempt(s) left.", 401, code="pin_incorrect")
