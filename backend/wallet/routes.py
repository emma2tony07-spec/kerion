import math
import re
from flask import Blueprint, request, g
from datetime import datetime, timezone
import hashlib
import uuid

try:
    from firebase_admin import messaging
except ImportError:  # pragma: no cover - optional dependency in some environments
    messaging = None

from firebase_config import get_db_ref
from utils.helpers import (
    check_pin, error_response, success_response, validate_pin,
    lookup_allowed, email_index_key, phone_index_key,
    normalize_email, normalize_phone, write_lookup_indexes,
)
from utils.auth_middleware import require_auth

wallet_bp = Blueprint('wallet', __name__)

_TAG_RE = re.compile(r'^kr-\d{10}$')


def send_push_notification(user_id, title, body, data=None):
    """Best-effort push delivery; a notification failure must not undo a transfer."""
    devices = get_db_ref(f"devices/{user_id}").get() or {}
    tokens = [device.get('fcm_token') for device in devices.values()
              if isinstance(device, dict) and device.get('fcm_token')]
    if not tokens:
        return

    message = messaging.MulticastMessage(
        notification=messaging.Notification(title=title, body=body),
        data={key: str(value) for key, value in (data or {}).items()},
        tokens=tokens,
    )
    messaging.send_each_for_multicast(message)


@wallet_bp.route('/api/wallet/balance', methods=['GET'])
@require_auth
def get_balance():
    """Get current user's balance."""
    try:
        user_ref = get_db_ref(f"users/{g.user_id}")
        user_data = user_ref.get()

        if not user_data:
            return error_response("User not found.", 404)

        # Return the complete client-safe profile.  Returning only a partial
        # object caused the mobile client to overwrite cached profile fields.
        return success_response({
            "name": user_data.get('name'),
            "email": user_data.get('email'),
            "phone": user_data.get('phone'),
            "dob": user_data.get('dob'),
            "nationality": user_data.get('nationality'),
            "balance": user_data.get('balance', 0.00),
            "kr_tag": user_data.get('kr_tag'),
        })

    except Exception as e:
        return error_response(f"Failed to fetch balance: {str(e)}", 500)


def _public_profile(user_data):
    return {"kr_tag": user_data.get('kr_tag'), "name": user_data.get('name')}


@wallet_bp.route('/api/user/lookup', methods=['POST'])
@require_auth
def lookup_user():
    """Look up a user by kr_tag, email, or phone."""
    try:
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return error_response("Request body is required.")

        query = data.get('query')
        query = query.strip() if isinstance(query, str) else ''
        if not query or len(query) > 100:
            return error_response("Provide a kr_tag, email, or phone number to look up.")

        if not lookup_allowed(g.user_id):
            return error_response("Too many lookups. Please wait a minute.", 429,
                                  code="lookup_rate_limited")

        db_ref = get_db_ref()
        uid = None
        kind = None

        # 1. Direct reads from the right index, based on what was typed.
        if _TAG_RE.match(query):
            kind = "tag"
            uid = db_ref.child("kr_tags").child(query).get()
        elif '@' in query:
            kind = "email"
            if normalize_email(query):
                uid = db_ref.child("emails").child(email_index_key(query)).get()
        else:
            digits = normalize_phone(query)
            if 10 <= len(digits) <= 15:
                kind = "phone"
                uid = db_ref.child("phones").child(phone_index_key(query)).get()

        if kind is None:
            return error_response("Enter a Kerion tag (kr-...), an email, or a phone number.")

        # 2. Fallback for users created before the indexes existed. It scans
        #    once and repairs the index, so each old user costs one scan.
        if not uid and kind in ("email", "phone"):
            users = db_ref.child("users").get() or {}
            for u, profile in users.items():
                if not isinstance(profile, dict):
                    continue
                if kind == "email" and normalize_email(profile.get('email')) == normalize_email(query):
                    uid = u
                elif kind == "phone" and normalize_phone(profile.get('phone')) == normalize_phone(query):
                    uid = u
                if uid:
                    try:
                        write_lookup_indexes(u, profile.get('email'), profile.get('phone'))
                    except Exception as e:
                        print(f"Index repair failed for {u}: {e}")
                    break

        if not uid or uid == g.user_id:
            return error_response(
                "User not found. Check the kr_tag, email, or phone and try again.", 404)

        user_data = db_ref.child("users").child(uid).get()
        if not isinstance(user_data, dict):
            return error_response(
                "User not found. Check the kr_tag, email, or phone and try again.", 404)

        return success_response(_public_profile(user_data))

    except Exception as e:
        print(f"Lookup failed: {e}")
        return error_response("Lookup failed. Please try again.", 500)


@wallet_bp.route('/api/wallet/send', methods=['POST'])
@require_auth
def send_money():
    """Send money to another user using their kr_tag and PIN confirmation."""
    try:
        data = request.get_json()

        if not data:
            return error_response("Request body is required.")

        recipient_tag = data.get('kr_tag', '').strip()
        amount = data.get('amount')
        pin = data.get('pin', '')
        description = data.get('description', '').strip()

        # Validate inputs
        if not recipient_tag or not amount or not pin:
            return error_response("kr_tag, amount, and pin are required.")

        if not validate_pin(pin):
            return error_response("PIN must be exactly 4 digits.")

        # Validate amount (rejects NaN / inf, rounds to kobo precision)
        try:
            amount = round(float(amount), 2)
        except (ValueError, TypeError):
            return error_response("Amount must be a valid number.")

        if not math.isfinite(amount) or amount <= 0:
            return error_response("Amount must be greater than zero.")

        if amount > 1000000:  # Reasonable upper limit for MVP
            return error_response("Amount exceeds maximum limit of 1,000,000.")

        db_ref = get_db_ref()

        # 1. Verify sender's PIN (rate-limited: 5 wrong guesses lock it)
        sender_ref = db_ref.child("users").child(g.user_id)
        sender_data = sender_ref.get()

        if not sender_data:
            return error_response("Sender account not found.", 404)

        pin_error = check_pin(g.user_id, pin, sender_data.get('pin_hash'))
        if pin_error:
            return pin_error

        # 2. Look up recipient by kr_tag
        kr_tags_ref = db_ref.child("kr_tags")
        recipient_uid = kr_tags_ref.child(recipient_tag).get()

        if not recipient_uid:
            return error_response("Recipient not found. Check the kr_tag and try again.", 404)

        # 3. Cannot send to self
        if recipient_uid == g.user_id:
            return error_response("You cannot send money to yourself.", 400)

        # 4. Get recipient data
        recipient_ref = db_ref.child("users").child(recipient_uid)
        recipient_data = recipient_ref.get()

        if not recipient_data:
            return error_response("Recipient account not found.", 404)

        # 5. Atomic transfer: both balances change in ONE conditional write
        #    on the common parent node, or neither does.
        txn_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        state = {"ok": False, "reason": None, "balance": 0.0, "new_balance": None}

        def transfer(users):
            # May be re-run on write conflicts, so reset state every time.
            state.update(ok=False, reason=None)
            users = users or {}
            sender = users.get(g.user_id)
            target = users.get(recipient_uid)
            if not isinstance(sender, dict) or not isinstance(target, dict):
                state["reason"] = "missing"
                return users
            sender_balance = float(sender.get('balance') or 0)
            if sender_balance < amount:
                state.update(reason="insufficient", balance=sender_balance)
                return users
            sender['balance'] = round(sender_balance - amount, 2)
            target['balance'] = round(float(target.get('balance') or 0) + amount, 2)
            state.update(ok=True, new_balance=sender['balance'])
            return users

        try:
            db_ref.child("users").transaction(transfer)
        except Exception as e:
            print(f"Transfer transaction failed: {e}")
            return error_response("Transaction failed. Please try again.", 500)

        if not state["ok"]:
            if state["reason"] == "insufficient":
                return error_response(
                    f"Insufficient balance. Your balance is {state['balance']:.2f}.", 400)
            return error_response("Account not found.", 404)

        # 6. Money has moved. History records are written after the transfer;
        #    a failure here must not report the transfer as failed.
        try:
            db_ref.child("transactions").child(g.user_id).child(txn_id).set({
                "type": "debit",
                "amount": amount,
                "counterparty_uid": recipient_uid,
                "counterparty_name": recipient_data.get('name'),
                "counterparty_kr_tag": recipient_tag,
                "timestamp": timestamp,
                "status": "completed",
                "description": description,
            })
            db_ref.child("transactions").child(recipient_uid).child(txn_id).set({
                "type": "credit",
                "amount": amount,
                "counterparty_uid": g.user_id,
                "counterparty_name": sender_data.get('name'),
                "counterparty_kr_tag": sender_data.get('kr_tag'),
                "timestamp": timestamp,
                "status": "completed",
                "description": description,
            })
        except Exception as e:
            print(f"CRITICAL: history write failed for transfer {txn_id}: {e}")

        # 7. Return success
        new_balance = state["new_balance"]
        try:
            send_push_notification(
                recipient_uid,
                'Payment received',
                f'You received ₦{amount:,.2f} from {sender_data.get("name", "a Kerion user")}.',
                {'type': 'credit', 'transaction_id': txn_id},
            )
        except Exception as notification_error:
            print(f"Push notification delivery failed: {notification_error}")

        return success_response({
            "transaction_id": txn_id,
            "amount": amount,
            "recipient_name": recipient_data.get('name'),
            "recipient_kr_tag": recipient_tag,
            "new_balance": new_balance,
            "timestamp": timestamp,
        })

    except Exception as e:
        return error_response(f"An unexpected error occurred: {str(e)}", 500)


@wallet_bp.route('/api/wallet/topup', methods=['POST'])
@require_auth
def topup_wallet():
    """Add simulated testnet funds after PIN verification."""
    try:
        data = request.get_json(silent=True) or {}
        amount = data.get('amount')
        pin = data.get('pin', '')

        if not validate_pin(pin):
            return error_response("PIN must be exactly 4 digits.")
        try:
            amount = round(float(amount), 2)
        except (TypeError, ValueError):
            return error_response("Amount must be a valid number.")
        if not math.isfinite(amount) or amount < 100:
            return error_response("Minimum top-up amount is 100.")
        if amount > 1000000:
            return error_response("Top-up amount exceeds the maximum limit of 1,000,000.")

        db_ref = get_db_ref()
        user_ref = db_ref.child("users").child(g.user_id)
        user_data = user_ref.get()
        if not user_data:
            return error_response("User account not found.", 404)

        pin_error = check_pin(g.user_id, pin, user_data.get('pin_hash'))
        if pin_error:
            return pin_error

        # Add inside a transaction so a concurrent send is never overwritten.
        state = {}

        def add(balance):
            state["new_balance"] = round(float(balance or 0) + amount, 2)
            return state["new_balance"]

        try:
            user_ref.child('balance').transaction(add)
        except Exception as e:
            print(f"Top-up transaction failed: {e}")
            return error_response("Top-up failed. Please try again.", 500)

        new_balance = state["new_balance"]
        transaction_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        try:
            db_ref.child("transactions").child(g.user_id).child(transaction_id).set({
                "type": "topup",
                "amount": amount,
                "counterparty_name": "Testnet",
                "timestamp": timestamp,
                "status": "completed",
                "description": "Simulated testnet top-up",
            })
        except Exception as e:
            print(f"CRITICAL: history write failed for top-up {transaction_id}: {e}")

        return success_response({
            "transaction_id": transaction_id,
            "amount": amount,
            "new_balance": new_balance,
            "timestamp": timestamp,
        })
    except Exception as e:
        print(f"Top-up failed: {e}")
        return error_response("Top-up failed. Please try again.", 500)


@wallet_bp.route('/api/device/register', methods=['POST'])
@require_auth
def register_device():
    """Store the authenticated device's FCM token for future notifications."""
    try:
        data = request.get_json(silent=True) or {}
        token = data.get('fcm_token')
        if not isinstance(token, str) or not token.strip():
            return error_response("A non-empty fcm_token is required.")

        token = token.strip()
        # A hash is Firebase-key-safe and avoids using the token itself as a key.
        token_id = hashlib.sha256(token.encode('utf-8')).hexdigest()
        get_db_ref(f"devices/{g.user_id}/{token_id}").set({
            "fcm_token": token,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        })
        return success_response({"registered": True})
    except Exception as e:
        return error_response(f"Device registration failed: {str(e)}", 500)


@wallet_bp.route('/api/wallet/transactions', methods=['GET'])
@require_auth
def get_transactions():
    """Get current user's transaction history."""
    try:
        # Optional pagination params
        limit = request.args.get('limit', 50, type=int)
        offset = request.args.get('offset', 0, type=int)

        if limit > 100:
            limit = 100  # Cap at 100

        transactions_ref = get_db_ref(f"transactions/{g.user_id}")
        transactions = transactions_ref.get()

        if not transactions:
            return success_response({
                "transactions": [],
                "count": 0
            })

        # Convert to list and sort by timestamp (newest first)
        txn_list = []
        for txn_id, txn_data in transactions.items():
            txn_data['transaction_id'] = txn_id
            txn_list.append(txn_data)

        txn_list.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

        # Apply pagination
        total_count = len(txn_list)
        paginated = txn_list[offset:offset + limit]

        return success_response({
            "transactions": paginated,
            "count": total_count,
            "limit": limit,
            "offset": offset
        })

    except Exception as e:
        return error_response(f"Failed to fetch transactions: {str(e)}", 500)
