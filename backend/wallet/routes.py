import math
from flask import Blueprint, request, g
from datetime import datetime, timezone
import hashlib
from firebase_admin import messaging
import uuid

from firebase_config import get_db_ref
from utils.helpers import (
    verify_pin, error_response, success_response, validate_pin
)
from utils.auth_middleware import require_auth

wallet_bp = Blueprint('wallet', __name__)


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


@wallet_bp.route('/api/user/lookup', methods=['POST'])
@require_auth
def lookup_user():
    """Look up a user by kr_tag, email, or phone."""
    try:
        data = request.get_json()

        if not data:
            return error_response("Request body is required.")

        query = data.get('query', '').strip()

        if not query:
            return error_response("Provide a kr_tag, email, or phone number to look up.")

        db_ref = get_db_ref()

        # 1. Try kr_tag lookup first (fastest - direct lookup)
        kr_tag_ref = db_ref.child("kr_tags").child(query)
        uid = kr_tag_ref.get()

        if uid:
            user_data = db_ref.child("users").child(uid).get()
            if user_data:
                return success_response({
                    "kr_tag": user_data.get('kr_tag'),
                    "name": user_data.get('name')
                })

        # 2. Try email lookup
        users_ref = db_ref.child("users")
        # Firebase Realtime DB doesn't support complex queries natively
        # We need to fetch users and search (MVP approach)
        all_users = users_ref.get()

        if all_users:
            for uid, user_data in all_users.items():
                # Skip current user
                if uid == g.user_id:
                    continue

                # Check email
                if user_data.get('email', '').lower() == query.lower():
                    return success_response({
                        "kr_tag": user_data.get('kr_tag'),
                        "name": user_data.get('name')
                    })

                # Check phone
                if user_data.get('phone', '') == query:
                    return success_response({
                        "kr_tag": user_data.get('kr_tag'),
                        "name": user_data.get('name')
                    })

        return error_response("User not found. Check the kr_tag, email, or phone and try again.", 404)

    except Exception as e:
        return error_response(f"Lookup failed: {str(e)}", 500)


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

        # 1. Verify sender's PIN
        sender_ref = db_ref.child("users").child(g.user_id)
        sender_data = sender_ref.get()

        if not sender_data:
            return error_response("Sender account not found.", 404)

        if not verify_pin(pin, sender_data.get('pin_hash', '')):
            return error_response("Incorrect PIN.", 401)

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
            amount = float(amount)
        except (TypeError, ValueError):
            return error_response("Amount must be a valid number.")
        if amount < 100:
            return error_response("Minimum top-up amount is 100.")
        if amount > 1000000:
            return error_response("Top-up amount exceeds the maximum limit of 1,000,000.")

        db_ref = get_db_ref()
        user_ref = db_ref.child("users").child(g.user_id)
        user_data = user_ref.get()
        if not user_data:
            return error_response("User account not found.", 404)
        if not verify_pin(pin, user_data.get('pin_hash', '')):
            return error_response("Incorrect PIN.", 401)

        new_balance = round(float(user_data.get('balance', 0)) + amount, 2)
        transaction_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        user_ref.child('balance').set(new_balance)
        db_ref.child("transactions").child(g.user_id).child(transaction_id).set({
            "type": "topup",
            "amount": amount,
            "counterparty_name": "Testnet",
            "timestamp": timestamp,
            "status": "completed",
            "description": "Simulated testnet top-up",
        })

        return success_response({
            "transaction_id": transaction_id,
            "amount": amount,
            "new_balance": new_balance,
            "timestamp": timestamp,
        })
    except Exception as e:
        return error_response(f"Top-up failed: {str(e)}", 500)


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
