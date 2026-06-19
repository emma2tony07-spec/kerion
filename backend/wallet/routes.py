from flask import Blueprint, request, g
from datetime import datetime, timezone
import uuid

from firebase_config import get_db_ref
from utils.helpers import (
    verify_pin, error_response, success_response, validate_pin
)
from utils.auth_middleware import require_auth

wallet_bp = Blueprint('wallet', __name__)


# ═══════════════════════════════
# BALANCE
# ═══════════════════════════════
@wallet_bp.route('/api/wallet/balance', methods=['GET'])
@require_auth
def get_balance():
    """Get current user's balance and profile info."""
    try:
        user_ref = get_db_ref(f"users/{g.user_id}")
        user_data = user_ref.get()

        if not user_data:
            return error_response("User not found.", 404)

        return success_response({
            "balance": user_data.get('balance', 0.00),
            "kr_tag": user_data.get('kr_tag'),
            "name": user_data.get('name'),
            "email": user_data.get('email'),
            "phone": user_data.get('phone')
        })

    except Exception as e:
        return error_response(f"Failed to fetch balance: {str(e)}", 500)


# ═══════════════════════════════
# USER LOOKUP
# ═══════════════════════════════
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

        # 1. Try kr_tag lookup first (fastest — direct key lookup)
        uid = db_ref.child("kr_tags").child(query).get()
        if uid:
            user_data = db_ref.child("users").child(uid).get()
            if user_data and uid != g.user_id:
                return success_response({
                    "kr_tag": user_data.get('kr_tag'),
                    "name": user_data.get('name')
                })

        # 2. Scan users for email or phone match
        all_users = db_ref.child("users").get()
        if all_users:
            for uid, user_data in all_users.items():
                if uid == g.user_id:
                    continue

                email_match = user_data.get('email', '').lower() == query.lower()
                phone_match = user_data.get('phone', '') == query

                if email_match or phone_match:
                    return success_response({
                        "kr_tag": user_data.get('kr_tag'),
                        "name": user_data.get('name')
                    })

        return error_response("User not found. Check the kr_tag, email, or phone and try again.", 404)

    except Exception as e:
        return error_response(f"Lookup failed: {str(e)}", 500)


# ═══════════════════════════════
# SEND MONEY
# ═══════════════════════════════
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
        if not recipient_tag:
            return error_response("Recipient kr_tag is required.")
        if amount is None:
            return error_response("Amount is required.")
        if not pin:
            return error_response("PIN is required.")

        if not validate_pin(pin):
            return error_response("PIN must be exactly 4 digits.")

        # Validate amount
        try:
            amount = float(amount)
        except (ValueError, TypeError):
            return error_response("Amount must be a valid number.")

        if amount <= 0:
            return error_response("Amount must be greater than zero.")
        if amount > 1000000:
            return error_response("Amount exceeds maximum limit of ₦1,000,000.")
        if round(amount, 2) != amount:
            return error_response("Amount can have at most 2 decimal places.")

        db_ref = get_db_ref()

        # 1. Verify sender exists and PIN is correct
        sender_ref = db_ref.child("users").child(g.user_id)
        sender_data = sender_ref.get()
        if not sender_data:
            return error_response("Sender account not found.", 404)

        if not verify_pin(pin, sender_data.get('pin_hash', '')):
            return error_response("Incorrect PIN.", 401)

        # 2. Look up recipient
        recipient_uid = db_ref.child("kr_tags").child(recipient_tag).get()
        if not recipient_uid:
            return error_response("Recipient not found. Check the kr_tag and try again.", 404)

        if recipient_uid == g.user_id:
            return error_response("You cannot send money to yourself.", 400)

        recipient_ref = db_ref.child("users").child(recipient_uid)
        recipient_data = recipient_ref.get()
        if not recipient_data:
            return error_response("Recipient account not found.", 404)

        # 3. Check balance
        current_balance = sender_data.get('balance', 0.00)
        if current_balance < amount:
            return error_response(
                f"Insufficient balance. Your balance is ₦{current_balance:,.2f}.",
                400
            )

        # 4. Perform atomic transfer
        txn_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        transfer_successful = False

        def perform_transfer(current_sender):
            nonlocal transfer_successful
            if current_sender is None:
                return None

            sender_bal = current_sender.get('balance', 0.00)

            # Final balance check inside transaction
            if sender_bal < amount:
                raise Exception("Insufficient balance.")

            new_sender_balance = round(sender_bal - amount, 2)

            # Read current recipient balance
            current_recipient = recipient_ref.get()
            recipient_bal = current_recipient.get('balance', 0.00) if current_recipient else 0.00
            new_recipient_balance = round(recipient_bal + amount, 2)

            # Build transaction records
            debit_txn = {
                "type": "debit",
                "amount": amount,
                "counterparty_uid": recipient_uid,
                "counterparty_name": recipient_data.get('name', 'Unknown'),
                "counterparty_kr_tag": recipient_tag,
                "timestamp": timestamp,
                "status": "completed",
                "description": description
            }
            credit_txn = {
                "type": "credit",
                "amount": amount,
                "counterparty_uid": g.user_id,
                "counterparty_name": sender_data.get('name', 'Unknown'),
                "counterparty_kr_tag": sender_data.get('kr_tag', ''),
                "timestamp": timestamp,
                "status": "completed",
                "description": description
            }

            # Write everything atomically
            updates = {
                f"users/{g.user_id}/balance": new_sender_balance,
                f"users/{recipient_uid}/balance": new_recipient_balance,
                f"transactions/{g.user_id}/{txn_id}": debit_txn,
                f"transactions/{recipient_uid}/{txn_id}": credit_txn,
            }
            db_ref.update(updates)

            transfer_successful = True
            return {"balance": new_sender_balance}

        try:
            sender_ref.child('balance').transaction(perform_transfer)
        except Exception as e:
            return error_response(f"Transaction failed: {str(e)}", 500)

        if not transfer_successful:
            return error_response("Transaction could not be completed. Please try again.", 500)

        # 5. Return receipt
        new_balance = sender_ref.child('balance').get()
        return success_response({
            "transaction_id": txn_id,
            "amount": amount,
            "recipient_name": recipient_data.get('name'),
            "recipient_kr_tag": recipient_tag,
            "new_balance": new_balance,
            "timestamp": timestamp
        })

    except Exception as e:
        return error_response(f"An unexpected error occurred: {str(e)}", 500)


# ═══════════════════════════════
# TOP UP (TESTNET)
# ═══════════════════════════════
@wallet_bp.route('/api/wallet/topup', methods=['POST'])
@require_auth
def topup():
    """Add funds to wallet — testnet mode, instant credit."""
    try:
        data = request.get_json()
        if not data:
            return error_response("Request body is required.")

        amount = data.get('amount')
        pin = data.get('pin', '')

        if amount is None:
            return error_response("Amount is required.")
        if not pin:
            return error_response("PIN is required.")

        if not validate_pin(pin):
            return error_response("PIN must be exactly 4 digits.")

        try:
            amount = float(amount)
        except (ValueError, TypeError):
            return error_response("Amount must be a valid number.")

        if amount <= 0:
            return error_response("Amount must be greater than zero.")
        if amount > 10000000:
            return error_response("Maximum top-up is ₦10,000,000.")

        db_ref = get_db_ref()
        user_ref = db_ref.child("users").child(g.user_id)
        user_data = user_ref.get()

        if not user_data:
            return error_response("User not found.", 404)

        # Verify PIN
        if not verify_pin(pin, user_data.get('pin_hash', '')):
            return error_response("Incorrect PIN.", 401)

        # Credit balance
        current_balance = user_data.get('balance', 0.00)
        new_balance = round(current_balance + amount, 2)

        txn_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        # Atomic update: balance + transaction record
        updates = {
            f"users/{g.user_id}/balance": new_balance,
            f"transactions/{g.user_id}/{txn_id}": {
                "type": "credit",
                "amount": amount,
                "counterparty_uid": "system",
                "counterparty_name": "Wallet Top-Up",
                "counterparty_kr_tag": "kr-topup",
                "timestamp": timestamp,
                "status": "completed",
                "description": "Testnet top-up"
            }
        }
        db_ref.update(updates)

        return success_response({
            "transaction_id": txn_id,
            "amount": amount,
            "new_balance": new_balance,
            "timestamp": timestamp
        })

    except Exception as e:
        return error_response(f"Top-up failed: {str(e)}", 500)


# ═══════════════════════════════
# TRANSACTION HISTORY
# ═══════════════════════════════
@wallet_bp.route('/api/wallet/transactions', methods=['GET'])
@require_auth
def get_transactions():
    """Get current user's transaction history with pagination."""
    try:
        limit = request.args.get('limit', 50, type=int)
        offset = request.args.get('offset', 0, type=int)

        if limit < 1:
            limit = 1
        if limit > 100:
            limit = 100
        if offset < 0:
            offset = 0

        transactions_ref = get_db_ref(f"transactions/{g.user_id}")
        transactions = transactions_ref.get()

        if not transactions:
            return success_response({
                "transactions": [],
                "count": 0,
                "limit": limit,
                "offset": offset
            })

        # Convert dict to list, attach ID, sort by timestamp descending
        txn_list = []
        for txn_id, txn_data in transactions.items():
            txn_data['transaction_id'] = txn_id
            txn_list.append(txn_data)

        txn_list.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
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


# ═══════════════════════════════
# UPDATE USER PROFILE (for setup flow)
# ═══════════════════════════════
@wallet_bp.route('/api/user/profile', methods=['PATCH'])
@require_auth
def update_profile():
    """Update user's phone, DOB, nationality, and PIN after initial signup."""
    try:
        data = request.get_json()
        if not data:
            return error_response("Request body is required.")

        user_ref = get_db_ref(f"users/{g.user_id}")
        user_data = user_ref.get()

        if not user_data:
            return error_response("User not found.", 404)

        updates = {}
        allowed_fields = ['phone', 'dob', 'nationality']
        for field in allowed_fields:
            if field in data and data[field]:
                updates[field] = str(data[field]).strip()

        # Handle PIN update separately — requires current PIN verification
        new_pin = data.get('pin')
        if new_pin:
            current_pin = data.get('current_pin', '')
            if not current_pin:
                return error_response("Current PIN is required to set a new PIN.", 400)
            if not validate_pin(current_pin):
                return error_response("Current PIN must be 4 digits.", 400)
            if not validate_pin(new_pin):
                return error_response("New PIN must be 4 digits.", 400)
            if not verify_pin(current_pin, user_data.get('pin_hash', '')):
                return error_response("Current PIN is incorrect.", 401)
            from utils.helpers import hash_pin
            updates['pin_hash'] = hash_pin(new_pin)

        if updates:
            user_ref.update(updates)

        # Fetch updated data
        updated = user_ref.get()
        return success_response({
            "phone": updated.get('phone'),
            "dob": updated.get('dob'),
            "nationality": updated.get('nationality'),
            "kr_tag": updated.get('kr_tag'),
            "name": updated.get('name'),
            "email": updated.get('email')
        })

    except Exception as e:
        return error_response(f"Profile update failed: {str(e)}", 500)
