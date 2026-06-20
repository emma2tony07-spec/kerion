from flask import Blueprint, request, g
from datetime import datetime, timezone
import uuid

from firebase_config import get_db_ref
from utils.helpers import (
    verify_pin, error_response, success_response, validate_pin
)
from utils.auth_middleware import require_auth

wallet_bp = Blueprint('wallet', __name__)


@wallet_bp.route('/api/wallet/balance', methods=['GET'])
@require_auth
def get_balance():
    """Get current user's balance."""
    try:
        user_ref = get_db_ref(f"users/{g.user_id}")
        user_data = user_ref.get()

        if not user_data:
            return error_response("User not found.", 404)

        return success_response({
            "balance": user_data.get('balance', 0.00),
            "kr_tag": user_data.get('kr_tag'),
            "name": user_data.get('name')
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

        # 1. Try direct kr_tag lookup
        uid = db_ref.child("kr_tags").child(query).get()
        if uid:
            user_data = db_ref.child("users").child(uid).get()
            if user_data:
                return success_response({
                    "kr_tag": user_data.get('kr_tag'),
                    "name": user_data.get('name')
                })

        # 2. Search by email or phone
        all_users = db_ref.child("users").get()
        if all_users:
            for uid, user_data in all_users.items():
                if uid == g.user_id:
                    continue
                if user_data.get('email', '').lower() == query.lower():
                    return success_response({
                        "kr_tag": user_data.get('kr_tag'),
                        "name": user_data.get('name')
                    })
                if user_data.get('phone', '') == query:
                    return success_response({
                        "kr_tag": user_data.get('kr_tag'),
                        "name": user_data.get('name')
                    })

        return error_response("User not found.", 404)

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

        if not recipient_tag or not amount or not pin:
            return error_response("kr_tag, amount, and pin are required.")

        if not validate_pin(pin):
            return error_response("PIN must be exactly 4 digits.")

        try:
            amount = float(amount)
        except (ValueError, TypeError):
            return error_response("Amount must be a valid number.")

        if amount <= 0:
            return error_response("Amount must be greater than zero.")

        if amount > 1000000:
            return error_response("Amount exceeds maximum limit of 1,000,000.")

        db_ref = get_db_ref()

        # Get sender data
        sender_ref = db_ref.child("users").child(g.user_id)
        sender_data = sender_ref.get()

        if not sender_data:
            return error_response("Sender account not found.", 404)

        # Verify PIN
        if not verify_pin(pin, sender_data.get('pin_hash', '')):
            return error_response("Incorrect PIN.", 401)

        # Find recipient
        recipient_uid = db_ref.child("kr_tags").child(recipient_tag).get()
        if not recipient_uid:
            return error_response("Recipient not found.", 404)

        if recipient_uid == g.user_id:
            return error_response("You cannot send money to yourself.", 400)

        recipient_ref = db_ref.child("users").child(recipient_uid)
        recipient_data = recipient_ref.get()

        if not recipient_data:
            return error_response("Recipient account not found.", 404)

        # Check balance
        sender_balance = sender_data.get('balance', 0.00)
        if sender_balance < amount:
            return error_response(
                f"Insufficient balance. You have {sender_balance:,.2f}.", 400
            )

        # Calculate new balances
        new_sender_balance = round(sender_balance - amount, 2)
        new_recipient_balance = round(recipient_data.get('balance', 0.00) + amount, 2)

        # Create transaction records
        txn_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        sender_name = sender_data.get('name', 'Unknown')
        sender_tag = sender_data.get('kr_tag', '')
        recipient_name = recipient_data.get('name', 'Unknown')

        debit_txn = {
            "type": "debit",
            "amount": amount,
            "counterparty_uid": recipient_uid,
            "counterparty_name": recipient_name,
            "counterparty_kr_tag": recipient_tag,
            "timestamp": timestamp,
            "status": "completed",
            "description": description or f"Sent to {recipient_name}"
        }

        credit_txn = {
            "type": "credit",
            "amount": amount,
            "counterparty_uid": g.user_id,
            "counterparty_name": sender_name,
            "counterparty_kr_tag": sender_tag,
            "timestamp": timestamp,
            "status": "completed",
            "description": description or f"Received from {sender_name}"
        }

        # Write everything
        sender_ref.child('balance').set(new_sender_balance)
        recipient_ref.child('balance').set(new_recipient_balance)
        db_ref.child("transactions").child(g.user_id).child(txn_id).set(debit_txn)
        db_ref.child("transactions").child(recipient_uid).child(txn_id).set(credit_txn)

        return success_response({
            "transaction_id": txn_id,
            "amount": amount,
            "recipient_name": recipient_name,
            "recipient_kr_tag": recipient_tag,
            "new_balance": new_sender_balance,
            "timestamp": timestamp
        })

    except Exception as e:
        return error_response(f"Transaction failed: {str(e)}", 500)


@wallet_bp.route('/api/wallet/transactions', methods=['GET'])
@require_auth
def get_transactions():
    """Get current user's transaction history."""
    try:
        limit = request.args.get('limit', 50, type=int)
        offset = request.args.get('offset', 0, type=int)

        if limit > 100:
            limit = 100

        transactions_ref = get_db_ref(f"transactions/{g.user_id}")
        transactions = transactions_ref.get()

        if not transactions:
            return success_response({
                "transactions": [],
                "count": 0
            })

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


@wallet_bp.route('/api/wallet/topup', methods=['POST'])
@require_auth
def topup():
    """Mock top-up — adds funds for testing."""
    try:
        data = request.get_json()

        if not data:
            return error_response("Request body is required.")

        try:
            amount = float(data.get('amount', 0))
        except (ValueError, TypeError):
            return error_response("Amount must be a valid number.")

        if amount < 100:
            return error_response("Minimum top-up is ₦100.")
        if amount > 10000000:
            return error_response("Maximum top-up is ₦10,000,000.")

        # Optional PIN verification for top-up
        pin = data.get('pin', '')
        if pin:
            if not validate_pin(pin):
                return error_response("PIN must be exactly 4 digits.")
            db_ref = get_db_ref()
            user_data = db_ref.child("users").child(g.user_id).get()
            if not user_data:
                return error_response("User not found.", 404)
            if not verify_pin(pin, user_data.get('pin_hash', '')):
                return error_response("Incorrect PIN.", 401)

        db_ref = get_db_ref()
        user_ref = db_ref.child("users").child(g.user_id)
        user_data = user_ref.get()

        if not user_data:
            return error_response("User not found.", 404)

        current_balance = user_data.get('balance', 0.00)
        new_balance = round(current_balance + amount, 2)

        txn_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        txn_data = {
            "type": "topup",
            "amount": amount,
            "counterparty_uid": g.user_id,
            "counterparty_name": "Testnet Top-Up",
            "counterparty_kr_tag": "system",
            "timestamp": timestamp,
            "status": "completed",
            "description": "Testnet simulated top-up"
        }

        user_ref.child('balance').set(new_balance)
        db_ref.child("transactions").child(g.user_id).child(txn_id).set(txn_data)

        return success_response({
            "transaction_id": txn_id,
            "amount": amount,
            "new_balance": new_balance
        })

    except Exception as e:
        return error_response(f"Top-up failed: {str(e)}", 500)
