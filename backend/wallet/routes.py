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
        
        # Validate amount
        try:
            amount = float(amount)
        except (ValueError, TypeError):
            return error_response("Amount must be a valid number.")
        
        if amount <= 0:
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
        
        # 5. Check sufficient balance
        current_balance = sender_data.get('balance', 0.00)
        if current_balance < amount:
            return error_response(f"Insufficient balance. Your balance is {current_balance:.2f}.", 400)
        
        # 6. Perform atomic transaction
        transaction_result = {"success": False, "txn_id": None}
        
        def perform_transfer(current_data):
            """Atomic transfer function for Firebase transaction."""
            # This runs atomically on the server side
            if current_data is None:
                return current_data
            
            sender_balance = current_data.get('balance', 0.00)
            recipient_balance = recipient_ref.child('balance').get() or 0.00
            
            # Double-check balance (prevents race conditions)
            if sender_balance < amount:
                raise ValueError("Insufficient balance.")
            
            new_sender_balance = round(sender_balance - amount, 2)
            new_recipient_balance = round(recipient_balance + amount, 2)
            
            # Generate transaction ID
            txn_id = str(uuid.uuid4())
            timestamp = datetime.now(timezone.utc).isoformat()
            
            # Create transaction records
            debit_txn = {
                "type": "debit",
                "amount": amount,
                "counterparty_uid": recipient_uid,
                "counterparty_name": recipient_data.get('name'),
                "counterparty_kr_tag": recipient_tag,
                "timestamp": timestamp,
                "status": "completed",
                "description": description
            }
            
            credit_txn = {
                "type": "credit",
                "amount": amount,
                "counterparty_uid": g.user_id,
                "counterparty_name": sender_data.get('name'),
                "counterparty_kr_tag": sender_data.get('kr_tag'),
                "timestamp": timestamp,
                "status": "completed",
                "description": description
            }
            
            # Apply all updates
            sender_ref.child('balance').set(new_sender_balance)
            recipient_ref.child('balance').set(new_recipient_balance)
            
            # Store transactions under each user
            db_ref.child("transactions").child(g.user_id).child(txn_id).set(debit_txn)
            db_ref.child("transactions").child(recipient_uid).child(txn_id).set(credit_txn)
            
            transaction_result["success"] = True
            transaction_result["txn_id"] = txn_id
            
            return {"balance": new_sender_balance}
        
        # Execute transaction
        try:
            sender_ref.child('balance').transaction(perform_transfer)
        except ValueError as e:
            return error_response(str(e), 400)
        except Exception as e:
            return error_response(f"Transaction failed. Please try again.", 500)
        
        if not transaction_result["success"]:
            return error_response("Transaction failed. Please try again.", 500)
        
        # 7. Return success
        new_balance = sender_ref.child('balance').get()
        
        return success_response({
            "transaction_id": transaction_result["txn_id"],
            "amount": amount,
            "recipient_name": recipient_data.get('name'),
            "recipient_kr_tag": recipient_tag,
            "new_balance": new_balance,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        
    except Exception as e:
        return error_response(f"An unexpected error occurred: {str(e)}", 500)


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