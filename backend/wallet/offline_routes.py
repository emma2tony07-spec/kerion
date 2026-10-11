"""Authoritative redemption endpoints for Android offline payment offers.

The server, not either phone, decides whether a signed offer transfers value.
"""
import base64
import json
import re
import secrets
import uuid
from math import asin, cos, radians, sin, sqrt
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from firebase_admin import db as firebase_db
from flask import Blueprint, g, request

from firebase_config import get_db_ref
from utils.auth_middleware import require_auth
from utils.helpers import error_response, success_response

offline_bp = Blueprint("offline", __name__)

OFFLINE_LIMIT_KOBO = 200_000  # ₦2,000.00; all protocol money is integer kobo.
MAX_PENDING_OFFERS = 3
PERMIT_DAYS = 7
OFFER_SECONDS = 5 * 60
RADIUS_METERS = 500

_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
_TAG_RE = re.compile(r"^kr-\d{10}$")


def _now():
    return datetime.now(timezone.utc)


def _canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _location(data):
    location = data.get("location") or {}
    try:
        lat, lon = float(location["latitude"]), float(location["longitude"])
    except (KeyError, TypeError, ValueError):
        raise ValueError("Current location is required.")
    if not -90 <= lat <= 90 or not -180 <= lon <= 180:
        raise ValueError("Location coordinates are invalid.")
    return {"latitude": lat, "longitude": lon, "captured_at": _now().isoformat()}


def _distance_meters(first, second):
    """Haversine distance; this is a fraud-risk signal, not location proof."""
    lat1, lon1 = radians(first["latitude"]), radians(first["longitude"])
    lat2, lon2 = radians(second["latitude"]), radians(second["longitude"])
    a = sin((lat2 - lat1) / 2) ** 2 + cos(lat1) * cos(lat2) * sin((lon2 - lon1) / 2) ** 2
    return 6_371_000 * 2 * asin(sqrt(a))


def _issue_or_refresh_permit(uid, location):
    """Maintain one active, server-held ₦2,000 reserve per enrolled device."""
    permit_ref = get_db_ref(f"offline_permits/{uid}")
    existing = permit_ref.get() or {}
    expires_at = _now() + timedelta(days=PERMIT_DAYS)
    if existing.get("status") == "active" and existing.get("expires_at", "") > _now().isoformat():
        existing["last_location"] = location
        permit_ref.update({"last_location": location})
        return existing

    user_ref = get_db_ref(f"users/{uid}")
    user = user_ref.get() or {}
    balance_kobo = int(round(float(user.get("balance", 0)) * 100))
    reserve = min(OFFLINE_LIMIT_KOBO, balance_kobo)
    if reserve <= 0:
        raise ValueError("No available balance can be reserved for offline payments.")

    # The reserve is removed from spendable online balance before any offline
    # offer can exist. Redemption can therefore never overdraw the account.
    user_ref.update({"balance": round((balance_kobo - reserve) / 100, 2)})
    permit = {
        "permit_id": secrets.token_urlsafe(24),
        "status": "active",
        "reserved_kobo": reserve,
        "remaining_kobo": reserve,
        "pending_offer_ids": [],
        "expires_at": expires_at.isoformat(),
        "last_location": location,
    }
    permit_ref.set(permit)
    return permit


@offline_bp.route("/api/offline/enroll", methods=["POST"])
@require_auth
def enroll_device():
    """Register an Android Ed25519 public key and obtain the current permit."""
    try:
        data = request.get_json(silent=True) or {}
        device_id = data.get("device_id")
        public_key = data.get("public_key")
        if not isinstance(device_id, str) or not _ID_RE.match(device_id):
            return error_response("A valid device ID is required.")
        try:
            raw_key = base64.b64decode(public_key, validate=True)
            Ed25519PublicKey.from_public_bytes(raw_key)
        except Exception:
            return error_response("The device public key is not a valid Ed25519 key.")
        location = _location(data)
        get_db_ref(f"offline_devices/{g.user_id}/{device_id}").set({
            "public_key": public_key,
            "platform": "android",
            "last_location": location,
            "updated_at": _now().isoformat(),
            "active": True,
        })
        permit = _issue_or_refresh_permit(g.user_id, location)
        return success_response({"permit": permit, "limit_kobo": OFFLINE_LIMIT_KOBO,
                                 "max_pending_offers": MAX_PENDING_OFFERS})
    except ValueError as exc:
        return error_response(str(exc), 400)
    except Exception as exc:
        return error_response(f"Offline enrollment failed: {exc}", 500)


_REQUIRED_FIELDS = {
    "version", "permit_id", "device_id", "transaction_id", "sender", "recipient",
    "amount_kobo", "nonce", "issued_at", "expires_at",
    "sender_lat_e6", "sender_lon_e6",  # sender GPS at offer time, micro-degrees
}
_INT_FIELDS = ("version", "amount_kobo", "nonce", "issued_at", "expires_at",
               "sender_lat_e6", "sender_lon_e6")
_ID_FIELDS = ("permit_id", "device_id", "transaction_id")


def _validate_payload(payload):
    """Return an error message, or None if the payload is well formed."""
    if set(payload) != _REQUIRED_FIELDS:
        return "Payment payload fields are invalid."
    for key in _INT_FIELDS:
        if type(payload[key]) is not int:  # also rejects bool
            return "Payment payload fields are invalid."
    for key in _ID_FIELDS:
        if not isinstance(payload[key], str) or not _ID_RE.match(payload[key]):
            return "Payment payload fields are invalid."
    for key in ("sender", "recipient"):
        if not isinstance(payload[key], str) or not _TAG_RE.match(payload[key]):
            return "Payment payload fields are invalid."
    if payload["version"] != 1:
        return "Payment payload version is invalid."
    if not 0 < payload["amount_kobo"] <= OFFLINE_LIMIT_KOBO:
        return "Payment amount is invalid."
    if not -90_000_000 <= payload["sender_lat_e6"] <= 90_000_000 or \
            not -180_000_000 <= payload["sender_lon_e6"] <= 180_000_000:
        return "Payment location is invalid."
    return None


@offline_bp.route("/api/offline/redeem", methods=["POST"])
@require_auth
def redeem_offer():
    """Verify and atomically settle a five-minute Android-signed offer."""
    try:
        envelope = request.get_json(silent=True) or {}
        payload, signature = envelope.get("payload"), envelope.get("signature")
        if not isinstance(payload, dict) or not isinstance(signature, str):
            return error_response("A signed payment payload is required.")
        problem = _validate_payload(payload)
        if problem:
            return error_response(problem)

        now_ms = int(_now().timestamp() * 1000)
        if (payload["expires_at"] - payload["issued_at"] > OFFER_SECONDS * 1000
                or payload["expires_at"] < now_ms - 30_000
                or payload["issued_at"] > now_ms + 30_000):
            return error_response("This payment offer has expired.")

        receiver = get_db_ref(f"users/{g.user_id}").get() or {}
        if payload["recipient"] != receiver.get("kr_tag"):
            return error_response("This payment is not addressed to your account.", 403)
        sender_uid = get_db_ref(f"kr_tags/{payload['sender']}").get()
        if not sender_uid or sender_uid == g.user_id:
            return error_response("The payment sender is invalid.", 400)
        device = get_db_ref(f"offline_devices/{sender_uid}/{payload['device_id']}").get() or {}
        if not device.get("active"):
            return error_response("The sender device is not enrolled for offline payments.", 403)
        try:
            Ed25519PublicKey.from_public_bytes(base64.b64decode(device["public_key"], validate=True)).verify(
                base64.b64decode(signature, validate=True), _canonical(payload))
        except (InvalidSignature, ValueError, KeyError):
            return error_response("The payment signature is invalid.", 403)

        # Proximity: the sender's GPS reading is inside the signed payload, so
        # it cannot be altered after signing. A fraud signal, not proof.
        try:
            receiver_location = _location(envelope)
        except ValueError as exc:
            return error_response(str(exc), 400)
        sender_location = {"latitude": payload["sender_lat_e6"] / 1e6,
                           "longitude": payload["sender_lon_e6"] / 1e6}
        if _distance_meters(sender_location, receiver_location) > RADIUS_METERS:
            return error_response(
                f"The sender is not within the {RADIUS_METERS} m offline-payment radius.", 403)

        # One root transaction makes replay marking, permit depletion, and
        # recipient credit one indivisible Firebase operation.
        def redeem(state):
            state = state or {}
            permit = state.get("offline_permits", {}).get(sender_uid, {})
            redemptions = state.setdefault("offline_redemptions", {}).setdefault(payload["permit_id"], {})
            if payload["transaction_id"] in redemptions:
                raise ValueError("This payment offer has already been redeemed.")
            if (permit.get("permit_id") != payload["permit_id"] or
                    permit.get("status") != "active" or
                    permit.get("expires_at", "") < _now().isoformat()):
                raise ValueError("The sender's offline permit is unavailable.")
            if payload["amount_kobo"] > int(permit.get("remaining_kobo", 0)):
                raise ValueError("The offline permit has insufficient remaining value.")
            permit["remaining_kobo"] = int(permit["remaining_kobo"]) - payload["amount_kobo"]
            redemptions[payload["transaction_id"]] = {
                "sender_uid": sender_uid, "receiver_uid": g.user_id,
                "amount_kobo": payload["amount_kobo"], "redeemed_at": _now().isoformat(),
            }
            users = state.setdefault("users", {})
            sender = users.get(sender_uid) or {}
            target = users.get(g.user_id) or {}
            target["balance"] = round(float(target.get("balance", 0)) + payload["amount_kobo"] / 100, 2)
            # A confirmed redemption refills the reserve only when the sender
            # has enough unreserved value; money is conserved either way.
            available_kobo = int(round(float(sender.get("balance", 0)) * 100))
            if available_kobo >= payload["amount_kobo"]:
                sender["balance"] = round((available_kobo - payload["amount_kobo"]) / 100, 2)
                permit["remaining_kobo"] += payload["amount_kobo"]
                permit["expires_at"] = (_now() + timedelta(days=PERMIT_DAYS)).isoformat()
            state["offline_permits"][sender_uid] = permit
            users[sender_uid] = sender
            users[g.user_id] = target
            return state

        try:
            get_db_ref().transaction(redeem)
        except ValueError as exc:
            return error_response(str(exc), 409)
        except firebase_db.TransactionAbortedError:
            return error_response("The server is busy. Please try again.", 503)

        # Money has moved; history is best-effort, like a push notification.
        try:
            amount = payload["amount_kobo"] / 100
            timestamp = _now().isoformat()
            txn_id = str(uuid.uuid4())
            sender_profile = get_db_ref(f"users/{sender_uid}").get() or {}
            get_db_ref(f"transactions/{sender_uid}/{txn_id}").set({
                "type": "debit", "amount": amount,
                "counterparty_uid": g.user_id,
                "counterparty_name": receiver.get("name"),
                "counterparty_kr_tag": receiver.get("kr_tag"),
                "timestamp": timestamp, "status": "completed",
                "description": "Offline payment",
            })
            get_db_ref(f"transactions/{g.user_id}/{txn_id}").set({
                "type": "credit", "amount": amount,
                "counterparty_uid": sender_uid,
                "counterparty_name": sender_profile.get("name"),
                "counterparty_kr_tag": sender_profile.get("kr_tag"),
                "timestamp": timestamp, "status": "completed",
                "description": "Offline payment",
            })
        except Exception as exc:
            print(f"CRITICAL: history write failed for offline {payload['transaction_id']}: {exc}")

        return success_response({"status": "confirmed", "transaction_id": payload["transaction_id"],
                                 "amount_kobo": payload["amount_kobo"]})
    except Exception as exc:
        print(f"Offline redeem failed: {exc}")
        return error_response("Payment verification failed. Please try again.", 500)


@offline_bp.route("/api/offline/nearby", methods=["POST"])
@require_auth
def nearby_peers():
    """Return minimal opt-in nearby profiles within the initial 500 m radius."""
    try:
        location = _location(request.get_json(silent=True) or {})
        devices = get_db_ref("offline_devices").get() or {}
        peers = []
        for uid, user_devices in devices.items():
            if uid == g.user_id:
                continue
            for device in (user_devices or {}).values():
                if not device.get("active") or not device.get("last_location"):
                    continue
                distance = _distance_meters(location, device["last_location"])
                if distance <= RADIUS_METERS:
                    user = get_db_ref(f"users/{uid}").get() or {}
                    peers.append({"kr_tag": user.get("kr_tag"), "name": user.get("name"),
                                  "distance_meters": round(distance)})
                    break
        return success_response({"peers": peers})
    except ValueError as exc:
        return error_response(str(exc), 400)
    except Exception as exc:
        print(f"Nearby-peer lookup failed: {exc}")
        return error_response("Nearby-peer lookup failed.", 500)