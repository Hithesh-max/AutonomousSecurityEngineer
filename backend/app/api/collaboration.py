"""API routes for multi-node encrypted transfer and security goals evaluation."""
import base64
from collections import defaultdict, deque
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from app.api.auth import get_current_user
from app.config.settings import settings
from app.models.user import User
from app.collaboration.node_transfer import (
    derive_node_key, encrypt_payload, decrypt_and_verify_payload,
    get_transfer_audit_log, MediaType
)
from app.collaboration.security_evaluation import run_full_security_goals_evaluation

router = APIRouter()
_USER_EVENTS = defaultdict(lambda: deque(maxlen=100))


class NodeTransferRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    media_type: str = Field(pattern="^(TEXT|IMAGE|AUDIO|VIDEO)$")
    sender_node: str = Field(min_length=2, max_length=50)
    receiver_node: str = Field(min_length=2, max_length=50)
    payload_b64: str = Field(min_length=1, max_length=6990508)
    shared_key_seed: str = Field(min_length=32, max_length=256)


class NodeReceiveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    packet: dict
    shared_key_seed: str = Field(min_length=32, max_length=256)


@router.post("/collaboration/node-transfer", status_code=201)
def transfer_media_packet(
    body: NodeTransferRequest,
    current_user: User = Depends(get_current_user)
):
    """Local encryption demo; no network delivery is performed."""
    try:
        raw_bytes = base64.b64decode(body.payload_b64, validate=True)
        if len(raw_bytes) > 5 * 1024 * 1024:
            raise ValueError("Oversized payload")
    except Exception:
        raise HTTPException(400, detail="Payload must be valid base64 encoded data.")

    key_seed = str(current_user.id) + "\0" + body.shared_key_seed
    encryption_key = derive_node_key(key_seed)

    packet = encrypt_payload(
        raw_bytes=raw_bytes,
        media_type=body.media_type,
        sender_node=body.sender_node,
        receiver_node=body.receiver_node,
        encryption_key=encryption_key
    )
    _USER_EVENTS[str(current_user.id)].append({"transfer_id": packet["transfer_id"], "action": "ENCRYPTED_LOCALLY", "timestamp": datetime.now(timezone.utc).isoformat()})
    return packet


@router.post("/collaboration/node-receive")
def receive_media_packet(
    body: NodeReceiveRequest,
    current_user: User = Depends(get_current_user)
):
    """Decrypt and verify received media packet with cryptographic authentication and SHA-256 integrity check."""
    key_seed = str(current_user.id) + "\0" + body.shared_key_seed
    encryption_key = derive_node_key(key_seed)

    try:
        result = decrypt_and_verify_payload(body.packet, encryption_key)
        _USER_EVENTS[str(current_user.id)].append({"transfer_id": result["transfer_id"], "action": "DECRYPTED_LOCALLY", "timestamp": datetime.now(timezone.utc).isoformat()})
        return {
            "transfer_id": result["transfer_id"],
            "media_type": result["media_type"],
            "verified_sha256": result["verified_sha256"],
            "integrity_verified": True,
            "decryption_latency_ms": result["decryption_latency_ms"],
            "payload_b64": base64.b64encode(result["raw_bytes"]).decode("ascii")
        }
    except (PermissionError, ValueError, KeyError, TypeError) as e:
        raise HTTPException(403, detail="Packet is invalid, altered, or cannot be decrypted by this user and key.")


@router.get("/collaboration/audit-log")
def get_audit_log(current_user: User = Depends(get_current_user)):
    """Retrieve access-controlled transfer event log."""
    return list(_USER_EVENTS[str(current_user.id)])


@router.get("/collaboration/security-evaluation")
def get_security_evaluation(current_user: User = Depends(get_current_user)):
    """Execute and return CIA+AA security goals evaluation and performance profiling."""
    return run_full_security_goals_evaluation()
