"""Expiring share links for browser-encrypted corrected-project files."""
import os
import tempfile
import base64
import hashlib
import hmac
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import FileResponse
from sqlalchemy import update
from sqlalchemy.orm import Session

from app.api.auth import get_current_user
from app.config.database import get_db
from app.config.settings import settings
from app.models.secure_share import SecureShare
from app.models.user import User

router = APIRouter()
IV_BYTES = 12
GCM_TAG_BYTES = 16
PACKED_FILENAME_LENGTH_BYTES = 4
SHARE_TOKEN_HEADER = "X-Share-Token"


def _storage_dir() -> Path:
    path = Path(settings.SECURE_SHARE_STORAGE_DIR).expanduser()
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        path.chmod(0o700)
    except OSError:
        pass
    return path


def _stored_path(share: SecureShare) -> Path:
    # Never trust a path supplied by the request or stored metadata.
    if share.storage_key != f"{share.id}.enc":
        raise HTTPException(500, detail="Secure share storage metadata is invalid.")
    return _storage_dir() / share.storage_key


def _remove_share(db: Session, share: SecureShare) -> None:
    path = _stored_path(share)
    path.unlink(missing_ok=True)
    db.delete(share)
    db.commit()


def _reader_token_digest(token: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
        raise HTTPException(404, detail="Secure share not found or expired.")
    try:
        decoded = base64.urlsafe_b64decode(token + "=")
    except (ValueError, TypeError):
        raise HTTPException(404, detail="Secure share not found or expired.") from None
    if len(decoded) != 32:
        raise HTTPException(404, detail="Secure share not found or expired.")
    return hashlib.sha256(decoded).hexdigest()


@router.post("/secure-shares", status_code=201)
async def create_secure_share(
    request: Request,
    reader_token: str = Header(..., alias=SHARE_TOKEN_HEADER),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Accept only ciphertext from the client; never accept a decryption key."""
    if request.headers.get("content-type", "").split(";", 1)[0].lower() != "application/octet-stream":
        raise HTTPException(415, detail="Encrypted share upload must use application/octet-stream.")
    declared = request.headers.get("content-length")
    if declared:
        try:
            if int(declared) > settings.SECURE_SHARE_MAX_BYTES:
                raise HTTPException(413, detail="Encrypted file exceeds the secure-share size limit.")
        except ValueError:
            raise HTTPException(400, detail="Invalid Content-Length.") from None

    reader_token_sha256 = _reader_token_digest(reader_token)
    root = _storage_dir()
    fd, temporary_name = tempfile.mkstemp(prefix=".upload-", dir=root)
    temp_path = Path(temporary_name)
    final_path: Path | None = None
    try:
        size = 0
        with os.fdopen(fd, "wb") as output:
            async for chunk in request.stream():
                size += len(chunk)
                if size > settings.SECURE_SHARE_MAX_BYTES:
                    raise HTTPException(413, detail="Encrypted file exceeds the secure-share size limit.")
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        # Format is a 12-byte AES-GCM IV, encrypted package header/data and 16-byte tag.
        if size < IV_BYTES + PACKED_FILENAME_LENGTH_BYTES + GCM_TAG_BYTES:
            raise HTTPException(422, detail="Encrypted file is incomplete.")

        share_id = uuid4()
        storage_key = f"{share_id}.enc"
        final_path = root / storage_key
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, final_path)
        now = datetime.now(timezone.utc)
        share = SecureShare(
            id=share_id,
            owner_id=current_user.id,
            storage_key=storage_key,
            reader_token_sha256=reader_token_sha256,
            expires_at=now + timedelta(hours=settings.SECURE_SHARE_RETENTION_HOURS),
            download_count=0,
            max_downloads=settings.SECURE_SHARE_MAX_DOWNLOADS,
        )
        db.add(share)
        db.commit()
        return {
            "id": str(share.id),
            "expires_at": share.expires_at,
            "max_downloads": share.max_downloads,
            "encryption": "AES-256-GCM client-side; server stores ciphertext only",
        }
    except Exception:
        db.rollback()
        temp_path.unlink(missing_ok=True)
        if final_path is not None:
            final_path.unlink(missing_ok=True)
        raise


@router.get("/secure-shares/{share_id}/ciphertext")
def download_secure_share_ciphertext(
    share_id: UUID,
    reader_token: str | None = Header(None, alias=SHARE_TOKEN_HEADER),
    db: Session = Depends(get_db),
):
    """Public capability endpoint. It returns ciphertext and never sees the URL-fragment key."""
    share = db.query(SecureShare).filter(SecureShare.id == share_id).first()
    if share is None:
        raise HTTPException(404, detail="Secure share not found or expired.")
    supplied_digest = _reader_token_digest(reader_token or "")
    if not hmac.compare_digest(supplied_digest, share.reader_token_sha256):
        raise HTTPException(404, detail="Secure share not found or expired.")
    now = datetime.now(timezone.utc)
    expiry = share.expires_at
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    if expiry <= now or share.download_count >= share.max_downloads:
        if expiry <= now:
            _remove_share(db, share)
        raise HTTPException(404, detail="Secure share not found or expired.")
    path = _stored_path(share)
    if not path.is_file():
        _remove_share(db, share)
        raise HTTPException(404, detail="Secure share not found or expired.")

    # Conditional SQL update prevents concurrent downloads from exceeding the cap.
    claimed = db.execute(
        update(SecureShare)
        .where(
            SecureShare.id == share_id,
            SecureShare.expires_at > now,
            SecureShare.download_count < SecureShare.max_downloads,
        )
        .values(download_count=SecureShare.download_count + 1)
        .returning(SecureShare.id)
    ).scalar_one_or_none()
    db.commit()
    if claimed is None:
        raise HTTPException(404, detail="Secure share not found or expired.")
    return FileResponse(
        path,
        media_type="application/octet-stream",
        filename="ase-secure-share.enc",
        headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"},
    )


@router.delete("/secure-shares/{share_id}", status_code=204)
def revoke_secure_share(
    share_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    share = db.query(SecureShare).filter(
        SecureShare.id == share_id,
        SecureShare.owner_id == current_user.id,
    ).first()
    if share is None:
        raise HTTPException(404, detail="Secure share not found.")
    _remove_share(db, share)
    return None
