"""Remove expired secure-share ciphertext from persistent storage."""
from datetime import datetime, timezone

from app.config.database import SessionLocal
from app.config.settings import settings
from app.models.secure_share import SecureShare
from app.workers.celery_app import celery


@celery.task(name="expire_secure_shares")
def expire_secure_shares():
    db = SessionLocal()
    removed = 0
    try:
        rows = (db.query(SecureShare)
                .filter(SecureShare.expires_at <= datetime.now(timezone.utc))
                .order_by(SecureShare.expires_at)
                .limit(500).all())
        root = settings.SECURE_SHARE_STORAGE_DIR
        for share in rows:
            expected_key = f"{share.id}.enc"
            if share.storage_key == expected_key:
                from pathlib import Path
                (Path(root).expanduser() / expected_key).unlink(missing_ok=True)
            db.delete(share)
            removed += 1
        db.commit()
        return removed
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
