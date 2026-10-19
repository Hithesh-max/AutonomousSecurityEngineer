from sqlalchemy import CheckConstraint, Column, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.dialects.postgresql import UUID

from app.models.base import Base


class SecureShare(Base):
    """Metadata for opaque ciphertext; decryption keys and plaintext are never stored here."""
    __tablename__ = "secure_shares"
    __table_args__ = (
        CheckConstraint("download_count >= 0", name="ck_secure_shares_download_count"),
        CheckConstraint("max_downloads BETWEEN 1 AND 100", name="ck_secure_shares_max_downloads"),
        Index("ix_secure_shares_expires_at", "expires_at"),
    )

    owner_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    storage_key = Column(String(80), nullable=False, unique=True)
    reader_token_sha256 = Column(String(64), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    download_count = Column(Integer, nullable=False, default=0, server_default="0")
    max_downloads = Column(Integer, nullable=False)
