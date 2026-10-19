from uuid import UUID
from datetime import datetime, timedelta, timezone

from app.config.settings import settings
from app.models.secure_share import SecureShare


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _encrypted_test_payload():
    # Shape only: 12-byte IV followed by authenticated ciphertext/tag.
    return bytes(range(12)) + b"x" * 20


def _reader_token():
    import base64
    return base64.urlsafe_b64encode(b"t" * 32).decode().rstrip("=")


def test_secure_share_upload_is_authenticated_and_download_is_ciphertext_only(
    client, test_db, test_user_token, tmp_path, monkeypatch
):
    monkeypatch.setattr(settings, "SECURE_SHARE_STORAGE_DIR", str(tmp_path))
    monkeypatch.setattr(settings, "SECURE_SHARE_MAX_DOWNLOADS", 1)
    payload = _encrypted_test_payload()
    unauthenticated = client.post("/api/secure-shares", content=payload,
                                  headers={"Content-Type": "application/octet-stream", "X-Share-Token": _reader_token()})
    assert unauthenticated.status_code == 401

    created = client.post("/api/secure-shares", content=payload,
                          headers={**_auth(test_user_token), "Content-Type": "application/octet-stream", "X-Share-Token": _reader_token()})
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["max_downloads"] == 1
    assert body["encryption"].startswith("AES-256-GCM client-side")
    assert "key" not in created.text.lower()

    assert client.get(f"/api/secure-shares/{body['id']}/ciphertext").status_code == 404
    bad_token = "A" + _reader_token()[1:]
    assert client.get(f"/api/secure-shares/{body['id']}/ciphertext", headers={"X-Share-Token": bad_token}).status_code == 404
    downloaded = client.get(f"/api/secure-shares/{body['id']}/ciphertext", headers={"X-Share-Token": _reader_token()})
    assert downloaded.status_code == 200
    assert downloaded.content == payload
    assert downloaded.headers["cache-control"] == "no-store"
    assert client.get(f"/api/secure-shares/{body['id']}/ciphertext", headers={"X-Share-Token": _reader_token()}).status_code == 404


def test_secure_share_enforces_content_type_size_and_owner_revoke(
    client, test_db, test_user_token, test_user_2_token, tmp_path, monkeypatch
):
    monkeypatch.setattr(settings, "SECURE_SHARE_STORAGE_DIR", str(tmp_path))
    wrong_type = client.post("/api/secure-shares", content=b"x" * 40,
                             headers={**_auth(test_user_token), "Content-Type": "application/json"})
    assert wrong_type.status_code == 415
    monkeypatch.setattr(settings, "SECURE_SHARE_MAX_BYTES", 31)
    too_large = client.post("/api/secure-shares", content=_encrypted_test_payload(),
                            headers={**_auth(test_user_token), "Content-Type": "application/octet-stream", "X-Share-Token": _reader_token()})
    assert too_large.status_code == 413

    monkeypatch.setattr(settings, "SECURE_SHARE_MAX_BYTES", 50 * 1024 * 1024)
    created = client.post("/api/secure-shares", content=_encrypted_test_payload(),
                          headers={**_auth(test_user_token), "Content-Type": "application/octet-stream", "X-Share-Token": _reader_token()})
    share_id = created.json()["id"]
    forbidden = client.delete(f"/api/secure-shares/{share_id}", headers=_auth(test_user_2_token))
    assert forbidden.status_code == 404
    revoked = client.delete(f"/api/secure-shares/{share_id}", headers=_auth(test_user_token))
    assert revoked.status_code == 204
    assert client.get(f"/api/secure-shares/{share_id}/ciphertext", headers={"X-Share-Token": _reader_token()}).status_code == 404
    assert test_db.query(SecureShare).filter_by(id=UUID(share_id)).count() == 0


def test_expired_share_is_rejected_and_ciphertext_removed(
    client, test_db, test_user_token, tmp_path, monkeypatch
):
    monkeypatch.setattr(settings, "SECURE_SHARE_STORAGE_DIR", str(tmp_path))
    created = client.post("/api/secure-shares", content=_encrypted_test_payload(),
                          headers={**_auth(test_user_token), "Content-Type": "application/octet-stream", "X-Share-Token": _reader_token()})
    share_id = UUID(created.json()["id"])
    share = test_db.get(SecureShare, share_id)
    stored_path = tmp_path / share.storage_key
    assert stored_path.is_file()
    share.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    test_db.commit()

    expired = client.get(f"/api/secure-shares/{share_id}/ciphertext", headers={"X-Share-Token": _reader_token()})
    assert expired.status_code == 404
    assert not stored_path.exists()
    test_db.expire_all()
    assert test_db.get(SecureShare, share_id) is None

