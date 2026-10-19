"""Unit tests for SSRF prevention, destination verification, and scope validation."""
import pytest
from app.network.scope import (
    LAB_URL, LAB_IP, check_ssrf, resolve_and_verify_destination,
    sanitize_endpoint, validate_lab_target, is_lab_target
)


def test_lab_target_validation():
    assert validate_lab_target(LAB_URL) == LAB_URL
    assert validate_lab_target(LAB_URL + '/') == LAB_URL
    with pytest.raises(PermissionError, match="restricted to the bundled ASE lab"):
        validate_lab_target("http://evil.com")
    with pytest.raises(PermissionError):
        validate_lab_target("http://127.0.0.1:8080")


def test_is_lab_target():
    assert is_lab_target("http://ase-lab:8080") is True
    assert is_lab_target("http://ase-lab:8080/test") is True
    assert is_lab_target("http://example.com") is False
    assert is_lab_target("not-a-url") is False


def test_ssrf_blocks_private_and_metadata():
    # Loopback
    with pytest.raises(PermissionError, match="loopback"):
        check_ssrf("127.0.0.1")
    with pytest.raises(PermissionError, match="loopback"):
        check_ssrf("127.0.0.2")

    # Cloud metadata (AWS/GCP/Azure)
    with pytest.raises(PermissionError, match="link-local/cloud metadata"):
        check_ssrf("169.254.169.254")

    # Private RFC 1918
    with pytest.raises(PermissionError, match="private network"):
        check_ssrf("10.0.0.1")
    with pytest.raises(PermissionError, match="private network"):
        check_ssrf("192.168.1.100")
    with pytest.raises(PermissionError, match="private network"):
        check_ssrf("172.16.5.5")

    # Lab IP allowed only with allow_lab=True
    with pytest.raises(PermissionError):
        check_ssrf(LAB_IP, allow_lab=False)
    # Does not raise when allow_lab=True
    check_ssrf(LAB_IP, allow_lab=True)

    # Public IP allowed
    check_ssrf("93.184.216.34", allow_lab=False)


def test_resolve_and_verify_destination_schemes_and_credentials():
    with pytest.raises(PermissionError, match="Unsupported URL scheme"):
        resolve_and_verify_destination("ftp://example.com", "example.com")
    with pytest.raises(PermissionError, match="Unsupported URL scheme"):
        resolve_and_verify_destination("file:///etc/passwd", "example.com")
    with pytest.raises(PermissionError, match="Unsupported URL scheme"):
        resolve_and_verify_destination("gopher://example.com:70", "example.com")

    # Credentials
    with pytest.raises(PermissionError, match="Credentials in target URLs are forbidden"):
        resolve_and_verify_destination("http://admin:secret@example.com", "example.com")


def test_resolve_and_verify_destination_scope():
    with pytest.raises(PermissionError, match="outside the authorized explicit scope"):
        resolve_and_verify_destination("http://evil.com/path", "example.com")

    # Substring match must not authorize
    with pytest.raises(PermissionError, match="outside the authorized explicit scope"):
        resolve_and_verify_destination("http://notexample.com", "example.com")


def test_sanitize_endpoint():
    # Valid in-scope endpoint
    clean = sanitize_endpoint("http://example.com/api/v1/users?token=secret#frag", "http://example.com", "example.com")
    assert clean == "http://example.com/api/v1/users"

    # Out-of-scope redirection attempt
    with pytest.raises(PermissionError, match="out-of-scope"):
        sanitize_endpoint("http://evil.com/steal", "http://example.com", "example.com")

    # Path traversal / control characters
    with pytest.raises(PermissionError):
        sanitize_endpoint("http://example.com/api/\x00admin", "http://example.com", "example.com")
