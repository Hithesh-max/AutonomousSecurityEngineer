import pytest
import os
from app.utils.validators import validate_scope_syntax, is_url_in_scope

def test_scope_syntax_validation():
    # Valid scopes
    assert validate_scope_syntax("example.com") == "example.com"
    assert validate_scope_syntax("*.example.com") == "*.example.com"
    
    # Invalid scopes
    with pytest.raises(ValueError, match="Scope cannot be empty"):
        validate_scope_syntax("")
        
    with pytest.raises(ValueError, match="Scope cannot be a global wildcard"):
        validate_scope_syntax("*")
        
    with pytest.raises(ValueError, match="Scope cannot contain spaces"):
        validate_scope_syntax("example .com")
        
    with pytest.raises(ValueError, match="Scope must be a hostname"):
        validate_scope_syntax("example.com/api")
        
    with pytest.raises(ValueError, match="Scope must be a hostname"):
        validate_scope_syntax("http://example.com")
        
    with pytest.raises(ValueError, match="Malformed hostname label"):
        validate_scope_syntax("-example.com")
        
    with pytest.raises(ValueError, match="Malformed hostname label"):
        validate_scope_syntax("example-.com")
        
    with pytest.raises(ValueError, match="Hostname contains empty labels"):
        validate_scope_syntax("example..com")
        
def test_url_in_scope():
    # Exact match
    assert is_url_in_scope("http://example.com", "example.com") is True
    assert is_url_in_scope("https://example.com/path", "example.com") is True
    
    # Substring mismatch (anotherexample.com is NOT in example.com)
    assert is_url_in_scope("http://anotherexample.com", "example.com") is False
    assert is_url_in_scope("http://myexample.com", "example.com") is False
    
    # Wildcard matches
    assert is_url_in_scope("https://api.example.com", "*.example.com") is True
    assert is_url_in_scope("http://example.com", "*.example.com") is True
    assert is_url_in_scope("https://sub.api.example.com", "*.example.com") is True
    
    # Wildcard mismatch
    assert is_url_in_scope("https://example.org", "*.example.com") is False
    assert is_url_in_scope("https://anotherexample.com", "*.example.com") is False

def test_missing_jwt_secret():
    # Setting an environment variable manually to test startup failure
    # Pydantic will raise ValidationError if we try to instantiate Settings without it or if it's too short
    from app.config.settings import Settings
    from pydantic import ValidationError
    
    old_env = os.environ.get("JWT_SECRET")
    if "JWT_SECRET" in os.environ:
        del os.environ["JWT_SECRET"]
        
    with pytest.raises(ValidationError):
        Settings()
        
    # Test weak secret
    os.environ["JWT_SECRET"] = "too_short"
    with pytest.raises(ValidationError):
        Settings()
        
    if old_env:
        os.environ["JWT_SECRET"] = old_env

def test_disabled_legacy_admin(client, test_db):
    from app.models.user import User
    from app.core import security
    
    # Insert or update a legacy_admin user
    u = test_db.query(User).filter(User.username == "legacy_admin").first()
    if not u:
        u = User(username="legacy_admin", hashed_password="!disabled", is_active=False)
        test_db.add(u)
    else:
        u.is_active = False
        u.hashed_password = "!disabled"
    test_db.commit()
    
    # Try to login
    res = client.post("/api/auth/token", data={"username": "legacy_admin", "password": "legacy_password"})
    assert res.status_code == 401
    
    # Try with a generated token (which simulates a previously issued token)
    token = security.create_access_token(data={"sub": "legacy_admin", "t_ver": u.token_version})
    res2 = client.get("/api/projects", headers={"Authorization": f"Bearer {token}"})
    assert res2.status_code == 403
    assert "Inactive user account" in res2.json()["detail"]

def test_secret_redaction():
    from app.utils.redaction import redact_finding_context
    
    # Mock finding with nested evidence and bare gitleaks secret
    finding = {
        "title": "Hardcoded Secret",
        "description": "Found password = 'super_secret_123' in code.",
        "evidence": {
            "match": "API_KEY='12345'",
            "nested": {
                "secret": "my_bare_secret_value",
                "token_value": "tok_123",
                "other_data": "safe_value"
            },
            "array_data": [
                {"password": "nested_password_123"}
            ]
        },
        "source_location": "db_config.py"
    }
    
    redacted = redact_finding_context(finding)
    
    # Check string replacement in description
    assert "password = [REDACTED]" in redacted["description"]
    assert "super_secret_123" not in redacted["description"]
    
    # Check regex replacement in evidence match string
    assert redacted["evidence"]["match"] == "[REDACTED]"
    
    # Check bare key redaction in nested objects
    assert redacted["evidence"]["nested"]["secret"] == "[REDACTED]"
    assert "my_bare_secret_value" not in redacted["evidence"]["nested"].values()
    
    assert redacted["evidence"]["array_data"][0]["password"] == "[REDACTED]"
    assert redacted["evidence"]["nested"]["other_data"] == "safe_value"

def test_token_version_revocation(client, test_db):
    from app.models.user import User
    from app.core import security
    
    # Create user
    u = test_db.query(User).filter(User.username == "version_test").first()
    if not u:
        u = User(username="version_test", hashed_password="pw", token_version=1)
        test_db.add(u)
        test_db.commit()
    
    # Generate token for version 1
    token_v1 = security.create_access_token(data={"sub": "version_test", "t_ver": 1})
    
    # Valid token works
    res_valid = client.get("/api/projects", headers={"Authorization": f"Bearer {token_v1}"})
    assert res_valid.status_code == 200
    
    # Increment version (simulating password reset)
    u.token_version = 2
    test_db.commit()
    
    # Old token fails
    res_invalid = client.get("/api/projects", headers={"Authorization": f"Bearer {token_v1}"})
    assert res_invalid.status_code == 401
    assert "Could not validate credentials" in res_invalid.json()["detail"]
