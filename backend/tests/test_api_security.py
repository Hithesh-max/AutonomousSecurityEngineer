"""Tests for OpenAPI parsing, BOLA/BFLA authorization testing, and credential redaction."""
import json
import pytest

from app.api_testing.openapi_parser import parse_openapi_spec
from app.api_testing.authorization_checker import redact_auth_header, run_authorization_tests


SAMPLE_OPENAPI = """
openapi: 3.0.0
info:
  title: Test API
  version: 1.0.0
paths:
  /api/users/{id}:
    get:
      security:
        - BearerAuth: []
      summary: Get user profile
      parameters:
        - name: id
          in: path
          required: true
      responses:
        '200':
          description: OK
  /api/admin/users:
    get:
      security:
        - BearerAuth: []
      summary: List users
      tags:
        - admin
      responses:
        '204':
          description: Deleted
  /api/public/status:
    get:
      summary: Health status
      responses:
        '200':
          description: OK
"""


def test_openapi_parser():
    inventory = parse_openapi_spec(SAMPLE_OPENAPI)
    assert inventory["title"] == "Test API"
    assert inventory["total_endpoints"] == 3
    assert inventory["bola_candidates"] == 1  # /api/users/{id}
    assert inventory["bfla_candidates"] == 1  # /api/admin/users

    bola_ep = next(e for e in inventory["endpoints"] if e["path"] == "/api/users/{id}")
    assert bola_ep["bola_candidate"] is True
    assert bola_ep["has_object_id"] is True

    bfla_ep = next(e for e in inventory["endpoints"] if e["path"] == "/api/admin/users")
    assert bfla_ep["bfla_candidate"] is True
    assert bfla_ep["is_admin_endpoint"] is True


def test_redact_auth_header():
    assert redact_auth_header("Bearer secret_jwt_token_12345") == "Bearer [REDACTED_TOKEN]"
    assert redact_auth_header("Basic YWRtaW46cGFzc3dvcmQ=") == "Basic [REDACTED_CREDENTIALS]"
    assert redact_auth_header("CustomKey12345") == "[REDACTED]"
    assert redact_auth_header("") == ""


def test_authorization_tests_redaction_and_ssrf(monkeypatch):
    # Mock destination check to allow example.com
    monkeypatch.setattr("app.api_testing.authorization_checker.resolve_and_verify_destination", lambda u, s: "93.184.216.34")

    # Mock probe to return 403 on admin, and 200 on object access (simulating BOLA)
    def mock_probe(url, method, headers, timeout_seconds=5, **kwargs):
        if "/api/users/" in url:
            return {"status_code": 200, "error": None, "headers": headers, "body_sample": '{"id": "user-a"}'}
        return {"status_code": 200 if headers.get("Authorization") == "Bearer token-admin" else 403, "error": None, "headers": headers, "body_sample": ""}

    monkeypatch.setattr("app.api_testing.authorization_checker.execute_auth_probe", mock_probe)

    inventory = parse_openapi_spec(SAMPLE_OPENAPI)
    synthetic_users = {
        "USER_A": {"token": "token-a", "resource_id": "existing-user-a"},
        "USER_B": {"token": "token-b"},
        "ADMIN": {"token": "token-admin"}
    }

    report = run_authorization_tests("http://example.com", inventory["endpoints"], synthetic_users, "example.com")
    assert report["tested_endpoints_count"] == 2
    assert report["vulnerable_count"] == 1  # BOLA flagged
    assert report["secure_count"] == 1      # BFLA secured (got 403)

    bola_result = next(r for r in report["results"] if r["test_type"] == "BOLA")
    assert bola_result["status"] == "ACCESS_GRANTED_REVIEW_REQUIRED"
    assert "human confirmation" in " ".join(report["limitations"])
