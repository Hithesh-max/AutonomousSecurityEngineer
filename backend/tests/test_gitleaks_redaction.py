from app.utils.redaction import redact_finding_context
import json

def test_gitleaks_normalize_and_redact():
    # Simulate a raw Gitleaks JSON finding
    raw_leak = {
        "Description": "Generic API Key",
        "StartLine": 10,
        "EndLine": 10,
        "StartColumn": 1,
        "EndColumn": 20,
        "Match": "my_bare_secret_value",
        "Secret": "my_bare_secret_value",
        "File": "config.py",
        "Commit": "abc1234",
        "Author": "test",
        "Email": "test@example.com",
        "Message": "Add config",
        "Date": "2023-01-01T00:00:00Z",
        "Tags": [],
        "RuleID": "generic-api-key",
        "Fingerprint": "fingerprint123"
    }
    
    # Simulate the normalization that GitleaksScanner does
    finding = {
        "title": raw_leak.get("Description", "Secret detected"),
        "description": f"Gitleaks detected a hardcoded secret in {raw_leak.get('File')}.",
        "severity": "CRITICAL",
        "source_location": {
            "file": raw_leak.get("File"),
            "start_line": raw_leak.get("StartLine"),
            "end_line": raw_leak.get("EndLine")
        },
        "evidence": {
            "match": raw_leak.get("Match"),
            "secret": raw_leak.get("Secret"),
            "commit": raw_leak.get("Commit"),
            "rule": raw_leak.get("RuleID")
        }
    }
    
    # Redact
    redacted = redact_finding_context(finding)
    
    # Check that bare secrets are removed
    assert redacted["evidence"]["match"] == "[REDACTED]"
    assert redacted["evidence"]["secret"] == "[REDACTED]"
    
    # Check that non-secret metadata is preserved
    assert redacted["evidence"]["rule"] == "generic-api-key"
    assert redacted["evidence"]["commit"] == "abc1234"
    assert redacted["source_location"]["file"] == "config.py"
    
def test_nested_list_redaction():
    finding = {
        "title": "Test",
        "evidence": {
            "tokens": ["DUMMY_A", "DUMMY_B"],
            "keys": {"secret_key": "DUMMY_C"}
        }
    }
    
    redacted = redact_finding_context(finding)
    
    assert redacted["evidence"]["tokens"] == ["[REDACTED]", "[REDACTED]"]
    assert redacted["evidence"]["keys"]["secret_key"] == "[REDACTED]"
    
    # Check serialized output
    serialized = json.dumps(redacted)
    assert "DUMMY_A" not in serialized
    assert "DUMMY_B" not in serialized
    assert "DUMMY_C" not in serialized
