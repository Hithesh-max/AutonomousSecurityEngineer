import re
from typing import Dict, Any

SECRET_REGEX = re.compile(r'(?i)(password|secret|key|token|api_key|credential)[\'"\s]*[:=][\'"\s]*([^\'"\s]+)')
SENSITIVE_KEY_REGEX = re.compile(r'(?i)(password|secret|key|token|api_key|credential|match)')

def redact_string(text: str) -> str:
    if not isinstance(text, str):
        return text
    text = re.sub(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+", r"\1 [REDACTED]", text)
    return SECRET_REGEX.sub(r'\1 = [REDACTED]', text)

def redact_evidence(evidence: Any, key_name: str = "") -> Any:
    # If the key itself indicates a secret (like Gitleaks 'secret' field or any password key)
    if key_name and SENSITIVE_KEY_REGEX.search(key_name):
        if isinstance(evidence, str) and evidence:
            return "[REDACTED]"
        elif isinstance(evidence, list):
            return ["[REDACTED]" if isinstance(i, str) else redact_evidence(i, key_name) for i in evidence]
        
    if isinstance(evidence, dict):
        return {k: redact_evidence(v, k) for k, v in evidence.items()}
    elif isinstance(evidence, list):
        # Pass the current key_name down to list items so tokens: ["a", "b"] gets redacted
        return [redact_evidence(i, key_name) for i in evidence]
    elif isinstance(evidence, str):
        return redact_string(evidence)
    return evidence

def redact_finding_context(finding_data: Dict[str, Any]) -> Dict[str, Any]:
    redacted = dict(finding_data)
    # Recursively redact all fields that might have secrets
    for field in ["evidence", "source_location", "description"]:
        if field in redacted and redacted[field]:
            redacted[field] = redact_evidence(redacted[field], field)
    return redacted
