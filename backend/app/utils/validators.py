import re
from urllib.parse import urlparse

def validate_scope_syntax(scope: str) -> str:
    """
    Validates that a scope is a valid hostname or wildcard hostname.
    Wildcard semantics:
      - A scope can optionally start with '*.' (e.g., '*.example.com').
      - '*.example.com' matches 'example.com', 'api.example.com', 'foo.api.example.com'.
      - Global wildcards ('*') are rejected.
    Rejects spaces, paths, schemes, and malformed hostname labels (e.g., labels starting/ending with hyphen).
    """
    if not scope:
        raise ValueError("Scope cannot be empty.")
    scope = scope.strip().lower()
    if scope == "*":
        raise ValueError("Scope cannot be a global wildcard (*).")
    if " " in scope:
        raise ValueError("Scope cannot contain spaces.")
    if "/" in scope or "://" in scope:
        raise ValueError("Scope must be a hostname, not a path or URI with a scheme.")
    
    # Extract the base domain part if there's a wildcard
    base_scope = scope[2:] if scope.startswith("*.") else scope
    
    if not base_scope:
        raise ValueError("Scope cannot be just '*.'")
        
    labels = base_scope.split(".")
    for label in labels:
        if not label:
            raise ValueError("Hostname contains empty labels (e.g., double dots).")
        if not re.match(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", label):
            raise ValueError(f"Malformed hostname label '{label}'. Labels must contain only alphanumeric characters or hyphens, and cannot start or end with a hyphen.")
            
    return scope

def is_url_in_scope(url: str, scope: str) -> bool:
    """
    Validates if a given URL falls exactly within the specified scope.
    Substrings (e.g. 'anotherexample.com' vs 'example.com') are rejected.
    Supported URL schemes are only http and https.
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme and parsed.scheme.lower() not in ["http", "https"]:
            return False
            
        hostname = parsed.hostname
        if not hostname:
            # Fallback for simple 'example.com' inputs (though targets should be full URLs)
            if "://" not in url:
                hostname = url.split('/')[0]
            else:
                return False
                
        hostname = hostname.lower()
        scope = scope.strip().lower()
        
        if scope.startswith("*."):
            base_scope = scope[2:]
            return hostname == base_scope or hostname.endswith("." + base_scope)
        else:
            return hostname == scope
    except Exception:
        return False
