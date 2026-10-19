"""Remediation *guidance* keyed by scanner rule. These are hints for the model, never prebuilt patches."""

# ZAP rule id -> strategy family. Mirrors the rules for which verified bundled-lab source mappings exist.
RULE_FAMILY = {
    "ase.python.request-to-sql": "sqli", "ase.python.input-to-eval": "evaluation",
    "ase.python.shell-enabled": "command", "ase.javascript.eval": "evaluation",
    "40012": "xss", "40018": "sqli",
    "10038": "headers", "10020": "headers", "10021": "headers",
    "10010": "cookie", "10054": "cookie", "10036": "server_disclosure",
}

GUIDANCE = {
    "evaluation": "Establish the intended input language. JSON.parse or ast.literal_eval only preserves behavior for data literals; do not replace arithmetic evaluation with a literal parser and claim unchanged functionality. Use a bounded parser appropriate to intended operations; otherwise state that manual design is required.",
    "command": "Never pass request-selected command names to an execution API. Use an explicitly permitted fixed executable and argument array, shell=False, and a bounded timeout. ASE only accepts new subprocess.run calls for ping, printf, echo, whoami or hostname. If the application is an arbitrary command runner, a safe behavior-preserving automatic fix may not exist: explain the authorization and design changes required.",
    "sqli": "Replace string-concatenated SQL with a parameterized query (placeholders plus bound parameters). "
            "Keep query semantics and the response format unchanged.",
    "xss": "Apply HTML-body-context output encoding to the reflected value (for example html.escape from the "
           "standard library). Do not strip legitimate input or change the route.",
    "headers": "Add the missing response headers in the code that writes response headers. Do not change the "
               "response body, status code, or routing. The snippet is a response-generation block, not a single "
               "defective statement.",
    "cookie": "Add HttpOnly and SameSite attributes to the Set-Cookie value. Do not add Secure unless the "
              "application is served over HTTPS; the bundled lab is plain HTTP, so state that limitation.",
    "server_disclosure": "Reduce version detail in the advertised server string without breaking HTTP behavior.",
}

CWE_HINT = {"xss": "CWE-79", "sqli": "CWE-89", "headers": "CWE-693", "cookie": "CWE-1004",
            "server_disclosure": "CWE-200"}


def family_for(rule_id) -> str | None:
    value = str(rule_id)
    return RULE_FAMILY.get(value) or next((family for rule, family in RULE_FAMILY.items() if value.endswith("." + rule)), None)
