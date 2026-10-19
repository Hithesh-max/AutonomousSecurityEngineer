"""Labeled benchmark dataset with ground truth for precision, recall, and F1 evaluation."""
from typing import Any

# Curated benchmark covering vulnerable and benign/remediated examples
LABELED_BENCHMARK_SAMPLES = [
    {
        "id": "BENCH-001",
        "title": "Raw SQL concatenation in query",
        "cwe": "CWE-89",
        "category": "INJECTION",
        "ground_truth": "VULNERABLE",
        "language": "Python",
        "code": "cursor.execute('SELECT * FROM users WHERE id = ' + user_id)",
        "expected_detection": True,
        "primary_rule": "ase.python.request-to-sql"
    },
    {
        "id": "BENCH-002",
        "title": "Parameterized SQL query",
        "cwe": "CWE-89",
        "category": "INJECTION",
        "ground_truth": "BENIGN",
        "language": "Python",
        "code": "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
        "expected_detection": False,
        "primary_rule": "ase.python.request-to-sql"
    },
    {
        "id": "BENCH-003",
        "title": "Direct shell execution with os.system",
        "cwe": "CWE-78",
        "category": "COMMAND_INJECTION",
        "ground_truth": "VULNERABLE",
        "language": "Python",
        "code": "os.system('ping -c 1 ' + host)",
        "expected_detection": True,
        "primary_rule": "ase.python.shell-enabled"
    },
    {
        "id": "BENCH-004",
        "title": "Safe subprocess with argv list and shell=False",
        "cwe": "CWE-78",
        "category": "COMMAND_INJECTION",
        "ground_truth": "BENIGN",
        "language": "Python",
        "code": "subprocess.run(['ping', '-c', '1', host], shell=False, check=True)",
        "expected_detection": False,
        "primary_rule": "ase.python.shell-enabled"
    },
    {
        "id": "BENCH-005",
        "title": "Dynamic eval on user supplied string",
        "cwe": "CWE-94",
        "category": "CODE_EVAL",
        "ground_truth": "VULNERABLE",
        "language": "Python",
        "code": "result = eval(user_expression)",
        "expected_detection": True,
        "primary_rule": "ase.python.input-to-eval"
    },
    {
        "id": "BENCH-006",
        "title": "Safe ast.literal_eval on constant expression",
        "cwe": "CWE-94",
        "category": "CODE_EVAL",
        "ground_truth": "BENIGN",
        "language": "Python",
        "code": "result = ast.literal_eval(user_expression)",
        "expected_detection": False,
        "primary_rule": "ase.python.input-to-eval"
    },
    {
        "id": "BENCH-007",
        "title": "Hardcoded production API secret key",
        "cwe": "CWE-798",
        "category": "SECRETS",
        "ground_truth": "VULNERABLE",
        "language": "Text",
        "code": "aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'",
        "expected_detection": True,
        "primary_rule": "gitleaks.generic-api-key"
    },
    {
        "id": "BENCH-008",
        "title": "Secret loaded securely from environment variable",
        "cwe": "CWE-798",
        "category": "SECRETS",
        "ground_truth": "BENIGN",
        "language": "Python",
        "code": "secret_key = os.environ.get('SECRET_KEY')",
        "expected_detection": False,
        "primary_rule": "gitleaks.generic-api-key"
    },
    {
        "id": "BENCH-009",
        "title": "Weak MD5 hashing for passwords",
        "cwe": "CWE-327",
        "category": "CRYPTO",
        "ground_truth": "VULNERABLE",
        "language": "Python",
        "code": "password_hash = hashlib.md5(password.encode()).hexdigest()",
        "expected_detection": True,
        "primary_rule": "ase.python.weak-crypto-md5"
    },
    {
        "id": "BENCH-010",
        "title": "Strong bcrypt password hashing with salt",
        "cwe": "CWE-327",
        "category": "CRYPTO",
        "ground_truth": "BENIGN",
        "language": "Python",
        "code": "password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())",
        "expected_detection": False,
        "primary_rule": "ase.python.weak-crypto-md5"
    }
]


def get_labeled_samples() -> list[dict[str, Any]]:
    """Return complete labeled benchmark suite with ground truth."""
    return LABELED_BENCHMARK_SAMPLES
