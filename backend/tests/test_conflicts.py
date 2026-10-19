"""Tests for semantic and line-level patch conflict detection."""
from types import SimpleNamespace
from uuid import uuid4
import pytest
from app.remediation.conflicts import detect_conflicts, ConflictType


def test_no_conflicts_on_distinct_files():
    p1 = SimpleNamespace(id=uuid4(), source_path="app.py", edits=[{"start_line": 10, "end_line": 15, "replacement_text": "x = 1"}])
    p2 = SimpleNamespace(id=uuid4(), source_path="utils.py", edits=[{"start_line": 10, "end_line": 15, "replacement_text": "y = 2"}])
    report = detect_conflicts([p1, p2], {})
    assert report["compatible"] is True
    assert report["conflict_count"] == 0


def test_line_overlap_conflict_detected():
    p1 = SimpleNamespace(id=uuid4(), source_path="app.py", edits=[{"start_line": 10, "end_line": 20, "replacement_text": "x = 1"}])
    p2 = SimpleNamespace(id=uuid4(), source_path="app.py", edits=[{"start_line": 15, "end_line": 25, "replacement_text": "x = 2"}])
    report = detect_conflicts([p1, p2], {})
    assert report["compatible"] is False
    assert report["conflict_count"] >= 1
    assert report["conflicts"][0]["type"] == ConflictType.LINE_OVERLAP
    assert report["conflicts"][0]["requires_resolution"] is True


def test_function_conflict_detected():
    source_lines = [
        "import os",
        "def process_data(user_input):",
        "    sanitized = user_input.strip()",
        "    return sanitized",
        "def other():",
        "    pass"
    ]
    source = SimpleNamespace(lines=source_lines)
    p1 = SimpleNamespace(id=uuid4(), source_path="app.py", edits=[{"start_line": 2, "end_line": 3, "replacement_text": "    # fix 1"}])
    p2 = SimpleNamespace(id=uuid4(), source_path="app.py", edits=[{"start_line": 4, "end_line": 4, "replacement_text": "    return secure(sanitized)"}])
    report = detect_conflicts([p1, p2], {"app.py": source})
    # Both modify process_data
    assert any(c["type"] == ConflictType.FUNCTION_CONFLICT for c in report["conflicts"])


def test_dependency_version_conflict_detected():
    p1 = SimpleNamespace(id=uuid4(), source_path="requirements.txt", edits=[{"start_line": 1, "end_line": 1, "replacement_text": "requests>=2.31.0"}])
    p2 = SimpleNamespace(id=uuid4(), source_path="requirements.txt", edits=[{"start_line": 2, "end_line": 2, "replacement_text": "requests==2.25.1"}])
    report = detect_conflicts([p1, p2], {})
    assert any(c["type"] == ConflictType.DEPENDENCY_CONFLICT for c in report["conflicts"])
