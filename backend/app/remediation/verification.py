"""Bounded, non-executing verification of an approved bundled-lab patch.

This deliberately does NOT run arbitrary model-generated Python or claim DAST verification.
"""
from __future__ import annotations

import ast
import hashlib
import tempfile
from pathlib import Path

from app.ai.schemas import ModelPatch
from app.remediation.patching import validate_and_render


def isolated_verify(source, proposal):
    """Re-validate, materialize in a private temp dir, parse and inspect; original untouched."""
    edits = proposal.edits
    patch = ModelPatch.model_validate({
        "edits": edits,
        "explanation": proposal.explanation,
        "behavior_notes": proposal.behavior_notes or "",
        "limitations": proposal.limitations or [],
    })
    rendered = validate_and_render(source, patch)
    if rendered.patch_sha256 != proposal.patch_sha256 or rendered.patched_sha256 != proposal.patched_sha256:
        raise ValueError("Approved patch differs from stored validated proposal")
    lines = list(source.lines)
    for edit in reversed(sorted(edits, key=lambda e: e["start_line"])):
        replacement = edit["replacement_text"].replace("\r\n", "\n").replace("\r", "\n").split("\n")
        if replacement == [""]:
            replacement = []
        lines[edit["start_line"] - 1:edit["end_line"]] = replacement
    result = ("\n".join(lines) + "\n").encode("utf-8")
    if hashlib.sha256(result).hexdigest() != proposal.patched_sha256:
        raise ValueError("Patched file hash mismatch")
    with tempfile.TemporaryDirectory(prefix="ase-remediation-") as directory:
        destination = Path(directory) / Path(source.path).name
        destination.write_bytes(result)
        from app.remediation.languages import syntax_check
        syntax = syntax_check(source.path, destination.read_text(encoding="utf-8"))
        if syntax["status"] != "PASS": raise ValueError("Isolated source did not pass language validation")
        # We intentionally do not execute model-generated code without a real sandbox.
        checks = {
            "approved_patch_integrity": {"status": "PASS", "detail": "Stored patch and resulting hashes match."},
            "isolated_copy": {"status": "PASS", "detail": "Patched source written to a private temporary directory, then removed."},
            "syntax": syntax,
            "python_syntax": syntax if syntax["language"] == "Python" else {"status": "NOT_APPLICABLE"},
            "functional_tests": {"status": "NOT_RUN", "detail": "Executing untrusted patched code requires a dedicated sandbox."},
            "dynamic_rescan": {"status": "NOT_RUN", "detail": "Patched lab has not been launched or scanned."},
        }
    return {"status": "INCONCLUSIVE", "checks": checks,
            "patched_sha256": proposal.patched_sha256,
            "message": "Patch applied and syntax-checked in an isolated temporary copy. Security fix not yet verified."}
