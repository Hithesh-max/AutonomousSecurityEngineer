"""Standalone tests for bounded patch verification; no database or external provider needed."""
import hashlib
from pathlib import Path
from types import SimpleNamespace
import unittest

from app.ai.schemas import ModelPatch
from app.remediation.patching import validate_and_render
from app.remediation.source import SourceContext
from app.remediation.verification import isolated_verify

LAB = Path(__file__).resolve().parents[3] / "lab" / "app.py"


class IsolatedVerificationTests(unittest.TestCase):
    def setUp(self):
        self.original = LAB.read_bytes()
        lines = tuple(self.original.decode("utf-8").splitlines())
        self.source = SourceContext("BUNDLED_LAB", "lab/app.py", 31, 41, 37, lines,
                                    hashlib.sha256(self.original).hexdigest(), "VERIFIED", "unit")
        before = lines[36]
        after = before.replace(
            '"SELECT owner, amount FROM invoices WHERE owner = \'" + query.get(\'q\', [\'alice\'])[0] + "\'"',
            '"SELECT owner, amount FROM invoices WHERE owner = ?", (query.get(\'q\', [\'alice\'])[0],)')
        self.assertNotEqual(before, after)
        model = ModelPatch(edits=[{"start_line": 37, "end_line": 37, "original_text": before,
                                   "replacement_text": after}], explanation="Use SQL placeholders.")
        validated = validate_and_render(self.source, model)
        self.proposal = SimpleNamespace(edits=validated.edits, explanation=model.explanation,
                                        behavior_notes="", limitations=[], patch_sha256=validated.patch_sha256,
                                        patched_sha256=validated.patched_sha256)

    def test_applies_in_private_copy_and_preserves_original(self):
        result = isolated_verify(self.source, self.proposal)
        self.assertEqual(result["status"], "INCONCLUSIVE")
        self.assertEqual(result["checks"]["python_syntax"]["status"], "PASS")
        self.assertEqual(result["checks"]["dynamic_rescan"]["status"], "NOT_RUN")
        self.assertEqual(LAB.read_bytes(), self.original)

    def test_tampered_patch_hash_rejected(self):
        self.proposal.patch_sha256 = "0" * 64
        with self.assertRaises(ValueError):
            isolated_verify(self.source, self.proposal)

    def test_tampered_result_hash_rejected(self):
        self.proposal.patched_sha256 = "0" * 64
        with self.assertRaises(ValueError):
            isolated_verify(self.source, self.proposal)


if __name__ == "__main__":
    unittest.main()
