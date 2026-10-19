import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch
from app.scanners.controlled import run_process, ToolFailure, finding_path
from app.scanners.semgrep import SemgrepScanner
from app.scanners.gitleaks import GitleaksScanner
from app.repositories.intelligence import inspect_repository
from app.repositories.analysis import prepare_findings


class ToolTests(unittest.TestCase):
    def test_missing_binaries_fail_without_simulation(self):
        with patch('app.scanners.controlled.shutil.which', return_value=None):
            for scanner in [SemgrepScanner(), GitleaksScanner()]:
                with self.assertRaises(FileNotFoundError): scanner.scan('/not-real')
    def test_timeout_output_limit_and_shell_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(ToolFailure): run_process([sys.executable, '-c', 'import time; time.sleep(10)'], cwd=root, seconds=.1)
            with patch('app.scanners.controlled.MAX_OUTPUT', 100):
                with self.assertRaises(ToolFailure): run_process([sys.executable, '-c', 'print("x"*1000)'], cwd=root)
            with self.assertRaises(ToolFailure): run_process(['python', '-c', 'print(1)'], cwd=root)
    def test_environment_contains_no_application_secrets(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'JWT_SECRET': 'dummy', 'DATABASE_URL': 'dummy', 'AI_API_KEY': 'dummy'}):
            result = run_process([sys.executable, '-c', 'import os,json; print(json.dumps(dict(os.environ)))'], cwd=Path(directory))
            child = json.loads(result.stdout)
            self.assertNotIn('JWT_SECRET', child)
            self.assertNotIn('DATABASE_URL', child)
            self.assertNotIn('AI_API_KEY', child)
    def test_malformed_output_and_path_escape(self):
        for scanner in [SemgrepScanner(), GitleaksScanner()]:
            with self.assertRaises(ToolFailure): scanner.parse(b'{broken')
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ToolFailure): finding_path('/etc/passwd', Path(directory))
    def test_actual_normalizer_never_persists_secret_or_match(self):
        scanner = GitleaksScanner()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'config.txt').write_text('example')
            files = inspect_repository(root).files
            # Parser fixture only; this is not an executed scan or a UI finding.
            raw = scanner.parse(json.dumps([{'RuleID':'generic-api-key','File':'config.txt','StartLine':1,'EndLine':1,'StartColumn':1,'EndColumn':7,'Secret':'UNIT_SECRET_A','Match':'UNIT_MATCH_A','Commit':''}]).encode())
            prepared = prepare_findings(scanner, raw, root, files, 'project', 'scan', 'repository', 'hash', {'version':'test'})
            serialized = json.dumps(prepared)
            self.assertNotIn('UNIT_SECRET_A', serialized)
            self.assertNotIn('UNIT_MATCH_A', serialized)
            self.assertEqual(prepared[0]['source_location']['sha256'], files[0]['sha256'])
            self.assertEqual(prepared[0]['source'], 'SECRET_DETECTION')

if __name__ == '__main__': unittest.main()
