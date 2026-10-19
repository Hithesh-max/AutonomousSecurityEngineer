import hashlib
from pathlib import Path
import tempfile
import unittest
from app.repositories.intelligence import inspect_repository, parse_manifest
from app.repositories.analysis import create_snapshot, verify_snapshot, source_context
from app.scanners.controlled import ToolFailure


class IntelligenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / 'source'
        self.root.mkdir()
    def tearDown(self): self.tmp.cleanup()
    def write(self, path, content):
        file = self.root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(content)
        return file
    def test_ast_framework_routes_functions_and_provenance(self):
        file = self.write('app.py', 'from fastapi import FastAPI\napp = FastAPI()\n@app.get("/invoices/{id}")\ndef invoice(id):\n    return id\n')
        result = inspect_repository(self.root)
        self.assertEqual(result.languages[0]['language'], 'Python')
        self.assertEqual(result.frameworks[0]['framework'], 'FastAPI')
        self.assertEqual(result.frameworks[0]['confidence'], 'HIGH')
        entry = result.files[0]
        self.assertEqual(entry['sha256'], hashlib.sha256(file.read_bytes()).hexdigest())
        self.assertEqual(entry['functions'][0]['name'], 'invoice')
        self.assertEqual(entry['routes'][0]['method'], 'GET')
        self.assertFalse(entry['routes'][0]['prefix_resolved'])
    def test_extensionless_shebang_and_binary_and_ignored(self):
        self.write('service', '#!/usr/bin/env python3\nimport flask\n')
        self.write('node_modules/bad.py', 'eval(input())')
        self.write('.semgrepignore', '*')
        (self.root / 'binary.py').write_bytes(b'\x00hello')
        result = inspect_repository(self.root)
        self.assertEqual({f['path'] for f in result.files}, {'service', 'binary.py'})
        self.assertEqual(next(f for f in result.files if f['path'] == 'service')['language'], 'Python')
        self.assertFalse(next(f for f in result.files if f['path'] == 'binary.py')['is_text'])
    def test_dependency_manifests_and_framework(self):
        self.write('package.json', '{"dependencies":{"react":"18.2.0","thing":"https://user:secret@host/x"}}')
        self.write('requirements.txt', 'Flask==3.0.0\nfastapi>=0.110\n')
        result = inspect_repository(self.root)
        self.assertEqual(len(result.dependencies), 4)
        self.assertEqual({f['framework'] for f in result.frameworks}, {'React', 'Flask', 'FastAPI'})
        self.assertNotIn('user:secret', str(result.dependencies))
    def test_toml_lock_and_malformed(self):
        deps = parse_manifest('pyproject.toml', '[project]\ndependencies=["fastapi==0.110.0"]')
        self.assertEqual(deps[0]['version'], '0.110.0')
        deps = parse_manifest('package-lock.json', '{"packages":{"node_modules/react":{"version":"18.2.0"}}}')
        self.assertTrue(deps[0]['locked'])
        self.write('package.json', 'broken{')
        self.assertEqual(inspect_repository(self.root).warnings, ['MANIFEST_PARSE_INCOMPLETE'])
    def test_limits_and_symlinks(self):
        self.write('one.py', 'pass')
        with self.assertRaises(ValueError): inspect_repository(self.root, max_files=0)
        try:
            (self.root / 'escape.py').symlink_to('/etc/passwd')
            with self.assertRaises(ValueError): inspect_repository(self.root)
        except OSError as e:
            if getattr(e, 'winerror', None) == 1314:
                return  # Skip symlink verification on Windows when client lacks privilege
            raise
    def test_snapshot_provenance_and_source_secret_withholding(self):
        self.write('app.py', 'x = 1\npassword = "dummy"\n')
        files = inspect_repository(self.root).files
        snapshot = self.root.parent / 'snapshot'
        create_snapshot(self.root, snapshot, files)
        verify_snapshot(snapshot, files)
        context = source_context(self.root, files[0], line=2, secret_paths=set())
        self.assertNotIn('dummy', context['content'])
        with self.assertRaises(PermissionError): source_context(self.root, files[0], line=2, secret_paths={'app.py'})
        self.write('app.py', 'changed')
        with self.assertRaises(PermissionError): source_context(self.root, files[0], line=1, secret_paths=set())
        with self.assertRaises(ToolFailure): create_snapshot(self.root, self.root.parent/'snapshot2', files)
        (snapshot / 'app.py').chmod(0o600)
        (snapshot / 'app.py').write_text('changed')
        with self.assertRaises(ToolFailure): verify_snapshot(snapshot, files)

if __name__ == '__main__': unittest.main()
