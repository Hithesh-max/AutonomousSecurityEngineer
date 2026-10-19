"""Mandatory real-tool smoke check. Missing tools fail, rather than skip."""
import json
from pathlib import Path
import shutil
import sys
import tempfile
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.repositories.intelligence import inspect_repository
from app.repositories.analysis import prepare_findings, rule_pack_hash
from app.scanners.semgrep import SemgrepScanner
from app.scanners.gitleaks import GitleaksScanner
from app.scanners.controlled import ToolFailure


def main():
    with tempfile.TemporaryDirectory(prefix='ase-static-check-') as temporary:
        root = Path(temporary)
        fixtures = Path(__file__).resolve().parents[1] / 'tests/fixtures/static-analysis-lab'
        for fixture in fixtures.iterdir():
            if fixture.is_file(): shutil.copyfile(fixture, root / fixture.name)
        intelligence = inspect_repository(root)
        for adapter in [SemgrepScanner(), GitleaksScanner()]:
            info = {**adapter.health_check(), 'rule_pack_sha256': rule_pack_hash()}
            raw = adapter.scan(root)
            findings = prepare_findings(adapter, raw, root, intelligence.files, 'test-project', 'test-scan', 'test-repository', 'test-archive', info)
            if adapter.tool == 'semgrep':
                if raw.get('errors'): raise RuntimeError('Semgrep reported rule or analysis errors.')
                rules = {f['tool_rule_id'] for f in findings}
                for suffix in ['shell-enabled', 'input-to-eval', 'request-to-sql']:
                    if not any(rule.endswith(suffix) for rule in rules):
                        raise RuntimeError('Semgrep did not detect every expected seeded rule.')
            elif not findings:
                raise RuntimeError('Gitleaks did not detect the synthetic seeded credential.')
            if 'a7B9c2D4e6F8g1H3j5K7m9N2p4Q6r8S1' in json.dumps(findings):
                raise RuntimeError('Secret redaction check failed.')
            print(f"PASS: {adapter.display_name} {info['version']}: {len(findings)} real normalized findings; provenance and redaction checked.")
        print('PASS: Both real scanners detected seeded issues. Application code was not executed.')


if __name__ == '__main__':
    try: main()
    except (FileNotFoundError, ToolFailure, RuntimeError) as error:
        print(f'FAIL: {error}', file=sys.stderr)
        sys.exit(1)
