from pathlib import Path
import tempfile
from app.scanners.controlled import ControlledAdapter, ToolFailure, RULES_DIR, MAX_OUTPUT, MAX_FINDINGS, run_process, load_json


class GitleaksScanner(ControlledAdapter):
    tool = 'gitleaks'
    display_name = 'Gitleaks'

    def execute(self, target: Path):
        executable = self.validate_environment()
        with tempfile.TemporaryDirectory(prefix='ase-gitleaks-') as temp:
            report = Path(temp) / 'report.json'
            result = run_process([executable, 'detect', '--no-git', '--source', str(target.resolve()),
                                  '--config', str((RULES_DIR / 'gitleaks.toml').resolve()),
                                  '--gitleaks-ignore-path', str(RULES_DIR.resolve()), '--ignore-gitleaks-allow',
                                  '--redact', '--report-format=json', '--report-path', str(report), '--exit-code=7'],
                                 cwd=target, report=report)
            if result.returncode not in (0, 7):
                raise ToolFailure('TOOL_EXIT_ERROR', 'Gitleaks exited with a scanner error.')
            if not report.is_file(): raise ToolFailure('MALFORMED_OUTPUT', 'Gitleaks did not produce its report.')
            if report.stat().st_size > MAX_OUTPUT: raise ToolFailure('OUTPUT_LIMIT', 'Gitleaks report exceeded the configured limit.')
            output = report.read_bytes()
            parsed = self.parse(output)
            if result.returncode == 7 and not parsed:
                raise ToolFailure('TOOL_EXIT_ERROR', 'Gitleaks returned a nonzero exit without secret findings.')
            return output

    def parse(self, output):
        data = load_json(output)
        if not isinstance(data, list): raise ToolFailure('MALFORMED_OUTPUT', 'Gitleaks JSON must be a list.')
        if len(data) > MAX_FINDINGS: raise ToolFailure('FINDING_LIMIT', 'Gitleaks exceeded the per-tool finding limit.')
        return data

    def normalize(self, raw_data, project_id):
        normalized = []
        for leak in raw_data:
            if not isinstance(leak, dict) or not isinstance(leak.get('RuleID'), str):
                raise ToolFailure('MALFORMED_OUTPUT', 'Gitleaks result is malformed.')
            normalized.append({
                'project_id': project_id, 'source': 'SECRET_DETECTION', 'tool_rule_id': leak['RuleID'][:255],
                'title': f"Exposed secret: {str(leak.get('Description', 'Hardcoded credential'))[:200]}",
                'description': 'Gitleaks detected a possible exposed credential. Validate and rotate it if real.',
                'category': 'HARDCODED_SECRET', 'severity': 'HIGH', 'confidence': 'HIGH', 'status': 'OPEN',
                'source_tools': ['gitleaks'], 'cwe': 'CWE-798',
                'source_location': {'file': leak.get('File'), 'start_line': leak.get('StartLine'), 'end_line': leak.get('EndLine'),
                                    'start_column': leak.get('StartColumn'), 'end_column': leak.get('EndColumn')},
                # Secret, Match, raw report, and commit messages are never persisted.
                'evidence': {'tool': 'gitleaks', 'rule': leak['RuleID'], 'match': '[REDACTED]', 'secret': '[REDACTED]',
                             'commit': leak.get('Commit') or None, 'secret_stored': False},
            })
        return normalized
