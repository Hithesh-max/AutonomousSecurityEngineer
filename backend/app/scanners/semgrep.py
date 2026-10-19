from pathlib import Path
from app.scanners.controlled import ControlledAdapter, ToolFailure, RULES_DIR, MAX_FINDINGS, run_process, load_json


class SemgrepScanner(ControlledAdapter):
    tool = 'semgrep'
    display_name = 'Semgrep'

    def execute(self, target: Path):
        executable = self.validate_environment()
        result = run_process([executable, 'scan', '--config', str((RULES_DIR / 'semgrep.yml').resolve()),
                              '--json', '--metrics=off', '--disable-version-check', '--disable-nosem',
                              '--no-git-ignore', '--jobs=1', '--max-memory=256', '--timeout=10',
                              '--max-target-bytes=5242880', str(target.resolve())], cwd=target)
        if result.returncode != 0:
            raise ToolFailure('TOOL_EXIT_ERROR', 'Semgrep exited with a scanner error.')
        return result.stdout

    def parse(self, output):
        data = load_json(output)
        if not isinstance(data, dict) or not isinstance(data.get('results'), list) or not isinstance(data.get('errors', []), list):
            raise ToolFailure('MALFORMED_OUTPUT', 'Semgrep JSON has an invalid shape.')
        if len(data['results']) > MAX_FINDINGS:
            raise ToolFailure('FINDING_LIMIT', 'Semgrep exceeded the per-tool finding limit.')
        if not isinstance(data.get('paths', {}), dict) or not isinstance(data.get('paths', {}).get('scanned', []), list):
            raise ToolFailure('MALFORMED_OUTPUT', 'Semgrep coverage metadata is malformed.')
        return data

    def normalize(self, raw_data, project_id):
        normalized = []
        for issue in raw_data.get('results', []):
            if not isinstance(issue, dict) or not isinstance(issue.get('extra'), dict) or not isinstance(issue.get('check_id'), str):
                raise ToolFailure('MALFORMED_OUTPUT', 'Semgrep result is malformed.')
            extra = issue['extra']
            metadata = extra.get('metadata', {})
            if not isinstance(metadata, dict): raise ToolFailure('MALFORMED_OUTPUT', 'Semgrep rule metadata is malformed.')
            cwe = metadata.get('cwe')
            if isinstance(cwe, list): cwe = cwe[0] if cwe else None
            normalized.append({
                'project_id': project_id, 'source': 'SAST',
                'tool_rule_id': issue['check_id'][:255],
                'title': str(extra.get('message', 'Static security finding')).split('\n')[0][:255],
                'description': str(extra.get('message', 'Review the scanner evidence.'))[:2000],
                'category': metadata.get('category', 'SAST'),
                'severity': metadata.get('ase_severity', {'ERROR': 'HIGH', 'WARNING': 'MEDIUM', 'INFO': 'LOW'}.get(extra.get('severity'), 'INFO')),
                'confidence': metadata.get('confidence', 'MEDIUM'), 'status': 'OPEN', 'source_tools': ['semgrep'],
                'source_location': {'file': issue.get('path'), 'start_line': issue.get('start', {}).get('line'),
                                    'end_line': issue.get('end', {}).get('line'), 'start_column': issue.get('start', {}).get('col'),
                                    'end_column': issue.get('end', {}).get('col')},
                # Code is fetched separately through the redacted source viewer.
                'evidence': {'tool': 'semgrep', 'rule': issue['check_id'], 'code_snippet_stored': False},
                'cwe': cwe if isinstance(cwe, str) else None,
            })
        return normalized
