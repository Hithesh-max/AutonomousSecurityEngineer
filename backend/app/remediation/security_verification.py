"""Static reanalysis against operator-owned rules; never executes uploaded code."""
from pathlib import Path
import shutil
import tempfile
from app.scanners.semgrep import SemgrepScanner
from app.scanners.controlled import ToolFailure, finding_path
from app.repositories.intelligence import eligible_files


def reanalyze(root, findings):
    try:
        scanner = SemgrepScanner()
        version = scanner.health_check()
        with tempfile.TemporaryDirectory(prefix='ase-rescan-') as tmp:
            isolated = Path(tmp)
            for source in eligible_files(root):
                destination = isolated / source.relative_to(root)
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
            (isolated / '.semgrepignore').write_text('')
            raw = scanner.scan(isolated)
            detected = {(item['check_id'], finding_path(item['path'], isolated)) for item in raw['results']}
            coverage = bool(raw.get('paths', {}).get('scanned')) and not raw.get('errors')
            results = []
            for finding in findings:
                key = (finding.tool_rule_id, (finding.source_location or {}).get('file'))
                present = key in detected
                results.append({'finding_id': str(finding.id),
                    'status': 'STILL_VULNERABLE' if present else 'INCONCLUSIVE',
                    'evidence': 'Scanner still reports this rule in the same file; review whether it is the same occurrence.' if present else
                    'Rule not reported after changes; this is not proof of remediation.' if coverage else 'Scanner coverage was incomplete.'})
            return {'status': 'COMPLETED' if coverage else 'INCONCLUSIVE', 'scanner': version,
                    'finding_count': len(detected), 'findings': results,
                    'limitation': 'Comparison groups rule and file to tolerate shifted lines; multiple occurrences need human review.'}
    except FileNotFoundError:
        return {'status': 'NOT_SUPPORTED', 'detail': 'Semgrep is not installed in this process; no rescan performed.'}
    except (ToolFailure, OSError, ValueError, KeyError, TypeError):
        return {'status': 'VERIFICATION_FAILED', 'detail': 'Static reanalysis failed or returned incomplete/invalid data.'}
