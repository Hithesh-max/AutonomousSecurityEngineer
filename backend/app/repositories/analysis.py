"""Source snapshots, provenance validation and bounded source viewing."""
import hashlib
import json
from pathlib import Path
import shutil
from app.repositories.intelligence import eligible_files
from app.scanners.controlled import ToolFailure, finding_path, RULES_DIR
from app.utils.redaction import redact_finding_context, redact_string


def create_snapshot(source: Path, destination: Path, files: list[dict]):
    expected = {item['path']: item['sha256'] for item in files}
    destination.mkdir(mode=0o700)
    try:
        seen = set()
        for path in eligible_files(source):
            relative = path.relative_to(source).as_posix()
            data = path.read_bytes()
            if len(data) > 5 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != expected.get(relative):
                raise ToolFailure('PROVENANCE_ERROR', 'Managed source changed during analysis.')
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            target.write_bytes(data)
            target.chmod(0o400)
            seen.add(relative)
        if seen != set(expected):
            raise ToolFailure('PROVENANCE_ERROR', 'Managed source changed during analysis.')
        # No uploaded tool configuration or suppression files are used.
        (destination / '.semgrepignore').write_text('')
    except BaseException:
        shutil.rmtree(destination)
        raise


def verify_snapshot(root: Path, files: list[dict]):
    expected = {item['path']: item['sha256'] for item in files}
    actual = {}
    for path in eligible_files(root):
        if path.stat().st_size > 5 * 1024 * 1024:
            raise ToolFailure('PROVENANCE_ERROR', 'Analysis input changed during scanner execution.')
        actual[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        raise ToolFailure('PROVENANCE_ERROR', 'Analysis input changed during scanner execution.')


def rule_pack_hash():
    digest = hashlib.sha256()
    for name in ['semgrep.yml', 'gitleaks.toml', '.gitleaksignore']:
        digest.update(name.encode())
        digest.update((RULES_DIR / name).read_bytes())
    return digest.hexdigest()


def prepare_findings(adapter, raw, root, files, project_id, job_id, repository_id, archive_hash, tool_info):
    indexed = {file['path']: file for file in files}
    prepared, seen = [], set()
    try:
        normalized = adapter.normalize(raw, project_id)
        for finding in normalized:
            location = finding['source_location']
            path = finding_path(location['file'], root)
            entry = indexed.get(path)
            if not entry:
                raise ToolFailure('MALFORMED_OUTPUT', 'Scanner reported a file outside the source index.')
            for key in ['start_line', 'end_line']:
                if not isinstance(location.get(key), int) or isinstance(location[key], bool) or not 1 <= location[key] <= 1000000:
                    raise ToolFailure('MALFORMED_OUTPUT', 'Scanner reported invalid source coordinates.')
            if entry.get('line_count') is not None and location['end_line'] > entry['line_count']:
                raise ToolFailure('MALFORMED_OUTPUT', 'Scanner reported source coordinates outside the file.')
            for key in ['start_column', 'end_column']:
                if location.get(key) is not None and (not isinstance(location[key], int) or isinstance(location[key], bool) or not 0 <= location[key] <= 5242880):
                    raise ToolFailure('MALFORMED_OUTPUT', 'Scanner reported invalid source coordinates.')
            if location['end_line'] < location['start_line']:
                raise ToolFailure('MALFORMED_OUTPUT', 'Scanner reported invalid source coordinates.')
            if finding['severity'] not in {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'} or finding['confidence'] not in {'HIGH', 'MEDIUM', 'LOW'}:
                raise ToolFailure('MALFORMED_OUTPUT', 'Scanner reported invalid severity or confidence.')
            location['file'] = path
            location['sha256'] = entry['sha256']
            for function in entry['functions']:
                if function['line'] <= location['start_line'] <= function.get('end_line', function['line']):
                    location['function'] = function['name']
                    break
            fingerprint = hashlib.sha256(json.dumps([adapter.tool, finding['tool_rule_id'], path,
                location['start_line'], location.get('start_column')], separators=(',', ':')).encode()).hexdigest()
            if fingerprint in seen: continue
            seen.add(fingerprint)
            finding.update(scan_id=job_id, repository_id=repository_id, fingerprint=fingerprint)
            finding['evidence'].update(archive_sha256=archive_hash, file_sha256=entry['sha256'], **tool_info)
            prepared.append(redact_finding_context(finding))
        return prepared
    except ToolFailure:
        raise
    except (TypeError, ValueError, KeyError, AttributeError):
        raise ToolFailure('MALFORMED_OUTPUT', 'Scanner finding normalization failed.') from None


def source_context(source: Path, indexed: dict, *, line: int, secret_paths: set[str]):
    path = indexed['path']
    if not indexed['is_text'] or indexed['size'] > 1024 * 1024:
        raise PermissionError('Source viewer supports UTF-8 text under 1 MiB.')
    if path in secret_paths or Path(path).name.startswith('.env') or Path(path).suffix.lower() in {'.pem', '.key', '.p12', '.pfx'}:
        raise PermissionError('Source is withheld because it may contain credentials.')
    resolved = finding_path(path, source)
    if resolved != path:
        raise PermissionError('Managed source path is invalid.')
    raw = (source / path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != indexed['sha256']:
        raise PermissionError('Source checksum differs from this analysis.')
    lines = raw.decode('utf-8').splitlines()
    if line > max(len(lines), 1): raise ValueError('Requested line is outside this source file.')
    start, end = max(1, line - 20), min(len(lines), line + 30)
    text = '\n'.join(lines[start - 1:end])
    if len(text) > 20000: raise PermissionError('Requested source context exceeds the viewer limit.')
    return {'path': path, 'sha256': indexed['sha256'], 'start_line': start, 'end_line': end,
            'highlight_line': line, 'content': redact_string(text), 'redacted': True}
