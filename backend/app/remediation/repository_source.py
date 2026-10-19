"""Resolve static findings only through their persisted scan and source manifest."""
from hashlib import sha256
from pathlib import PurePosixPath
from app.config.settings import settings
from app.models.finding import Finding
from app.models.repository import Repository
from app.models.project import Project, ScanJob
from app.repositories.storage import repository_directory
from app.remediation.source import SourceContext, SourceUnavailable, MAX_SOURCE_BYTES
from app.utils.redaction import redact_string


def safe_source_path(root, relative):
    if not isinstance(relative, str) or not relative or '\\' in relative or ':' in relative:
        raise SourceUnavailable('SOURCE_UNAVAILABLE', 'Invalid source path.')
    path = PurePosixPath(relative)
    if path.is_absolute() or any(p in ('', '.', '..') for p in relative.split('/')):
        raise SourceUnavailable('SOURCE_UNAVAILABLE', 'Source path must be a canonical relative path.')
    current = root
    for part in path.parts:
        if current.is_symlink():
            raise SourceUnavailable('SOURCE_CHANGED', 'Source contains a symlink.')
        current = current / part
    if current.is_symlink() or not current.is_file():
        raise SourceUnavailable('SOURCE_UNAVAILABLE', 'Source file is missing or unsafe.')
    return current


class RepositoryLocator:
    kind = 'MANAGED_REPOSITORY'

    def locate(self, db, finding, user_id):
        repo = db.query(Repository).join(Project).filter(
            Repository.id == finding.repository_id, Project.owner_id == user_id,
            Repository.project_id == finding.project_id, Repository.ingestion_status == 'READY').first()
        job = db.query(ScanJob).filter(ScanJob.id == finding.scan_id,
            ScanJob.repository_id == finding.repository_id,
            ScanJob.job_type == 'REPOSITORY_ANALYSIS').first()
        if not repo or not job or job.status not in ('COMPLETED', 'PARTIALLY_COMPLETED'):
            raise SourceUnavailable('SOURCE_UNAVAILABLE', 'No completed, owned repository snapshot matches this finding.')
        if finding.source == 'SECRET_DETECTION':
            raise SourceUnavailable('MANUAL_REVIEW_REQUIRED', 'Rotate/revoke this credential, remove it from source and history, and use secret configuration. Source removal does not revoke credentials.')
        if finding.source != 'SAST':
            raise SourceUnavailable('UNSUPPORTED_FINDING', 'This scanner requires a dedicated dependency or configuration review.')
        summary = job.result_summary or {}
        if summary.get('archive_sha256') != repo.archive_sha256:
            raise SourceUnavailable('SOURCE_CHANGED', 'Scan archive identity differs from the uploaded snapshot.')
        if not any(t.get('tool') == 'gitleaks' and t.get('status') == 'COMPLETED' for t in summary.get('tools', [])):
            raise SourceUnavailable('MANUAL_REVIEW_REQUIRED', 'Source withheld until secret detection completes successfully.')
        location = finding.source_location or {}
        path = location.get('file')
        entry = next((f for f in summary.get('intelligence', {}).get('files', []) if f.get('path') == path), None)
        if isinstance(path, str) and len(path) > 255:
            raise SourceUnavailable('PARTIAL_SOURCE', 'Source path exceeds the proposal storage limit; manual review required.')
        if not entry:
            raise SourceUnavailable('SOURCE_UNAVAILABLE', 'Scanner path is absent from this scan manifest.')
        secrets = db.query(Finding).filter(Finding.scan_id == job.id,
            Finding.repository_id == repo.id, Finding.source == 'SECRET_DETECTION').all()
        if any((f.source_location or {}).get('file') == path for f in secrets):
            raise SourceUnavailable('MANUAL_REVIEW_REQUIRED', 'This file contains a detected credential; rotate and remove it before AI remediation.')
        if PurePosixPath(path).name.startswith('.env') or PurePosixPath(path).suffix.lower() in {'.pem', '.key', '.p12', '.pfx'}:
            raise SourceUnavailable('MANUAL_REVIEW_REQUIRED', 'Credential file is withheld.')
        try:
            root = repository_directory(settings.SCAN_WORKSPACE_ROOT, repo.id) / 'source'
            file = safe_source_path(root, path)
            if file.stat().st_size > MAX_SOURCE_BYTES:
                raise SourceUnavailable('PARTIAL_SOURCE', 'Source exceeds the bounded remediation context limit.')
            data = file.read_bytes()
            digest = sha256(data).hexdigest()
            if digest != entry.get('sha256') or digest != location.get('sha256'):
                raise SourceUnavailable('SOURCE_CHANGED', 'File hash differs from the exact scanned source.')
            evidence = finding.evidence or {}
            if evidence.get('file_sha256') != digest or evidence.get('archive_sha256') != repo.archive_sha256:
                raise SourceUnavailable('SOURCE_CHANGED', 'Scanner evidence does not match source provenance.')
            text = data.decode('utf-8')
            if redact_string(text) != text:
                raise SourceUnavailable('MANUAL_REVIEW_REQUIRED', 'Potential credential content is withheld from AI requests.')
            lines = text.splitlines()
            start, end = location.get('start_line'), location.get('end_line')
            if type(start) is not int or type(end) is not int or not 1 <= start <= end <= len(lines):
                raise SourceUnavailable('PARTIAL_SOURCE', 'Scanner line range is invalid.')
            for key, line in [('start_column', start), ('end_column', end)]:
                column = location.get(key)
                if column is not None and (type(column) is not int or not 0 <= column <= len(lines[line-1]) + 1):
                    raise SourceUnavailable('PARTIAL_SOURCE', 'Scanner column range is invalid.')
            return SourceContext(self.kind, path, max(1, start-20), min(len(lines), end+30), start,
                tuple(lines), digest, 'VERIFIED_SOURCE', 'Owned scan, archive identity, manifest, evidence and file SHA-256 verified.')
        except (OSError, UnicodeError, ValueError):
            raise SourceUnavailable('SOURCE_UNAVAILABLE', 'Source is unavailable or not UTF-8 text.') from None
