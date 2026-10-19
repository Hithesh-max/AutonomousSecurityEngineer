"""Build a complete archive from a hash-verified upload; never mutate source."""
from collections import defaultdict
from datetime import datetime, timezone
from hashlib import sha256
from io import BytesIO
import json
from pathlib import PurePosixPath, Path
import tempfile
import zipfile
from uuid import uuid4
from app.ai.schemas import ModelPatch
from app.config.settings import settings
from app.models.finding import Finding
from app.models.repository import Repository
from app.models.project import Project
from app.remediation.source import locator_for, SourceUnavailable
from app.remediation.patching import validate_and_render, PatchRejected
from app.remediation.languages import syntax_check
from app.repositories.archive import extract_zip, ArchiveLimits
from app.repositories.storage import repository_directory
from app.utils.redaction import redact_string


class ExportRejected(ValueError): pass


def apply_edits(lines, edits):
    result = list(lines)
    previous = 0
    for edit in sorted(edits, key=lambda e: e['start_line']):
        if edit['start_line'] <= previous:
            raise ExportRejected('Approved patches overlap; reject or regenerate conflicting proposals.')
        previous = edit['end_line']
    for edit in sorted(edits, key=lambda e: e['start_line'], reverse=True):
        replacement = edit['replacement_text'].replace('\r\n', '\n').replace('\r', '\n').split('\n')
        result[edit['start_line']-1:edit['end_line']] = [] if replacement == [''] else replacement
    return ('\n'.join(result) + '\n').encode('utf-8')


def _patched_bytes(source, patch):
    if source.sha256 != patch.source_sha256 or source.path != patch.source_path or source.kind != patch.source_kind:
        raise ExportRejected('Patch source identity is stale.')
    model = ModelPatch.model_validate(dict(edits=patch.edits, explanation=patch.explanation,
        behavior_notes=patch.behavior_notes or '', limitations=patch.limitations or []))
    rendered = validate_and_render(source, model)
    if rendered.patch_sha256 != patch.patch_sha256 or rendered.patched_sha256 != patch.patched_sha256:
        raise ExportRejected('Stored patch integrity check failed; review a new proposal.')
    result = apply_edits(source.lines, rendered.edits)
    if sha256(result).hexdigest() != patch.patched_sha256:
        raise ExportRejected('Result hash differs from the reviewed proposal.')
    return result


def excluded_path(path):
    p = PurePosixPath(path)
    return (any(part in {'.git', '__pycache__', '.pytest_cache', 'node_modules', '.venv', 'venv'} for part in p.parts)
        or (p.name.startswith('.env') and p.name not in {'.env.example', '.env.sample', '.env.template'})
        or p.suffix.lower() in {'.pem', '.key', '.p12', '.pfx', '.dump', '.log', '.pyc', '.sqlite', '.sqlite3', '.db', '.pkl', '.pickle'}
        or p.name.lower() in {'id_rsa', 'id_ed25519', 'credentials', 'credentials.json'})


def export_repository_zip(db, user, repository_id, proposals):
    repo = db.query(Repository).join(Project).filter(Repository.id == repository_id,
        Project.owner_id == user.id, Repository.ingestion_status == 'READY').with_for_update(of=Repository).first()
    if not repo: raise ExportRejected('Owned repository is unavailable.')
    if not proposals: raise ExportRejected('Select at least one approved patch.')
    findings = db.query(Finding).filter(Finding.repository_id == repo.id,
        Finding.scan_id == repo.latest_analysis_job_id).all()
    by_id = {f.id: f for f in findings}
    secret_paths = {(f.source_location or {}).get('file') for f in findings if f.source == 'SECRET_DETECTION'}
    groups, sources = defaultdict(list), {}
    seen = set()
    for patch in proposals:
        # Proposals may have been loaded before waiting for the repository lock.
        # Refresh them now so concurrent revocation cannot export a stale approval.
        db.refresh(patch)
        if patch.id in seen: raise ExportRejected('Duplicate proposal.')
        seen.add(patch.id)
        if patch.status not in {'APPROVED', 'INCONCLUSIVE', 'VERIFIED'} or patch.approved_by != user.id or not patch.approved_at:
            raise ExportRejected('Every exported patch must have a current approval by this user.')
        finding = by_id.get(patch.finding_id)
        if not finding or patch.project_id != repo.project_id:
            raise ExportRejected('Patch does not belong to the selected latest repository scan.')
        try:
            source = locator_for(finding).locate(db, finding, user.id)
            _patched_bytes(source, patch)
        except (SourceUnavailable, PatchRejected, ValueError):
            raise ExportRejected('An approved patch or its source failed integrity validation.') from None
        groups[source.path].append(patch)
        sources[source.path] = source
    archive = repository_directory(settings.SCAN_WORKSPACE_ROOT, repo.id) / 'upload.zip'
    if archive.is_symlink() or not archive.is_file() or archive.stat().st_size > settings.ZIP_MAX_UPLOAD_BYTES:
        raise ExportRejected('Original archive is unavailable or exceeds limits.')
    if sha256(archive.read_bytes()).hexdigest() != repo.archive_sha256:
        raise ExportRejected('Original upload hash changed.')
    manifest = {'artifact_id': str(uuid4()), 'schema_version': 1, 'repository_id': str(repo.id), 'scan_id': str(repo.latest_analysis_job_id),
        'generated_at': datetime.now(timezone.utc).isoformat(), 'original_archive_sha256': repo.archive_sha256,
        'verification_status': 'INCONCLUSIVE', 'changed_files': [], 'excluded_files': [],
        'findings': [{'finding_id': str(f.id), 'title': redact_string(f.title), 'severity': f.severity,
          'status': 'APPLIED_UNVERIFIED' if any(p.finding_id == f.id for p in proposals) else 'UNRESOLVED'} for f in findings],
        'limitations': ['Syntax validation is not proof of a security fix.',
          'Build, functional tests and dynamic rescans were not executed. Uploaded code is never executed on the host.',
          'Credential-bearing files and private artifacts are excluded; restore configuration securely before running.']}
    limits = ArchiveLimits(settings.ZIP_MAX_UPLOAD_BYTES, settings.ZIP_MAX_EXPANDED_BYTES,
        settings.ZIP_MAX_FILE_BYTES, settings.ZIP_MAX_ENTRIES, settings.ZIP_MAX_COMPRESSION_RATIO)
    with tempfile.TemporaryDirectory(prefix='ase-export-') as temp:
        root = Path(temp)
        extract_zip(archive, root, limits)
        source_root = root / 'source'
        for path, patches in groups.items():
            original = source_root / path
            if not original.is_file() or sha256(original.read_bytes()).hexdigest() != sources[path].sha256:
                raise ExportRejected('Uploaded archive and scanned source differ.')
            edits = [e for p in patches for e in p.edits]
            content = apply_edits(sources[path].lines, edits)
            syntax = syntax_check(path, content.decode('utf-8'))
            if syntax['status'] != 'PASS': raise ExportRejected('Combined patches fail syntax validation.')
            original.write_bytes(content)
            manifest['changed_files'].append({'path': path, 'original_sha256': sources[path].sha256,
                'sha256': sha256(content).hexdigest(), 'patch_ids': [str(p.id) for p in patches],
                'approved_patch_hashes': [p.patch_sha256 for p in patches], 'syntax': syntax})
        from app.remediation.security_verification import reanalyze
        manifest['static_security_reanalysis'] = reanalyze(source_root, [f for f in findings if f.source == 'SAST'])
        output = BytesIO()
        with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as bundle:
            for file in sorted(source_root.rglob('*')):
                if not file.is_file(): continue
                path = file.relative_to(source_root).as_posix()
                content = file.read_bytes()
                sensitive = path in secret_paths or excluded_path(path)
                try: sensitive |= redact_string(content.decode('utf-8')) != content.decode('utf-8')
                except UnicodeError: pass
                if sensitive:
                    if path in groups: raise ExportRejected('A corrected file contains potential credentials and cannot be exported.')
                    manifest['excluded_files'].append(path)
                    continue
                bundle.writestr(path, content)
            report_path = 'ASE_REMEDIATION_MANIFEST.json'
            if (source_root / report_path).exists():
                raise ExportRejected('Project contains the reserved remediation manifest filename.')
            bundle.writestr(report_path, json.dumps(manifest, indent=2))
        output.seek(0)
        with zipfile.ZipFile(output) as bundle:
            if bundle.testzip() is not None: raise ExportRejected('Export CRC validation failed.')
        return output.getvalue()
