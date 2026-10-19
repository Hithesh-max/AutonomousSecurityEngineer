"""Validate corrected copies without executing uploaded application code.

A temporary directory is not an execution sandbox. Build/test execution remains
NOT_RUN until a separately isolated runner is implemented and configured.
"""
from collections import defaultdict
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path, PurePosixPath
import shutil
import tempfile

from app.remediation.languages import syntax_check
from app.remediation.export import apply_edits, _patched_bytes
from app.remediation.security_verification import reanalyze


class VerificationStatus:
    VERIFIED_FIXED = 'VERIFIED_FIXED'
    STILL_VULNERABLE = 'STILL_VULNERABLE'
    REGRESSION = 'REGRESSION'
    FAILED = 'FAILED'
    UNSUPPORTED = 'UNSUPPORTED'
    INCONCLUSIVE = 'INCONCLUSIVE'


def create_isolated_environment():
    # Retained for compatibility; this environment is never used to execute code.
    return {'CI': 'true', 'HTTP_PROXY': 'http://127.0.0.1:0', 'HTTPS_PROXY': 'http://127.0.0.1:0'}


def run_bounded_process(*args, **kwargs):
    raise RuntimeError('Build/test execution is disabled: a temporary folder is not an isolated execution sandbox.')


def detect_project_runner(repo_dir):
    root = Path(repo_dir)
    marker_types = {'package.json': 'NODEJS', 'requirements.txt': 'PYTHON', 'pyproject.toml': 'PYTHON', 'pom.xml': 'JAVA_MAVEN', 'Cargo.toml': 'RUST_CARGO'}
    components = [{'path': p.parent.relative_to(root).as_posix(), 'runner_type': marker_types[p.name]}
                  for p in sorted(root.rglob('*')) if p.is_file() and p.name in marker_types]
    types = sorted({c['runner_type'] for c in components})
    return {'runner_type': types[0] if len(types) == 1 else 'MULTI_COMPONENT' if types else 'NONE',
            'components': components, 'has_tests': False, 'build_cmd': None, 'test_cmd': None}


def verify_project_changes(original_repo_root, proposals, sources, findings):
    if not proposals:
        raise ValueError('No currently approved patches. Generate, review and approve a patch first.')
    root = Path(original_repo_root)
    if root.is_symlink() or any(p.is_symlink() for p in root.rglob('*')):
        raise ValueError('Verification source must not contain symlinks.')
    groups = defaultdict(list)
    for patch in proposals:
        path = patch.source_path
        parts = PurePosixPath(path).parts
        if not path or PurePosixPath(path).is_absolute() or '..' in parts or '\\' in path:
            raise ValueError('Invalid patch path.')
        source = sources.get(path)
        if source is None:
            raise ValueError('Verified source is unavailable; no verification performed.')
        original = root / path
        if not original.is_file() or sha256(original.read_bytes()).hexdigest() != source.sha256:
            raise ValueError('Source changed since approval; review a new patch.')
        _patched_bytes(source, patch)  # Enforce reviewed patch and source hashes.
        groups[path].append(patch)
    with tempfile.TemporaryDirectory(prefix='ase-static-check-') as tmp:
        corrected = Path(tmp) / 'project'
        shutil.copytree(root, corrected)
        files = {}
        for path, patches in groups.items():
            content = apply_edits(sources[path].lines, [e for p in patches for e in p.edits])
            check = syntax_check(path, content.decode('utf-8'))
            (corrected / path).write_bytes(content)
            files[path] = {'patch_ids': [str(p.id) for p in patches], 'patched_sha256': sha256(content).hexdigest(), 'syntax_check': check}
        syntax_failed = any(v['syntax_check']['status'] == 'FAIL' for v in files.values())
        static = {'status': 'NOT_RUN', 'detail': 'Syntax validation failed.'} if syntax_failed else reanalyze(corrected, [f for f in findings if getattr(f, 'source', None) == 'SAST'])
        static_results = {i['finding_id']: i for i in static.get('findings', [])}
        evaluations = []
        for finding in findings:
            patch = next(p for p in proposals if p.finding_id == finding.id)
            check = files[patch.source_path]['syntax_check']
            status = 'FAILED' if check['status'] == 'FAIL' else static_results.get(str(finding.id), {}).get('status', 'INCONCLUSIVE')
            evaluations.append({'finding_id': str(finding.id), 'status': status,
                'evidence': check.get('detail', 'Syntax validation failed.') if status == 'FAILED' else static_results.get(str(finding.id), {}).get('evidence', 'Syntax checks and missing alerts are not proof of a fix; build, functional and dynamic tests were not run.')})
        statuses = {e['status'] for e in evaluations}
        overall = 'FAILED' if 'FAILED' in statuses else 'STILL_VULNERABLE' if 'STILL_VULNERABLE' in statuses else 'INCONCLUSIVE'
        return {'overall_status': overall, 'runner_type': detect_project_runner(corrected)['runner_type'],
                'applied_files': files, 'build_result': {'status': 'NOT_RUN', 'reason': 'No isolated execution runner configured.'},
                'test_result': {'status': 'NOT_RUN', 'reason': 'Uploaded code is not executed in the API container.'},
                'static_security_reanalysis': static, 'finding_evaluations': evaluations,
                'verification_timestamp': datetime.now(timezone.utc).isoformat(),
                'coverage_limitations': ['Static checks only. No build, functional or dynamic tests were executed.', 'Temporary file copies are not execution sandboxes.', 'No finding is marked VERIFIED_FIXED by these checks.']}
