"""Real PostgreSQL paths; queue publication is stubbed, scanner findings never are."""
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import shutil
from uuid import uuid4
from unittest.mock import Mock
import pytest
from app.config.settings import settings
from app.models.project import Project, Target, ScanJob
from app.models.repository import Repository
from app.models.finding import Finding
from app.repositories.storage import repository_directory
from app.workers.analysis_jobs import analyze_repository
from app.workers.recovery_jobs import recover_stale_jobs
from app.scanners.controlled import ToolFailure


@pytest.fixture
def context(tmp_path, monkeypatch, test_db, test_user, test_user_token):
    monkeypatch.setattr(settings, 'SCAN_WORKSPACE_ROOT', str(tmp_path))
    dispatch = Mock()
    monkeypatch.setattr(analyze_repository, 'apply_async', dispatch)
    project = Project(name='Static analysis '+uuid4().hex, owner_id=test_user.id)
    test_db.add(project); test_db.commit()
    target = Target(name='Static lab', url='http://localhost:8080', project_id=project.id,
                    authorization_status='APPROVED', explicit_scope='localhost', is_active=True)
    test_db.add(target); test_db.commit()
    repo = Repository(id=uuid4(), project_id=project.id, target_id=target.id, uploaded_by=test_user.id,
                      name='Static lab source', source_type='ZIP', ingestion_status='READY', analysis_status='NOT_STARTED',
                      archive_sha256=hashlib.sha256(b'test archive identity').hexdigest(), upload_bytes=100,
                      source_authorized_at=datetime.now(timezone.utc))
    test_db.add(repo); test_db.commit()
    directory = repository_directory(settings.SCAN_WORKSPACE_ROOT, repo.id, create=True)
    (directory/'source').mkdir()
    (directory/'source/app.py').write_text('from flask import Flask\napp = Flask(__name__)\n')
    return repo, target, directory, {'Authorization': f'Bearer {test_user_token}'}, dispatch


def submit(client, repo, headers):
    response = client.post(f'/api/repositories/{repo.id}/analyze', headers=headers)
    assert response.status_code == 202, response.text
    return response.json()['job_id']


def test_analysis_authorization_and_duplicate_admission(context, client, test_db, test_user_2_token):
    repo, target, directory, headers, dispatch = context
    other = {'Authorization': f'Bearer {test_user_2_token}'}
    assert client.post(f'/api/repositories/{repo.id}/analyze', headers=other).status_code == 404
    target.authorization_status = 'PENDING'; test_db.commit()
    assert client.post(f'/api/repositories/{repo.id}/analyze', headers=headers).status_code == 403
    target.authorization_status = 'APPROVED'; repo.ingestion_status = 'QUEUED'; test_db.commit()
    assert client.post(f'/api/repositories/{repo.id}/analyze', headers=headers).status_code == 409
    repo.ingestion_status = 'READY'; test_db.commit()
    submit(client, repo, headers)
    assert client.post(f'/api/repositories/{repo.id}/analyze', headers=headers).status_code == 409
    assert client.get(f'/api/repositories/{repo.id}/analyses', headers=other).status_code == 404
    assert client.get(f'/api/repositories/{repo.id}/files', headers=other).status_code == 404
    assert client.get(f'/api/repositories/{repo.id}/source', params={'path':'app.py'}, headers=other).status_code == 404
    dispatch.assert_called_once()


def test_missing_tools_are_durable_failures_not_clean_scans(context, client, test_db, monkeypatch):
    repo, target, directory, headers, dispatch = context
    job_id = submit(client, repo, headers)
    monkeypatch.setattr('app.scanners.controlled.shutil.which', lambda _: None)
    with pytest.raises(RuntimeError, match='both scanners failed'): analyze_repository(job_id)
    job = test_db.query(ScanJob).filter(ScanJob.id == job_id).one(); test_db.refresh(job)
    assert job.status == 'FAILED'
    assert all(tool['status'] == 'FAILED' and tool['failure_code'] == 'TOOL_NOT_INSTALLED' for tool in job.result_summary['tools'])
    assert job.result_summary['intelligence']['frameworks'][0]['framework'] == 'Flask'
    assert test_db.query(Finding).filter(Finding.scan_id == job.id).count() == 0
    assert 'Aborted' in analyze_repository(job_id)
    assert not list(directory.glob('analysis-*'))
    assert client.get(f'/api/repositories/{repo.id}/source', params={'path':'app.py'}, headers=headers).status_code == 409


def test_revocation_after_queue_stops_before_tools(context, client, test_db, monkeypatch):
    repo, target, directory, headers, dispatch = context
    job_id = submit(client, repo, headers)
    target.authorization_status = 'REJECTED'; test_db.commit()
    probe = Mock(side_effect=AssertionError('Scanner must not run'))
    monkeypatch.setattr('app.scanners.semgrep.SemgrepScanner.health_check', probe)
    with pytest.raises(RuntimeError, match='authorization'): analyze_repository(job_id)
    probe.assert_not_called()
    job = test_db.query(ScanJob).filter(ScanJob.id == job_id).one(); test_db.refresh(job)
    assert job.failure_code == 'AUTHORIZATION_ERROR'


def test_broker_failure_is_persisted(context, client, test_db):
    repo, target, directory, headers, dispatch = context
    dispatch.side_effect = RuntimeError('synthetic broker failure')
    response = client.post(f'/api/repositories/{repo.id}/analyze', headers=headers)
    assert response.status_code == 503
    test_db.refresh(repo)
    assert repo.analysis_status == 'FAILED'
    job = test_db.query(ScanJob).filter(ScanJob.id == repo.latest_analysis_job_id).one()
    assert job.failure_code == 'BROKER_SUBMISSION_FAILED'


def test_analysis_recovery_preserves_ingested_source(context, client, test_db):
    repo, target, directory, headers, dispatch = context
    job_id = submit(client, repo, headers)
    job = test_db.query(ScanJob).filter(ScanJob.id == job_id).one()
    job.created_at = datetime.now(timezone.utc).replace(tzinfo=None)-timedelta(minutes=20)
    test_db.commit()
    recover_stale_jobs()
    test_db.refresh(repo); test_db.refresh(job)
    assert job.status == 'FAILED' and repo.analysis_status == 'FAILED'
    assert repo.ingestion_status == 'READY'
    assert (directory/'source/app.py').is_file()


@pytest.mark.skipif(not shutil.which('semgrep') or not shutil.which('gitleaks'), reason='Real Semgrep and Gitleaks are required')
def test_real_scanners_database_findings_source_and_provenance(context, client, test_db):
    repo, target, directory, headers, dispatch = context
    # This acceptance test executes both real binaries. No scanner-output mocks.
    fixtures = Path(__file__).parent / 'fixtures/static-analysis-lab'
    for path in fixtures.iterdir():
        if path.is_file(): shutil.copyfile(path, directory/'source'/path.name)
    job_id = submit(client, repo, headers)
    result = analyze_repository(job_id)
    assert result == 'COMPLETED', client.get(f'/api/repositories/{repo.id}/analyses', headers=headers).json()
    findings = client.get(f'/api/repositories/{repo.id}/findings', headers=headers).json()
    assert any(f['source'] == 'SAST' and 'shell-enabled' in f['tool_rule_id'] for f in findings)
    assert any(f['source'] == 'SECRET_DETECTION' for f in findings)
    assert all(f['scan_id'] == job_id and f['repository_id'] == str(repo.id) and f['source_location']['sha256'] for f in findings)
    assert 'a7B9c2D4e6F8g1H3j5K7m9N2p4Q6r8S1' not in str(findings)
    assert client.get(f'/api/repositories/{repo.id}/source', params={'path':'secrets.py'}, headers=headers).status_code == 403
    shell_finding = next(f for f in findings if f['source'] == 'SAST' and 'shell-enabled' in f['tool_rule_id'])
    location = shell_finding['source_location']
    source = client.get(f'/api/repositories/{repo.id}/source',
                        params={'path': location['file'], 'line': location['start_line'], 'scan_id': job_id},
                        headers=headers)
    assert source.status_code == 200, source.text
    assert 'subprocess' in source.json()['content']
    assert source.json()['highlight_line'] == location['start_line']
    assert source.json()['sha256'] == location['sha256']
    indexed = client.get(f'/api/repositories/{repo.id}/files', headers=headers).json()
    assert any(file['path'] == 'app.py' and file['functions'] for file in indexed)


def test_fresh_worker_imports_all_models_and_tasks():
    import subprocess
    import sys
    result = subprocess.run([sys.executable, '-c',
        "from app.workers.celery_app import celery; celery.loader.import_default_modules(); "
        "from sqlalchemy.orm import configure_mappers; configure_mappers(); "
        "assert 'analyze_repository' in celery.tasks; assert 'ingest_zip_repository' in celery.tasks"],
        capture_output=True, timeout=30)
    assert result.returncode == 0, 'Fresh worker model/task initialization failed: '+result.stderr.decode()[-2000:]
