"""PostgreSQL API/worker integration; queue submission is stubbed, not scanners."""
from datetime import datetime, timedelta, timezone
import io
from pathlib import Path
import subprocess
import sys
from uuid import uuid4
from unittest.mock import Mock
import zipfile

import pytest
from app.config.settings import settings
from app.models.project import Project, Target, ScanJob
from app.models.repository import Repository
from app.repositories.storage import repository_directory
from app.workers.ingestion_jobs import ingest_zip_repository
from app.workers.recovery_jobs import recover_stale_jobs


@pytest.fixture
def ingestion_context(monkeypatch, tmp_path, client, test_user_token, test_db, test_user):
    monkeypatch.setattr(settings, 'SCAN_WORKSPACE_ROOT', str(tmp_path))
    dispatch = Mock()
    monkeypatch.setattr(ingest_zip_repository, 'apply_async', dispatch)
    project = Project(name=f'Ingestion {uuid4().hex}', owner_id=test_user.id)
    test_db.add(project)
    test_db.commit()
    target = Target(name='Local lab', project_id=project.id, url='http://localhost:8080',
                    authorization_status='APPROVED', explicit_scope='localhost', is_active=True)
    test_db.add(target)
    test_db.commit()
    headers = {'Authorization': f'Bearer {test_user_token}', 'Content-Type': 'application/zip'}
    return target, project, headers, dispatch


def archive(name='src/app.py', content=b'print("lab")'):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as bundle:
        bundle.writestr(name, content)
    return output.getvalue()


def upload(client, target, headers, body=None, authorized=True):
    return client.post(f'/api/targets/{target.id}/repositories/upload',
                       params={'name': 'Lab source', 'source_authorized': authorized},
                       headers=headers, content=body if body is not None else archive())


def test_upload_and_ingestion_preserve_provenance_and_ownership(ingestion_context, client, test_db, test_user_2_token):
    target, project, headers, dispatch = ingestion_context
    response = upload(client, target, headers)
    assert response.status_code == 202, response.text
    repository_id, job_id = response.json()['repository_id'], response.json()['job_id']
    dispatch.assert_called_once()
    repository = test_db.query(Repository).filter(Repository.id == repository_id).one()
    assert repository.project_id == project.id
    assert repository.ingestion_status == 'QUEUED'
    assert repository.analysis_status == 'NOT_STARTED'
    result = ingest_zip_repository(job_id)
    assert result.startswith('Success')
    test_db.refresh(repository)
    assert repository.ingestion_status == 'READY'
    assert repository.file_count == 1
    assert (repository_directory(settings.SCAN_WORKSPACE_ROOT, repository_id) / 'source/src/app.py').read_bytes() == b'print("lab")'
    job = test_db.query(ScanJob).filter(ScanJob.id == job_id).one()
    test_db.refresh(job)
    assert job.status == 'COMPLETED'
    assert job.result_summary['archive_sha256'] == repository.archive_sha256
    assert 'Aborted' in ingest_zip_repository(job_id)  # duplicate does not extract again
    assert client.get(f'/api/repositories/{repository_id}', headers=headers).status_code == 200
    other = {'Authorization': f'Bearer {test_user_2_token}'}
    assert client.get(f'/api/repositories/{repository_id}', headers=other).status_code == 404
    assert client.get(f'/api/repositories?project_id={project.id}', headers=other).json() == []
    assert client.get(f'/api/jobs/{job_id}', headers=other).status_code == 404


def test_upload_rejects_unapproved_scope_and_cross_user(ingestion_context, client, test_user_2_token, test_db):
    target, _, headers, dispatch = ingestion_context
    other = {**headers, 'Authorization': f'Bearer {test_user_2_token}'}
    assert upload(client, target, other).status_code == 404
    target.authorization_status = 'PENDING'
    test_db.commit()
    assert upload(client, target, headers).status_code == 403
    target.authorization_status = 'APPROVED'
    target.explicit_scope = 'different.test'
    test_db.commit()
    assert upload(client, target, headers).status_code == 403
    dispatch.assert_not_called()


def test_upload_requires_source_permission_and_valid_zip(ingestion_context, client):
    target, _, headers, dispatch = ingestion_context
    assert upload(client, target, headers, authorized=False).status_code == 403
    assert upload(client, target, headers, body=b'not zip').status_code == 400
    assert upload(client, target, {**headers, 'Content-Type': 'application/json'}).status_code == 415
    assert list(Path(settings.SCAN_WORKSPACE_ROOT).glob('repositories/*')) == []
    dispatch.assert_not_called()


def test_size_limit_with_and_without_content_length(ingestion_context, client, monkeypatch):
    target, _, headers, dispatch = ingestion_context
    monkeypatch.setattr(settings, 'ZIP_MAX_UPLOAD_BYTES', 100)
    assert upload(client, target, headers).status_code == 413
    response = client.post(f'/api/targets/{target.id}/repositories/upload',
                           params={'name': 'Lab', 'source_authorized': True}, headers=headers,
                           content=iter([b'x' * 80, b'x' * 80]))
    assert response.status_code == 413
    assert list(Path(settings.SCAN_WORKSPACE_ROOT).glob('repositories/*')) == []
    dispatch.assert_not_called()


def test_malicious_zip_fails_persistently_without_extracting(ingestion_context, client, test_db):
    target, _, headers, _ = ingestion_context
    response = upload(client, target, headers, body=archive('../escape.txt', b'dummy'))
    assert response.status_code == 202
    job_id, repository_id = response.json()['job_id'], response.json()['repository_id']
    with pytest.raises(RuntimeError, match='unsafe path'):
        ingest_zip_repository(job_id)
    job = test_db.query(ScanJob).filter(ScanJob.id == job_id).one()
    repository = test_db.query(Repository).filter(Repository.id == repository_id).one()
    assert job.status == 'FAILED' and repository.ingestion_status == 'FAILED'
    assert repository.failure_code == 'UNSAFE_PATH'
    assert not (Path(settings.SCAN_WORKSPACE_ROOT) / 'escape.txt').exists()
    assert not (repository_directory(settings.SCAN_WORKSPACE_ROOT, repository_id) / 'source').exists()


def test_revocation_before_ingestion_and_disabled_user(ingestion_context, client, test_db, test_user):
    target, _, headers, _ = ingestion_context
    response = upload(client, target, headers)
    target.authorization_status = 'REJECTED'
    test_db.commit()
    with pytest.raises(RuntimeError, match='authorization'):
        ingest_zip_repository(response.json()['job_id'])
    target.authorization_status = 'APPROVED'
    test_db.commit()
    response = upload(client, target, headers)
    try:
        test_user.is_active = False
        test_db.commit()
        with pytest.raises(RuntimeError, match='authorization'):
            ingest_zip_repository(response.json()['job_id'])
    finally:
        test_user.is_active = True
        test_db.commit()


def test_broker_failure_tracks_failed_repository(ingestion_context, client, test_db):
    target, _, headers, dispatch = ingestion_context
    dispatch.side_effect = ConnectionError('dummy sensitive broker exception')
    response = upload(client, target, headers)
    assert response.status_code == 503
    assert 'sensitive' not in response.text
    identifiers = response.json()['detail']
    job = test_db.query(ScanJob).filter(ScanJob.id == identifiers['job_id']).one()
    repository = test_db.query(Repository).filter(Repository.id == identifiers['repository_id']).one()
    assert job.status == 'FAILED'
    assert repository.ingestion_status == 'FAILED'
    assert 'Aborted' in ingest_zip_repository(str(job.id))


def test_ambiguous_dispatch_failure_does_not_overwrite_completed_job(ingestion_context, client, test_db):
    target, _, headers, dispatch = ingestion_context
    def acknowledged_late(args, task_id):
        ingest_zip_repository(args[0])
        raise ConnectionError('broker acknowledgement lost')
    dispatch.side_effect = acknowledged_late
    response = upload(client, target, headers)
    assert response.status_code == 503
    repository_id = response.json()['detail']['repository_id']
    repository = test_db.query(Repository).filter(Repository.id == repository_id).one()
    test_db.refresh(repository)
    assert repository.ingestion_status == 'READY'


def test_recovery_fails_stale_ingestion_preserves_completed_and_recent(ingestion_context, client, test_db):
    target, _, headers, _ = ingestion_context
    first = upload(client, target, headers).json()
    ingest_zip_repository(first['job_id'])
    second = upload(client, target, headers).json()
    stale = test_db.query(ScanJob).filter(ScanJob.id == second['job_id']).one()
    stale.created_at = datetime.utcnow() - timedelta(minutes=20)
    test_db.commit()
    recover_stale_jobs()
    test_db.refresh(stale)
    assert stale.status == 'FAILED'
    completed = test_db.query(ScanJob).filter(ScanJob.id == first['job_id']).one()
    assert completed.status == 'COMPLETED'
    repository = test_db.query(Repository).filter(Repository.id == second['repository_id']).one()
    assert repository.ingestion_status == 'FAILED'
    assert 'Aborted' in ingest_zip_repository(second['job_id'])


def test_repository_quota_is_enforced(ingestion_context, client, monkeypatch):
    target, _, headers, _ = ingestion_context
    count = client.get('/api/repositories', headers=headers).json()
    monkeypatch.setattr(settings, 'REPOSITORY_LIMIT_PER_USER', len(count) + 1)
    response = upload(client, target, headers)
    assert response.status_code == 202
    assert upload(client, target, headers).status_code == 409


def test_worker_models_initialize_in_fresh_process():
    result = subprocess.run([sys.executable, '-c',
        'from app.workers.celery_app import celery; '
        'from sqlalchemy.orm import configure_mappers; configure_mappers(); '
        'assert "app.workers.ingestion_jobs" in celery.conf.include'],
        capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
