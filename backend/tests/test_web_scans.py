"""Authorization and failure paths; no simulated findings or scanner success."""
from unittest.mock import Mock
from uuid import uuid4
import pytest
from app.config.settings import settings
from app.models.project import Project, Target, ScanJob
from app.workers.web_jobs import run_web_scan

@pytest.fixture
def web_context(monkeypatch,test_db,test_user,test_user_token):
    monkeypatch.setattr(settings,'LAB_SCANNING_ENABLED',True)
    dispatch=Mock()
    monkeypatch.setattr(run_web_scan,'apply_async',dispatch)
    project=Project(name='Web lab '+uuid4().hex,owner_id=test_user.id)
    test_db.add(project);test_db.commit()
    target=Target(name='Web lab',project_id=project.id,url='http://ase-lab:8080',authorization_status='APPROVED',
                  explicit_scope='ase-lab',is_active=True,approved_by=test_user.id)
    test_db.add(target);test_db.commit()
    return project,target,{'Authorization':f'Bearer {test_user_token}'},dispatch

def test_web_scan_owner_approval_and_destination(web_context,client,test_db,test_user_2_token):
    project,target,headers,dispatch=web_context
    url=f'/api/targets/{target.id}/web-scans'
    assert client.post(url,json={},headers={'Authorization':f'Bearer {test_user_2_token}'}).status_code==404
    target.authorization_status='PENDING';test_db.commit()
    # SSRF loopback rejected with 403
    target.authorization_status='APPROVED';target.url='http://127.0.0.1:8080';target.explicit_scope='127.0.0.1';test_db.commit()
    assert client.post(url,json={},headers=headers).status_code==403
    # Out of scope rejected with 403
    target.url='http://evil.com';target.explicit_scope='example.com';test_db.commit()
    assert client.post(url,json={},headers=headers).status_code==403
    dispatch.assert_not_called()

def test_active_consent_validation_and_duplicate_jobs(web_context,client,test_db):
    project,target,headers,dispatch=web_context
    url=f'/api/targets/{target.id}/web-scans'
    for invalid in [{'active_testing':True},{'profile':'AGGRESSIVE'},{'active_testing':'true'},{'target_url':'http://outside.test'}]:
        assert client.post(url,json=invalid,headers=headers).status_code==422
    response=client.post(url,json={},headers=headers)
    assert response.status_code==202,response.text
    job=test_db.query(ScanJob).filter(ScanJob.id==response.json()['job_id']).one()
    assert job.result_summary['configuration']['active_testing'] is False
    assert job.celery_task_id
    assert client.post(url,json={},headers=headers).status_code==409
    dispatch.assert_called_once()

def test_disabled_lab_and_broker_failure(web_context,client,test_db,monkeypatch):
    project,target,headers,dispatch=web_context
    url=f'/api/targets/{target.id}/web-scans'
    monkeypatch.setattr(settings,'LAB_SCANNING_ENABLED',False)
    assert client.post(url,json={},headers=headers).status_code==503
    monkeypatch.setattr(settings,'LAB_SCANNING_ENABLED',True)
    dispatch.side_effect=RuntimeError('Queue unavailable')
    response=client.post(url,json={},headers=headers)
    assert response.status_code==503
    job=test_db.query(ScanJob).filter(ScanJob.id==response.json()['detail']['job_id']).one()
    assert job.status=='FAILED' and job.failure_code=='BROKER_SUBMISSION_FAILED'

def test_worker_rechecks_revocation_before_tools(web_context,client,test_db,monkeypatch):
    project,target,headers,dispatch=web_context
    response=client.post(f'/api/targets/{target.id}/web-scans',json={},headers=headers)
    job_id=response.json()['job_id']
    target.is_active=False;test_db.commit()
    probe=Mock(side_effect=AssertionError('Must never run'))
    monkeypatch.setattr('app.workers.web_jobs.NmapScanner.health_check',probe)
    with pytest.raises(RuntimeError,match='authorization'):run_web_scan(job_id)
    probe.assert_not_called()
    job=test_db.query(ScanJob).filter(ScanJob.id==job_id).one();test_db.refresh(job)
    assert job.status=='FAILED' and job.failure_code=='AUTHORIZATION_ERROR'
    assert 'Aborted' in run_web_scan(job_id)

def test_scan_history_and_findings_are_owned(web_context,client,test_user_2_token):
    project,target,headers,dispatch=web_context
    response=client.post(f'/api/targets/{target.id}/web-scans',json={},headers=headers)
    job_id=response.json()['job_id']
    other={'Authorization':f'Bearer {test_user_2_token}'}
    assert client.get('/api/web-scans',params={'project_id':str(project.id)},headers=other).json()==[]
    assert client.get(f'/api/web-scans/{job_id}/findings',headers=other).status_code==404
    assert client.get(f'/api/web-scans/{job_id}/findings',headers=headers).json()==[]

def test_lab_registration_is_pending_and_idempotent(web_context,client,test_db):
    project,target,headers,dispatch=web_context
    response=client.post(f'/api/projects/{project.id}/lab-target',headers=headers)
    assert response.status_code==201 and response.json()['target_id']==str(target.id)
    assert test_db.query(Target).filter(Target.project_id==project.id).count()==1
    new_project=Project(name='Pending lab',owner_id=project.owner_id)
    test_db.add(new_project);test_db.commit()
    created=client.post(f'/api/projects/{new_project.id}/lab-target',headers=headers)
    assert created.status_code==201
    registered=test_db.query(Target).filter(Target.id==created.json()['target_id']).one()
    assert registered.authorization_status=='PENDING' and registered.approved_by is None


def test_deployed_target_registration_and_scanning(web_context,client,test_db,monkeypatch):
    project,target,headers,dispatch=web_context
    # SSRF registration attempt rejected
    ssrf_resp = client.post(f'/api/projects/{project.id}/deployed-target', json={
        'name': 'SSRF Target',
        'url': 'http://127.0.0.1:8080',
        'explicit_scope': '127.0.0.1',
        'ownership_declaration': 'I claim ownership of localhost'
    }, headers=headers)
    assert ssrf_resp.status_code == 400

    # Valid external registration succeeds in PENDING status
    monkeypatch.setattr('app.network.scope.resolve_and_verify_destination', lambda url, scope: '93.184.216.34')
    resp = client.post(f'/api/projects/{project.id}/deployed-target', json={
        'name': 'Authorized App',
        'url': 'http://example.com',
        'explicit_scope': 'example.com',
        'ownership_declaration': 'I am authorized to test example.com'
    }, headers=headers)
    assert resp.status_code == 201
    tid = resp.json()['target_id']
    t = test_db.query(Target).filter(Target.id == tid).one()
    assert t.authorization_status == 'PENDING'

    # Once approved, scanning is accepted
    t.authorization_status = 'APPROVED'
    test_db.commit()
    scan_resp = client.post(f'/api/targets/{tid}/web-scans', json={}, headers=headers)
    assert scan_resp.status_code == 202

