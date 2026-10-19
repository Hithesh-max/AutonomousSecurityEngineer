"""Offline regressions for project isolation, Suite contracts and safe static checks."""
import base64
import json
from types import SimpleNamespace
from uuid import uuid4
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.api.auth import get_current_user
from app.config.database import get_db
from app.models import Project, Finding
from app.api_testing.openapi_parser import parse_openapi_spec
from app.api_testing import authorization_checker as checker
from app.collaboration.node_transfer import derive_node_key, encrypt_payload, decrypt_and_verify_payload
from app.verification import runner
from test_remediation_workflow import setup, propose


@pytest.fixture
def client(setup):
    app.dependency_overrides[get_current_user] = lambda: setup.user
    app.dependency_overrides[get_db] = lambda: setup.db
    with TestClient(app) as c: yield c
    app.dependency_overrides.clear()


def test_findings_project_repository_and_owner_scope(setup, client):
    s=setup
    lab=Project(name='ASE Lab',owner_id=s.user.id)
    private=Project(name='other-user-project',owner_id=s.other.id)
    s.db.add_all([lab,private]);s.db.commit()
    for p in [lab,private]:
        s.db.add(Finding(project_id=p.id,title=p.name,source='DAST',status='OPEN',severity='HIGH',fingerprint=uuid4().hex))
    s.db.commit()
    r=client.get('/api/findings',params={'project_id':str(s.repo.project_id)})
    assert r.status_code==200
    assert {f['title'] for f in r.json()}=={f.title for f in s.findings}|{s.secret.title}
    r=client.get('/api/findings',params={'project_id':str(lab.id),'repository_id':str(s.repo.id)})
    assert r.json()==[]
    assert client.get('/api/findings',params={'project_id':str(private.id)}).json()==[]
    assert client.get('/api/findings',params={'project_id':str(uuid4())}).json()==[]


def test_null_correlation_and_native_contract(client, setup):
    from app.evaluation.metrics import correlate_cross_tool_findings
    result=correlate_cross_tool_findings([{'source_location':None,'endpoint':None,'source_tools':None}])
    assert result['total_locations']==1
    r=client.get(f'/api/projects/{setup.repo.project_id}/cross-tool-correlation')
    assert r.status_code==200
    assert 'correlated_items' in r.json()


def test_benchmark_declares_heuristics(client):
    r=client.post('/api/evaluation/evaluate')
    assert r.status_code==200
    assert r.json()['evaluation_mode']=='SYNTHETIC_STRING_HEURISTICS'
    assert 'f1_score' in r.json()['metrics']
    assert any('No Semgrep' in x for x in r.json()['sample_limitations'])


def test_openapi_import_roundtrip_json_and_yaml(client, setup):
    for content in [json.dumps({'openapi':'3.0.0','info':{'title':'My API','version':'1'},'paths':{}}), 'openapi: 3.0.0\ninfo:\n  title: My API\n  version: "1"\npaths: {}\n']:
        r=client.post(f'/api/projects/{setup.repo.project_id}/openapi-import',files={'file':('spec.yaml',content,'application/yaml')})
        assert r.status_code==200, r.text
        assert r.json()['title']=='My API'
        assert r.json()['total_endpoints']==0


@pytest.mark.parametrize('document', ['[]','{}','{"openapi":"3.0.0","paths":[]}','{"openapi":"3.0.0","info":"oops"}'])
def test_bad_spec_is_validation_error(document):
    with pytest.raises(ValueError):parse_openapi_spec(document)


def test_api_auth_requires_actual_spec(client, setup):
    r=client.post(f'/api/projects/{setup.repo.project_id}/api-auth-test',params={'target_id':str(setup.repo.target_id)})
    assert r.status_code==400
    assert 'actual OpenAPI' in r.json()['detail']


def test_auth_checks_are_read_only_and_require_successful_control(monkeypatch):
    monkeypatch.setattr(checker,'resolve_and_verify_destination',lambda u,s: '93.184.216.34')
    calls=[]
    def probe(url, method, headers, **kw):
        calls.append((url,method))
        return {'status_code':404, 'body_sha256':None}
    monkeypatch.setattr(checker,'execute_auth_probe',probe)
    endpoints=[{'path':'/users/{id}','method':'GET','bola_candidate':True,'security_required':True},
               {'path':'/admin/users','method':'DELETE','bfla_candidate':True,'security_required':True}]
    users={'USER_A':{'token':'a','resource_id':'existing-user-a'},'USER_B':{'token':'b'},'ADMIN':{'token':'admin'}}
    r=checker.run_authorization_tests('https://example.com',endpoints,users,'example.com')
    assert r['inconclusive_count']==2 and r['secure_count']==0
    assert len(calls)==1 and calls[0][1]=='GET'
    assert 'existing-user-a' in calls[0][0]
    with pytest.raises(ValueError):checker.run_authorization_tests('https://example.com',endpoints,{},'example.com')


def test_auth_access_alert_is_not_verified_vulnerability(monkeypatch):
    monkeypatch.setattr(checker,'resolve_and_verify_destination',lambda u,s:'93.184.216.34')
    monkeypatch.setattr(checker,'execute_auth_probe',lambda *a,**k:{'status_code':200,'body_sha256':'same'})
    r=checker.run_authorization_tests('https://example.com',[{'path':'/users/{id}','method':'GET','bola_candidate':True,'security_required':True}],{'USER_A':{'token':'a','resource_id':'owner'},'USER_B':{'token':'b'},'ADMIN':{'token':'c'}},'example.com')
    assert r['results'][0]['status']=='ACCESS_GRANTED_REVIEW_REQUIRED'


def test_empty_verification_has_actionable_error(client, setup):
    r=client.post(f'/api/repositories/{setup.repo.id}/verify')
    assert r.status_code==409 and 'No approved patches' in r.json()['detail']


def test_combined_verification_never_executes_or_claims_fix(setup, client, monkeypatch):
    s=setup
    for f in s.findings:propose(s,f)
    monkeypatch.setattr(runner,'reanalyze',lambda root, fs:{'status':'COMPLETED','findings':[]})
    monkeypatch.setattr(runner,'run_bounded_process',lambda *a,**k:pytest.fail('Uploaded code executed'))
    before=(s.directory/'source/src/app.py').read_bytes()
    r=client.post(f'/api/repositories/{s.repo.id}/verify')
    assert r.status_code==200,r.text
    result=r.json()
    assert result['overall_status']=='INCONCLUSIVE'
    assert len(result['applied_files'])==1
    assert len(result['applied_files']['src/app.py']['patch_ids'])==2
    assert result['build_result']['status']=='NOT_RUN'
    assert all(e['status']=='INCONCLUSIVE' for e in result['finding_evaluations'])
    assert (s.directory/'source/src/app.py').read_bytes()==before


def test_tampered_approved_patch_is_rejected(setup, client):
    p=propose(setup,setup.findings[0]);p.patch_sha256='f'*64;setup.db.commit()
    r=client.post(f'/api/repositories/{setup.repo.id}/verify')
    assert r.status_code==409


def test_components_are_detected_without_execution(tmp_path):
    (tmp_path/'frontend').mkdir();(tmp_path/'backend').mkdir()
    (tmp_path/'frontend/package.json').write_text('{}')
    (tmp_path/'backend/requirements.txt').write_text('')
    assert runner.detect_project_runner(tmp_path)['runner_type']=='MULTI_COMPONENT'
    with pytest.raises(RuntimeError):runner.run_bounded_process(['echo','no'],tmp_path)


@pytest.mark.parametrize('media',['TEXT','IMAGE','AUDIO','VIDEO'])
def test_transfer_contract_and_binary_roundtrip(client, media):
    data=b'\x00\xff\x80hello' if media!='TEXT' else 'Hello 🌍'.encode()
    secret='test-only-shared-secret-with-32-chars'
    r=client.post('/api/collaboration/node-transfer',json={'sender_node':'NODE_A','receiver_node':'NODE_B','media_type':media,'payload_b64':base64.b64encode(data).decode(),'shared_key_seed':secret})
    assert r.status_code==201,r.text
    packet=r.json()
    r=client.post('/api/collaboration/node-receive',json={'packet':packet,'shared_key_seed':secret})
    assert r.status_code==200,r.text
    assert base64.b64decode(r.json()['payload_b64'])==data
    packet['receiver_node']='ATTACKER'
    assert client.post('/api/collaboration/node-receive',json={'packet':packet,'shared_key_seed':secret}).status_code==403


def test_transfer_cannot_be_decrypted_by_another_account(client, setup):
    secret='test-only-shared-secret-with-32-chars'
    packet=client.post('/api/collaboration/node-transfer',json={'sender_node':'NODE_A','receiver_node':'NODE_B','media_type':'TEXT','payload_b64':'aGVsbG8=','shared_key_seed':secret}).json()
    app.dependency_overrides[get_current_user]=lambda:setup.other
    assert client.post('/api/collaboration/node-receive',json={'packet':packet,'shared_key_seed':secret}).status_code==403
    assert client.get('/api/collaboration/audit-log').json()==[]


def test_security_evaluation_has_real_contract_and_no_fake_compliance(client):
    r=client.get('/api/collaboration/security-evaluation')
    assert r.status_code==200,r.text
    assert r.json()['authentication_and_accountability']['authentication_status']=='NOT_MEASURED'
    assert 'limitations' in r.json()


def test_bearer_and_basic_credentials_are_redacted():
    from app.utils.redaction import redact_string
    value = redact_string('Authorization: Bearer secret.jwt.token; Basic YWxhZGRpbjpvcGVuc2VzYW1l')
    assert 'secret.jwt.token' not in value
    assert 'YWxhZGRpbjpvcGVuc2VzYW1l' not in value


def test_pinned_connection_uses_validated_ip_without_second_dns(monkeypatch):
    seen = []
    sentinel = object()
    monkeypatch.setattr(checker.socket, 'create_connection', lambda address, timeout: (seen.append(address), sentinel)[1])
    connection = checker.PinnedHTTP('example.com', 80, '93.184.216.34', 3)
    connection.connect()
    assert seen == [('93.184.216.34', 80)]
    assert connection.host == 'example.com'
    assert connection.sock is sentinel


def test_dependency_preview_contract_and_path_boundary(client, setup):
    manifest=setup.directory/'source/requirements.txt'
    manifest.write_text('requests==2.28.0\n')
    url=f'/api/repositories/{setup.repo.id}/dependency-upgrade'
    request={'manifest_path':'requirements.txt','package_name':'requests','target_version':'2.31.0'}
    r=client.post(url,json=request)
    assert r.status_code==201,r.text
    assert r.json()['status']=='DRAFT_NOT_SAVED'
    assert r.json()['edits'][0]['replacement_text']=='requests==2.31.0'
    assert manifest.read_text()=='requests==2.28.0\n'
    request['manifest_path']='../outside/requirements.txt'
    assert client.post(url,json=request).status_code==400


def test_dependency_preview_rejects_injected_version():
    from app.supply_chain.upgrades import propose_dependency_upgrade
    with pytest.raises(ValueError):
        propose_dependency_upgrade('requirements.txt','requests==2.28.0','requests','2.31.0\nmalware==1')
