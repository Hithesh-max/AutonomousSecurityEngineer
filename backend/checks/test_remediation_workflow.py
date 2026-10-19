"""Offline integration tests: real ORM, filesystem, archive and API; explicit mock AI.

SQLite is used only by this test harness. PostgreSQL locking/migrations and real
provider behavior still require the Docker acceptance checks in the release notes.
"""
import hashlib
import io
import json
import zipfile
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4
import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.dialects.postgresql import JSONB
from app.models.base import Base
from app.models import User, Project, Target, ScanJob, Finding, Repository
from app.models.remediation import PatchProposal, RemediationBatch
from app.config.settings import settings
from app.ai.providers import MockProvider
from app.remediation.source import locator_for, SourceUnavailable
from app.remediation.repository_source import safe_source_path
from app.remediation import service
from app.remediation.export import export_repository_zip, ExportRejected, apply_edits
from app.repositories.archive import extract_zip, ArchiveLimits
from app.repositories.storage import repository_directory
from app.api.remediation import remediation_inventory, revoke_patch, PatchDecision, corrected_source_preview


@compiles(JSONB, 'sqlite')
def _jsonb(element, compiler, **kw): return 'JSON'


@pytest.fixture
def setup(tmp_path, monkeypatch):
    engine = create_engine('sqlite:///'+str(tmp_path/'test.db'))
    @event.listens_for(engine, 'connect')
    def functions(conn, record):
        conn.create_function('hashtext',1,lambda x:1)
        conn.create_function('pg_try_advisory_xact_lock',1,lambda x:1)
    Base.metadata.create_all(engine)
    Session = sessionmaker(engine)
    db = Session()
    user = User(username='owner', hashed_password='not-a-real-login', is_active=True)
    other = User(username='other', hashed_password='not-a-real-login', is_active=True)
    db.add_all([user,other]);db.commit()
    project = Project(name='test', owner_id=user.id);db.add(project);db.commit()
    target = Target(name='source',project_id=project.id,url='http://ase-lab:8080',authorization_status='APPROVED',explicit_scope='ase-lab',is_active=True)
    db.add(target);db.commit()
    source = 'import ast\n\ndef query(db, value):\n    return db.execute("SELECT * FROM records WHERE id=" + value)\n\ndef parse(value):\n    return eval(value)\n'
    files = {'src/app.py':source.encode(), 'README.md':b'Keep this unchanged.\n', 'assets/logo.bin':b'\x80\x81\x00',
             'secrets.py':b'API_KEY = "synthetic-secret-123456"\n', '.env':b'password=synthetic-only\n'}
    buf=io.BytesIO()
    with zipfile.ZipFile(buf,'w',zipfile.ZIP_DEFLATED) as z:
        for name,content in files.items():z.writestr(name,content)
    archive=buf.getvalue();digest=hashlib.sha256(archive).hexdigest()
    repo=Repository(id=uuid4(),project_id=project.id,target_id=target.id,uploaded_by=user.id,name='fixture',source_type='ZIP',ingestion_status='READY',archive_sha256=digest,upload_bytes=len(archive),source_authorized_at=datetime.now(timezone.utc))
    db.add(repo);db.commit()
    monkeypatch.setattr(settings,'SCAN_WORKSPACE_ROOT',str(tmp_path/'workspaces'))
    directory=repository_directory(settings.SCAN_WORKSPACE_ROOT,repo.id,create=True)
    (directory/'upload.zip').write_bytes(archive);extract_zip(directory/'upload.zip',directory,ArchiveLimits())
    index=[{'path':n,'sha256':hashlib.sha256(c).hexdigest(),'is_text':True,'size':len(c),'functions':[]} for n,c in files.items()]
    job=ScanJob(repository_id=repo.id,target_id=target.id,requesting_user_id=user.id,job_type='REPOSITORY_ANALYSIS',status='COMPLETED',result_summary={'archive_sha256':digest,'intelligence':{'files':index},'tools':[{'tool':'gitleaks','status':'COMPLETED'}]})
    db.add(job);db.commit();repo.latest_analysis_job_id=job.id;db.commit()
    findings=[]
    for line,rule in [(4,'ase.python.request-to-sql'),(7,'ase.python.input-to-eval')]:
        h=hashlib.sha256(files['src/app.py']).hexdigest()
        f=Finding(project_id=project.id,repository_id=repo.id,scan_id=job.id,source='SAST',title=rule,tool_rule_id=rule,severity='HIGH',confidence='HIGH',status='OPEN',source_tools=['semgrep'],fingerprint=uuid4().hex,source_location={'file':'src/app.py','start_line':line,'end_line':line,'sha256':h},evidence={'file_sha256':h,'archive_sha256':digest})
        db.add(f);findings.append(f)
    secret=Finding(project_id=project.id,repository_id=repo.id,scan_id=job.id,source='SECRET_DETECTION',title='Exposed credential',tool_rule_id='generic-api-key',severity='HIGH',confidence='HIGH',status='OPEN',source_tools=['gitleaks'],fingerprint=uuid4().hex,source_location={'file':'secrets.py','start_line':1,'end_line':1},evidence={'secret':'[REDACTED]'})
    db.add(secret);db.commit()
    analysis={'vulnerability_type':'Injection','cwe':'CWE-89','root_cause':'Input reaches an unsafe interpreter.', 'security_impact':'Untrusted input may alter query behavior.', 'evidence_summary':'Scanner identified an unsafe source call.', 'recommended_fix':'Use a parameterized API appropriate to the application.', 'confidence':'HIGH','limitations':[]}
    def respond(system,prompt):
        if 'Return JSON matching: {"edits"' not in prompt:return json.dumps(analysis)
        line=7 if 'ase.python.input-to-eval' in prompt else 4
        before=source.splitlines()[line-1]
        after='    return ast.literal_eval(value)' if line==7 else '    return db.execute("SELECT * FROM records WHERE id=?", (value,))'
        return json.dumps({'edits':[{'start_line':line,'end_line':line,'original_text':before,'replacement_text':after}], 'explanation':'Use a bounded parser or parameter binding.', 'behavior_notes':'Review intended accepted input semantics.', 'limitations':['Fixture response from explicit mock provider.']})
    provider=MockProvider(respond);monkeypatch.setattr('app.ai.factory.get_provider',lambda:provider)
    monkeypatch.setattr(settings,'AI_MAX_REQUESTS_PER_HOUR',500)
    yield SimpleNamespace(db=db,user=user,other=other,repo=repo,job=job,findings=findings,secret=secret,directory=directory,files=files,archive=archive,provider=provider,Session=Session)
    db.close();engine.dispose()


def propose(s,f):
    a=service.analyze(s.db,s.user,f.id,True)
    p=service.generate_patch(s.db,s.user,f.id,a.id,True)
    service.decide_patch(s.db,s.user,p.id,'APPROVED',p.patch_sha256)
    return p


def test_full_two_patch_export_preserves_original_and_other_files(setup):
    s=setup
    inventory=remediation_inventory(s.repo.id,s.db,s.user)
    assert (inventory['total'],inventory['eligible'],inventory['unsupported'])==(3,2,1)
    patches=[propose(s,f) for f in s.findings]
    preview=corrected_source_preview(patches[0].id,s.db,s.user)
    assert 'id=?' in preview['content'] and 'id=" + value' in preview['original_content']
    result=export_repository_zip(s.db,s.user,s.repo.id,patches)
    with zipfile.ZipFile(io.BytesIO(result)) as z:
        assert z.testzip() is None
        code=z.read('src/app.py').decode()
        assert 'ast.literal_eval(value)' in code and 'id=?' in code
        assert z.read('README.md')==s.files['README.md']
        assert z.read('assets/logo.bin')==s.files['assets/logo.bin']
        assert 'secrets.py' not in z.namelist() and '.env' not in z.namelist()
        manifest=json.loads(z.read('ASE_REMEDIATION_MANIFEST.json'))
        assert len(manifest['changed_files'])==1
        assert manifest['verification_status']=='INCONCLUSIVE'
        assert len(manifest['findings'])==3
    assert (s.directory/'source/src/app.py').read_bytes()==s.files['src/app.py']
    assert (s.directory/'upload.zip').read_bytes()==s.archive


def test_source_owner_hash_and_secret_boundaries(setup):
    s=setup;f=s.findings[0]
    with pytest.raises(SourceUnavailable):locator_for(f).locate(s.db,f,s.other.id)
    with pytest.raises(SourceUnavailable,match='Rotate'):locator_for(s.secret).locate(s.db,s.secret,s.user.id)
    (s.directory/'source/src/app.py').write_text('changed\n')
    with pytest.raises(SourceUnavailable) as err:locator_for(f).locate(s.db,f,s.user.id)
    assert err.value.code=='SOURCE_CHANGED'


@pytest.mark.parametrize('path',['../secrets','/etc/passwd','C:/file','src\\file','src/../file','src//file'])
def test_unsafe_paths(tmp_path,path):
    with pytest.raises(SourceUnavailable):safe_source_path(tmp_path,path)


def test_symlink_parent(tmp_path):
    try:
        (tmp_path/'alias').symlink_to(tmp_path,target_is_directory=True)
    except OSError:
        pytest.skip("Symlink creation requires elevated privilege on Windows")
    (tmp_path/'file.py').write_text('x=1')
    with pytest.raises(SourceUnavailable):safe_source_path(tmp_path,'alias/file.py')


def test_approval_hash_cross_user_and_revocation(setup):
    s=setup;p=propose(s,s.findings[0])
    with pytest.raises(service.RemediationError):service.get_owned_patch(s.db,p.id,s.other)
    with pytest.raises(service.RemediationError):service.decide_patch(s.db,s.user,p.id,'APPROVED',p.patch_sha256)
    revoke_patch(p.id,PatchDecision(patch_sha256=p.patch_sha256),s.db,s.user)
    with pytest.raises(ExportRejected):export_repository_zip(s.db,s.user,s.repo.id,[p])


def test_tampered_patch_and_archive_rejected(setup):
    s=setup;p=propose(s,s.findings[0]);old=p.patch_sha256
    p.patch_sha256='0'*64;s.db.commit()
    with pytest.raises(ExportRejected):export_repository_zip(s.db,s.user,s.repo.id,[p])
    p.patch_sha256=old;s.db.commit();(s.directory/'upload.zip').write_bytes(b'changed')
    with pytest.raises(ExportRejected):export_repository_zip(s.db,s.user,s.repo.id,[p])


def test_overlap_rejected():
    e={'start_line':1,'end_line':1,'replacement_text':'x=2'}
    with pytest.raises(ExportRejected):apply_edits(['x=1'],[e,e])


def test_batch_checkpoints_resume_and_preserve(setup,monkeypatch):
    from app.workers import remediation_batch as worker
    s=setup;monkeypatch.setattr(worker,'SessionLocal',s.Session)
    queued=[];monkeypatch.setattr(worker,'dispatch',lambda id:queued.append(id))
    b=RemediationBatch(repository_id=s.repo.id,scan_id=s.job.id,requested_by=s.user.id,status='QUEUED',mode='PROPOSE',consent=True,cursor=0,items=[{'finding_id':str(f.id),'title':f.title,'status':'PENDING'} for f in [*s.findings,s.secret]])
    s.db.add(b);s.db.commit()
    for expected in [1,2,3]:
        worker.process_one(b.id);s.db.refresh(b);assert b.cursor==expected
    assert b.status=='COMPLETED'
    assert [i['status'] for i in b.items]==['PROPOSED','PROPOSED','SKIPPED']
    assert s.db.query(PatchProposal).count()==2
    worker.process_one(b.id)
    assert s.db.query(PatchProposal).count()==2


def test_external_consent_enforced(setup):
    s=setup;s.provider.is_external=True
    with pytest.raises(service.RemediationError) as error:service.analyze(s.db,s.user,s.findings[0].id,False)
    assert error.value.code=='EXTERNAL_TRANSMISSION_NOT_CONFIRMED'
    assert not s.provider.calls


@pytest.mark.parametrize('path,good,bad',[
    ('a.py','x = 1\n','x = (\n'),('a.json','{"x":1}','{"x":}'),
    ('a.js','const x = JSON.parse(value);','const = ;'),
    ('a.ts','const x: number = 1;','const x: = ;'),
    ('a.tsx','const x = <p>Hello</p>;','const x = <p>;'),
    ('A.java','class A { int x = 1; }','class {'),
    ('a.c','int main(void) { return 0; }','int main( {'),
    ('a.cpp','class A { public: int x; };','class {'),
    ('a.css','a { color: red; }','a { color: ; ??? }'),
    ('a.html','<div>Hello</div>','<div><!???')])
def test_language_specific_parsing(path,good,bad):
    from app.remediation.languages import syntax_check
    assert syntax_check(path,good)['status']=='PASS'
    assert syntax_check(path,bad)['status']=='FAIL'


def test_unsupported_language_never_python_parsed():
    from app.remediation.languages import syntax_check
    assert syntax_check('query.sql','SELECT 1;')['status']=='NOT_SUPPORTED'


def test_secret_in_same_file_blocks_transmission(setup):
    s=setup;s.secret.source_location={'file':'src/app.py'};s.db.commit()
    with pytest.raises(SourceUnavailable):locator_for(s.findings[0]).locate(s.db,s.findings[0],s.user.id)
    a=service.analyze(s.db,s.user,s.findings[0].id,True)
    assert a.source_sha256 is None
    assert all('return db.execute' not in prompt for _,prompt in s.provider.calls)


def test_quota_pause_is_resumable_without_skipping_finding(setup,monkeypatch):
    from app.workers import remediation_batch as worker
    s=setup;monkeypatch.setattr(worker,'SessionLocal',s.Session)
    original=service.analyze
    def quota(*args,**kwargs):raise service.RemediationError(429,'AI_RATE_LIMITED','Quota reached.')
    monkeypatch.setattr(service,'analyze',quota)
    b=RemediationBatch(repository_id=s.repo.id,scan_id=s.job.id,requested_by=s.user.id,status='QUEUED',mode='PROPOSE',consent=True,cursor=0,items=[{'finding_id':str(s.findings[0].id),'title':'SQL','status':'PENDING'}])
    s.db.add(b);s.db.commit();worker.process_one(b.id);s.db.refresh(b)
    assert b.status=='PAUSED' and b.cursor==0
    monkeypatch.setattr(service,'analyze',original);b.status='QUEUED';s.db.commit()
    worker.process_one(b.id);s.db.refresh(b)
    assert b.status=='COMPLETED' and b.cursor==1


def test_http_review_export_and_access(setup):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from app.api.remediation import router
    from app.api.auth import get_current_user
    from app.config.database import get_db
    s=setup;app=FastAPI();app.include_router(router,prefix='/api')
    app.dependency_overrides[get_current_user]=lambda:s.user
    app.dependency_overrides[get_db]=lambda:s.db
    with TestClient(app) as client:
        inventory=client.get(f'/api/repositories/{s.repo.id}/remediation-inventory')
        assert inventory.status_code==200 and inventory.json()['eligible']==2
        f=s.findings[0]
        response=client.post(f'/api/findings/{f.id}/analysis',json={'acknowledge_external_transmission':True})
        assert response.status_code==201
        response=client.post(f'/api/findings/{f.id}/patches',json={'analysis_id':response.json()['id'],'acknowledge_external_transmission':True})
        assert response.status_code==201
        p=response.json()
        assert client.get(f'/api/patches/{p["id"]}/corrected-source').status_code==200
        assert client.post(f'/api/patches/{p["id"]}/approve',json={'patch_sha256':p['patch_sha256']}).status_code==200
        response=client.get(f'/api/repositories/{s.repo.id}/corrected-zip?all_approved=true')
        assert response.status_code==200
        assert response.headers['content-type']=='application/zip'
        with zipfile.ZipFile(io.BytesIO(response.content)) as z:assert z.testzip() is None
        report=client.get(f'/api/repositories/{s.repo.id}/remediation-report')
        assert report.status_code==200 and any(e['event']=='PATCH_EXPORTED' for e in report.json()['audit_history'])
        app.dependency_overrides[get_current_user]=lambda:s.other
        assert client.get(f'/api/patches/{p["id"]}/corrected-source').status_code==404
        assert client.get(f'/api/repositories/{s.repo.id}/corrected-zip?all_approved=true').status_code==404


@pytest.mark.parametrize('command,allowed',[
    ('subprocess.run(["ping", "--", host], shell=False, timeout=5)',True),
    ('subprocess.run(["sh", "-c", value], shell=False, timeout=5)',False),
    ('subprocess.run([value], shell=False, timeout=5)',False),
    ('subprocess.run(["ping", host], shell=True, timeout=5)',False),
    ('subprocess.run(["ping", host], shell=False)',False),
    ('subprocess.run(["ping", host], shell=False, timeout=500)',False),
    ('subprocess.run(["ping", host], shell=False, timeout=5, **options)',False),
])
def test_command_policy(command,allowed):
    from app.remediation.process_policy import safe_process_edit
    assert safe_process_edit(command) is allowed


def test_safe_shell_fix_parses_and_unsafe_command_does_not():
    from app.remediation.source import SourceContext
    from app.remediation.patching import validate_and_render, PatchRejected
    from app.ai.schemas import ModelPatch
    before='    return subprocess.run(["ping", host], shell=True)'
    lines=('import subprocess','def ping(host):',before)
    source=SourceContext('MANAGED_REPOSITORY','network.py',1,3,3,lines,'0'*64,'VERIFIED_SOURCE','fixture')
    def patch(text):return ModelPatch(edits=[dict(start_line=3,end_line=3,original_text=before,replacement_text=text)],explanation='Use fixed argv, disable shell and bound runtime.')
    result=validate_and_render(source,patch('    return subprocess.run(["ping", "--", host], shell=False, timeout=5)'))
    assert result.checks['syntax_valid']['status']=='PASS'
    with pytest.raises(PatchRejected):validate_and_render(source,patch('    return subprocess.run([host], shell=False, timeout=5)'))


def test_http_batch_pause_resume_and_foreign_access(setup,monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from app.api.remediation import router
    from app.api.auth import get_current_user
    from app.config.database import get_db
    from app.workers import remediation_batch as worker
    s=setup;monkeypatch.setattr(worker,'dispatch',lambda id:True)
    app=FastAPI();app.include_router(router,prefix='/api')
    app.dependency_overrides[get_db]=lambda:s.db
    app.dependency_overrides[get_current_user]=lambda:s.user
    with TestClient(app) as c:
        r=c.post(f'/api/repositories/{s.repo.id}/remediation-batches',json={'mode':'PROPOSE','acknowledge_external_transmission':True})
        assert r.status_code==202,r.text
        batch=r.json()
        assert batch['total']==3 and batch['status']=='QUEUED'
        assert c.post(f'/api/repositories/{s.repo.id}/remediation-batches',json={'mode':'PROPOSE'}).status_code==409
        assert c.post(f'/api/remediation-batches/{batch["id"]}/pause').json()['status']=='PAUSED'
        assert c.post(f'/api/remediation-batches/{batch["id"]}/resume').json()['status']=='QUEUED'
        app.dependency_overrides[get_current_user]=lambda:s.other
        assert c.post(f'/api/remediation-batches/{batch["id"]}/pause').status_code==404


def test_changed_manifest_and_missing_secret_scan(setup):
    s=setup
    summary=dict(s.job.result_summary);summary['archive_sha256']='0'*64;s.job.result_summary=summary;s.db.commit()
    with pytest.raises(SourceUnavailable) as e:locator_for(s.findings[0]).locate(s.db,s.findings[0],s.user.id)
    assert e.value.code=='SOURCE_CHANGED'
    summary['archive_sha256']=s.repo.archive_sha256;summary['tools']=[];s.job.result_summary=dict(summary);s.db.commit()
    with pytest.raises(SourceUnavailable) as e:locator_for(s.findings[0]).locate(s.db,s.findings[0],s.user.id)
    assert e.value.code=='MANUAL_REVIEW_REQUIRED'


def test_approval_conflict_detected_before_export(setup):
    s=setup;first=propose(s,s.findings[0])
    # Propose another correction for the same exact source occurrence.
    analysis=service.analyze(s.db,s.user,s.findings[0].id,True)
    second=service.generate_patch(s.db,s.user,s.findings[0].id,analysis.id,True)
    with pytest.raises(service.RemediationError) as e:service.decide_patch(s.db,s.user,second.id,'APPROVED',second.patch_sha256)
    assert e.value.code=='PATCH_CONFLICT'
    assert first.status=='APPROVED'


def test_export_refreshes_cached_approval_after_revocation(setup):
    s=setup;p=propose(s,s.findings[0]);patch_id=p.id
    with s.Session() as other_session:
        other=other_session.get(PatchProposal,patch_id)
        other.status='REJECTED';other.approved_by=None;other.approved_at=None
        other_session.commit()
    assert p.status=='APPROVED'  # deliberately stale identity-map row
    with pytest.raises(ExportRejected):export_repository_zip(s.db,s.user,s.repo.id,[p])


def test_hourly_request_budget_preserves_completed_analysis(setup,monkeypatch):
    s=setup;monkeypatch.setattr(settings,'AI_MAX_REQUESTS_PER_HOUR',1)
    analysis=service.analyze(s.db,s.user,s.findings[0].id,True)
    with pytest.raises(service.RemediationError) as e:
        service.generate_patch(s.db,s.user,s.findings[0].id,analysis.id,True)
    assert e.value.code=='AI_RATE_LIMITED'
    assert len(s.provider.calls)==1
    assert analysis.status=='COMPLETED'
