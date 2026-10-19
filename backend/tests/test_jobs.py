import pytest
import uuid
from app.models.project import Target, ScanJob
from app.workers.diagnostic_jobs import run_diagnostic_job
from app.workers.scan_jobs import run_security_scan

def create_test_project_and_target(db, user):
    from app.models.project import Project, Target
    project = Project(name="Job Test Project", owner_id=user.id)
    db.add(project)
    db.commit()
    db.refresh(project)
    
    target = Target(
        project_id=project.id, 
        name="Job Test Target", 
        url="http://test.com",
        explicit_scope="test.com"
    )
    db.add(target)
    db.commit()
    db.refresh(target)
    return project, target

def test_job_ownership_and_unauthorized_access(client, test_user_token, test_user_2_token, test_db, test_user, test_user_2):
    project, target = create_test_project_and_target(test_db, test_user)
    
    # User 2 tries to submit job
    response = client.post(f"/api/targets/{target.id}/jobs?job_type=DIAGNOSTIC", headers={"Authorization": f"Bearer {test_user_2_token}"})
    assert response.status_code in (403, 404)
    
    # User 1 tries to list jobs (should only see their own)
    job = ScanJob(target_id=target.id, requesting_user_id=test_user.id, job_type="DIAGNOSTIC", status="QUEUED")
    test_db.add(job)
    test_db.commit()
    
    res1 = client.get("/api/jobs", headers={"Authorization": f"Bearer {test_user_token}"})
    assert len(res1.json()) >= 1
    
    res2 = client.get("/api/jobs", headers={"Authorization": f"Bearer {test_user_2_token}"})
    assert len(res2.json()) == 0

def test_successful_diagnostic_lifecycle(test_db, test_user):
    project, target = create_test_project_and_target(test_db, test_user)
    # Approve target
    target.authorization_status = "APPROVED"
    target.is_active = True
    test_db.commit()
    
    job = ScanJob(target_id=target.id, requesting_user_id=test_user.id, job_type="DIAGNOSTIC", status="QUEUED")
    test_db.add(job)
    test_db.commit()
    
    # Run diagnostic directly via worker
    run_diagnostic_job(str(job.id))
    
    # Verify status
    test_db.refresh(job)
    assert job.status == "COMPLETED"
    assert job.current_stage == "COMPLETED"
    assert job.message == "The diagnostic succeeded."

def test_authorization_revoked_before_execution(test_db, test_user):
    project, target = create_test_project_and_target(test_db, test_user)
    target.authorization_status = "REJECTED"
    test_db.commit()
    
    job = ScanJob(target_id=target.id, requesting_user_id=test_user.id, job_type="DIAGNOSTIC", status="QUEUED")
    test_db.add(job)
    test_db.commit()
    
    with pytest.raises(Exception, match="Authorization revoked"):
        run_diagnostic_job(str(job.id))
        
    test_db.refresh(job)
    assert job.status == "FAILED"
    assert job.current_stage == "ERROR"

def test_duplicate_delivery(test_db, test_user):
    project, target = create_test_project_and_target(test_db, test_user)
    target.authorization_status = "APPROVED"
    test_db.commit()
    
    job = ScanJob(target_id=target.id, requesting_user_id=test_user.id, job_type="DIAGNOSTIC", status="RUNNING")
    test_db.add(job)
    test_db.commit()
    
    # Should abort and not raise an exception
    result = run_diagnostic_job(str(job.id))
    assert "Aborted" in result
