import pytest
from app.models.user import User
from app.models.project import Project, Target
from app.workers.scan_jobs import run_security_scan
import uuid
import os

def test_unauthenticated_access(client):
    response = client.get("/api/projects")
    assert response.status_code == 401
    
    response = client.post("/api/projects", json={"name": "Test"})
    assert response.status_code == 401

def test_cross_user_access(client, test_db, test_user_token, test_user_2_token, test_user):
    # Create project with user 1
    response = client.post("/api/projects", json={"name": "User 1 Project"}, headers={"Authorization": f"Bearer {test_user_token}"})
    assert response.status_code == 200
    p1_id = response.json()["id"]
    
    # Try to view with user 2
    res2 = client.get("/api/projects", headers={"Authorization": f"Bearer {test_user_2_token}"})
    assert len(res2.json()) == 0
    
    # User 2 tries to add target to user 1 project
    res_target = client.post("/api/targets", json={"project_id": p1_id, "name": "T", "url": "http://x"}, headers={"Authorization": f"Bearer {test_user_2_token}"})
    assert res_target.status_code == 403

def test_target_auth_states_blocked(client, test_db, test_user_token):
    # Setup project and target
    p_res = client.post("/api/projects", json={"name": "Proj"}, headers={"Authorization": f"Bearer {test_user_token}"})
    p_id = p_res.json()["id"]
    t_res = client.post("/api/targets", json={"project_id": p_id, "name": "T1", "url": "http://example.com"}, headers={"Authorization": f"Bearer {test_user_token}"})
    t_id = t_res.json()["id"]
    
    # 1. PENDING is blocked
    scan_res = client.post(f"/api/targets/{t_id}/jobs?job_type=SECURITY_SCAN", headers={"Authorization": f"Bearer {test_user_token}"})
    assert scan_res.status_code == 403
    assert "Target is not approved" in scan_res.json()["detail"]
    
    # 2. Approve it
    client.post(f"/api/targets/{t_id}/approve?scope=example.com", headers={"Authorization": f"Bearer {test_user_token}"})
    scan_res_approved = client.post(f"/api/targets/{t_id}/jobs?job_type=SECURITY_SCAN", headers={"Authorization": f"Bearer {test_user_token}"})
    assert scan_res_approved.status_code == 200
    
    # 3. Revoke it
    client.post(f"/api/targets/{t_id}/revoke", headers={"Authorization": f"Bearer {test_user_token}"})
    scan_res_revoked = client.post(f"/api/targets/{t_id}/jobs?job_type=SECURITY_SCAN", headers={"Authorization": f"Bearer {test_user_token}"})
    assert scan_res_revoked.status_code == 403

def test_worker_rejection_after_submission(test_db):
    u = test_db.query(User).filter(User.username == "worker_test").first()
    if not u:
        u = User(username="worker_test", hashed_password="pw")
        test_db.add(u)
        test_db.commit()
    
    p = Project(name="WP", owner_id=u.id)
    test_db.add(p)
    test_db.commit()
    
    t = Target(project_id=p.id, name="WT", url="http://example.com", authorization_status="APPROVED", is_active=True, explicit_scope="example.com")
    test_db.add(t)
    test_db.commit()
    
    from app.models.project import ScanJob
    job = ScanJob(target_id=t.id, requesting_user_id=u.id, job_type="SECURITY_SCAN", status="QUEUED")
    test_db.add(job)
    test_db.commit()
    
    # Suppose scan is submitted and queued. Before worker picks it up, target is revoked.
    t.authorization_status = "REJECTED"
    t.is_active = False
    test_db.commit()
    
    # Worker executes
    with pytest.raises(PermissionError, match="Authorization revoked"):
        run_security_scan(str(job.id))

def test_missing_repository_workspace_reported(test_db, caplog, monkeypatch):
    import logging
    u = test_db.query(User).filter(User.username == "repo_test").first()
    if not u:
        u = User(username="repo_test", hashed_password="pw")
        test_db.add(u)
        test_db.commit()
    
    p = Project(name="RP", owner_id=u.id)
    test_db.add(p)
    test_db.commit()
    
    # Target with NO repo_url
    t = Target(project_id=p.id, name="RT", url="http://example.com", authorization_status="APPROVED", is_active=True, explicit_scope="example.com")
    test_db.add(t)
    test_db.commit()
    
    from app.models.project import ScanJob
    job = ScanJob(target_id=t.id, requesting_user_id=u.id, job_type="SECURITY_SCAN", status="QUEUED")
    test_db.add(job)
    test_db.commit()
    
    # Mock OS.path.isdir just in case
    monkeypatch.setattr(os.path, "isdir", lambda path: False)
    
    with pytest.raises(ValueError, match="Repository scanning skipped"):
        run_security_scan(str(job.id))
