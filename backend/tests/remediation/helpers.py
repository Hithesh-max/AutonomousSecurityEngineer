import json
from pathlib import Path
from uuid import uuid4

from app.ai.providers import MockProvider
from app.models.finding import Finding
from app.models.project import Project, ScanJob, Target

LAB_APP = Path(__file__).resolve().parents[3] / "lab" / "app.py"
LAB_LINES = LAB_APP.read_text().splitlines()

ANALYSIS = {"vulnerability_type": "SQL Injection", "cwe": "CWE-89",
            "root_cause": "User input is concatenated into the SQL statement.",
            "security_impact": "An attacker can read or alter database contents.",
            "evidence_summary": "ZAP reported SQL injection in parameter q on /search.",
            "recommended_fix": "Use a parameterized query with a bound parameter.",
            "preconditions": ["Endpoint reachable"], "confidence": "HIGH", "limitations": []}


def sqli_patch():
    original = LAB_LINES[36]
    replacement = original.replace(
        """\"SELECT owner, amount FROM invoices WHERE owner = '\" + query.get('q', ['alice'])[0] + \"'\")""",
        """\"SELECT owner, amount FROM invoices WHERE owner = ?\", (query.get('q', ['alice'])[0],))""")
    assert replacement != original
    return {"edits": [{"start_line": 37, "end_line": 37, "original_text": original, "replacement_text": replacement}],
            "explanation": "Bind the user value as a SQL parameter instead of concatenating it.",
            "behavior_notes": "Same query results for benign input.", "limitations": []}


def make_provider(analysis=None, patch=None, external=False):
    def respond(system, user):
        if "Return JSON matching: {\"edits\"" in user:
            return json.dumps(patch if patch is not None else sqli_patch())
        return json.dumps(analysis if analysis is not None else ANALYSIS)
    provider = MockProvider(respond)
    provider.is_external = external
    return provider


def make_finding(db, user, rule="40018", path="http://ase-lab:8080/search", param="q", lab=True):
    project = Project(name="Remediation " + uuid4().hex[:6], owner_id=user.id)
    db.add(project); db.commit()
    target = Target(name="Lab", project_id=project.id, url="http://ase-lab:8080" if lab else "http://example.test",
                    authorization_status="APPROVED", explicit_scope="ase-lab", is_active=True, approved_by=user.id)
    db.add(target); db.commit()
    job = ScanJob(target_id=target.id, requesting_user_id=user.id, job_type="WEB_SCAN", status="COMPLETED")
    db.add(job); db.commit()
    finding = Finding(project_id=project.id, scan_id=job.id, source="DAST", tool_rule_id=rule, title="Finding " + rule,
                      severity="HIGH", confidence="MEDIUM", cwe="CWE-89", status="OPEN", source_tools=["zap"],
                      endpoint={"method": "GET", "path": path}, parameter=param, fingerprint=uuid4().hex,
                      evidence={"scanner_evidence": "sample", "api_key": "sk-should-be-redacted-123456"})
    db.add(finding); db.commit()
    return finding
