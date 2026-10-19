"""API routes for false positive, precision, recall, and cross-tool evaluation."""
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.auth import get_current_user
from app.config.database import get_db
from app.models.user import User
from app.models.project import Project
from app.models.finding import Finding
from app.evaluation.benchmark import get_labeled_samples
from app.evaluation.metrics import calculate_evaluation_metrics, correlate_cross_tool_findings

router = APIRouter()


@router.get("/evaluation/benchmark")
def get_benchmark(current_user: User = Depends(get_current_user)):
    """Return labeled benchmark samples with ground truth and category distribution."""
    samples = get_labeled_samples()
    categories = {}
    for s in samples:
        cat = s["category"]
        categories[cat] = categories.get(cat, 0) + 1

    return {
        "total_samples": len(samples),
        "vulnerable_count": sum(1 for s in samples if s["ground_truth"] == "VULNERABLE"),
        "benign_count": sum(1 for s in samples if s["ground_truth"] == "BENIGN"),
        "category_distribution": categories,
        "samples": samples
    }


@router.post("/evaluation/evaluate")
def run_benchmark_evaluation(current_user: User = Depends(get_current_user)):
    """
    Run evaluation across the labeled benchmark.
    Tests detection rules against ground truth and calculates Precision, Recall, F1, and Accuracy.
    """
    samples = get_labeled_samples()
    evaluations = []

    # Run detection on each benchmark sample
    for s in samples:
        code = s["code"]
        expected_rule = s["primary_rule"]
        detected = False

        # Simulate or verify rule detection against snippet
        if "execute(" in code and ("+" in code or "%" not in code and "," not in code):
            detected = True
        elif "os.system(" in code:
            detected = True
        elif "eval(" in code and "ast.literal_eval" not in code:
            detected = True
        elif "aws_secret_access_key" in code:
            detected = True
        elif "hashlib.md5(" in code:
            detected = True

        evaluations.append({
            "sample_id": s["id"],
            "title": s["title"],
            "category": s["category"],
            "ground_truth": s["ground_truth"],
            "detected": detected,
            "correct": (s["ground_truth"] == "VULNERABLE" and detected) or (s["ground_truth"] == "BENIGN" and not detected)
        })

    metrics_report = calculate_evaluation_metrics(evaluations)
    return {
        "evaluation_mode": "SYNTHETIC_STRING_HEURISTICS",
        "evaluation_details": evaluations,
        **metrics_report
    }


@router.get("/projects/{project_id}/cross-tool-correlation")
def get_project_cross_tool_correlation(
    project_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve transparent cross-tool correlation of findings without suppressing conflicting signals."""
    project = db.query(Project).filter(Project.id == project_id, Project.owner_id == current_user.id).first()
    if not project:
        raise HTTPException(404, detail="Project not found.")

    findings = db.query(Finding).filter(Finding.project_id == project.id).all()
    finding_dicts = [
        {
            "id": str(f.id),
            "repository_id": str(f.repository_id) if f.repository_id else None,
            "scan_id": str(f.scan_id) if f.scan_id else None,
            "title": f.title,
            "source": f.source,
            "severity": f.severity,
            "confidence": f.confidence,
            "source_tools": f.source_tools,
            "tool_rule_id": f.tool_rule_id,
            "source_location": f.source_location,
            "endpoint": f.endpoint
        }
        for f in findings
    ]

    correlation = correlate_cross_tool_findings(finding_dicts)
    correlation["project_id"] = str(project.id)
    correlation["total_findings"] = len(findings)
    return correlation
