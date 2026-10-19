"""Tests for false-positive evaluation, precision, recall, F1, and cross-tool correlation."""
import pytest
from app.evaluation.benchmark import get_labeled_samples
from app.evaluation.metrics import calculate_evaluation_metrics, correlate_cross_tool_findings


def test_labeled_benchmark_samples():
    samples = get_labeled_samples()
    assert len(samples) >= 10
    vuln_count = sum(1 for s in samples if s["ground_truth"] == "VULNERABLE")
    benign_count = sum(1 for s in samples if s["ground_truth"] == "BENIGN")
    assert vuln_count == 5
    assert benign_count == 5


def test_calculate_evaluation_metrics():
    # 2 TP, 1 FP, 1 FN, 2 TN
    evaluations = [
        {"ground_truth": "VULNERABLE", "detected": True},
        {"ground_truth": "VULNERABLE", "detected": True},
        {"ground_truth": "VULNERABLE", "detected": False},
        {"ground_truth": "BENIGN", "detected": True},
        {"ground_truth": "BENIGN", "detected": False},
        {"ground_truth": "BENIGN", "detected": False}
    ]
    report = calculate_evaluation_metrics(evaluations)
    cm = report["confusion_matrix"]
    assert cm["true_positives"] == 2
    assert cm["false_positives"] == 1
    assert cm["false_negatives"] == 1
    assert cm["true_negatives"] == 2

    # Precision: 2 / (2 + 1) = 0.6667
    assert report["metrics"]["precision"] == 0.6667
    # Recall: 2 / (2 + 1) = 0.6667
    assert report["metrics"]["recall"] == 0.6667
    # F1: 0.6667
    assert report["metrics"]["f1_score"] == 0.6667


def test_cross_tool_correlation_preserves_conflicts():
    findings = [
        {
            "title": "SQL Injection",
            "source": "SAST",
            "severity": "HIGH",
            "source_tools": ["semgrep"],
            "tool_rule_id": "rule-sql-1",
            "source_location": {"file": "app.py"}
        },
        {
            "title": "SQL Injection Inconclusive",
            "source": "DAST",
            "severity": "LOW",
            "source_tools": ["zap"],
            "tool_rule_id": "zap-sql",
            "source_location": {"file": "app.py"}
        }
    ]
    report = correlate_cross_tool_findings(findings)
    assert report["total_locations"] == 1
    assert report["locations_with_divergence"] == 1
    item = report["correlated_items"][0]
    assert item["divergence_detected"] is True
    assert set(item["severities"]) == {"HIGH", "LOW"}
    assert set(item["tools_involved"]) == {"semgrep", "zap"}
