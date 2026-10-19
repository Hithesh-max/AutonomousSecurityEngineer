"""Precision, Recall, F1 evaluation and transparent cross-tool correlation."""
from collections import defaultdict
from typing import Any


def calculate_evaluation_metrics(
    evaluations: list[dict[str, Any]]
) -> dict[str, Any]:
    """
    Calculate Precision, Recall, F1, and Accuracy from sample evaluations.
    Each item must contain 'ground_truth' ('VULNERABLE' | 'BENIGN')
    and 'detected' (bool).
    """
    tp = 0  # Vulnerable and detected
    fp = 0  # Benign and detected
    fn = 0  # Vulnerable and not detected
    tn = 0  # Benign and not detected

    for item in evaluations:
        gt = item.get("ground_truth")
        detected = bool(item.get("detected"))

        if gt == "VULNERABLE":
            if detected:
                tp += 1
            else:
                fn += 1
        elif gt == "BENIGN":
            if detected:
                fp += 1
            else:
                tn += 1

    total = tp + fp + fn + tn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / total if total > 0 else 0.0

    return {
        "confusion_matrix": {
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "true_negatives": tn,
            "total_samples": total
        },
        "metrics": {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "accuracy": round(accuracy, 4)
        },
        "sample_limitations": [
            "This demonstration evaluates string heuristics on ten synthetic Python/configuration snippets.",
            "No Semgrep, Gitleaks, Trivy or ZAP execution is performed by this benchmark.",
            "Generalization to arbitrary custom codebases requires expanded sample datasets."
        ]
    }


def correlate_cross_tool_findings(
    findings: list[dict[str, Any]]
) -> dict[str, Any]:
    """
    Correlate findings across multiple tools (Semgrep, Gitleaks, Trivy, ZAP).
    Preserves conflicting results transparently without suppressing divergence.
    """
    # Group findings by file / endpoint location
    location_groups = defaultdict(list)

    for index, f in enumerate(findings):
        loc = (f.get("source_location") or {}).get("file") or (f.get("endpoint") or {}).get("path") or f"unmapped:{f.get('id') or index}"
        namespace = ":".join(str(f[k]) for k in ("repository_id", "scan_id") if f.get(k))
        location_groups[f"{namespace} · {loc}" if namespace else loc].append(f)

    correlated_items = []
    conflict_count = 0

    for loc, items in location_groups.items():
        tools_involved = list({t for item in items for t in (item.get("source_tools") or [])})
        severities = list({item.get("severity") for item in items})
        sources = list({item.get("source") for item in items})

        # A conflict occurs if multiple tools inspect the same target but disagree on severity or presence
        has_divergence = len(severities) > 1 or ("SAST" in sources and "DAST" in sources)

        if has_divergence:
            conflict_count += 1

        correlated_items.append({
            "location": loc,
            "tools_involved": tools_involved,
            "finding_count": len(items),
            "severities": severities,
            "divergence_detected": has_divergence,
            "findings": [
                {
                    "title": item.get("title"),
                    "source": item.get("source"),
                    "severity": item.get("severity"),
                    "confidence": item.get("confidence"),
                    "rule_id": item.get("tool_rule_id"),
                    "tools": item.get("source_tools") or []
                }
                for item in items
            ]
        })

    return {
        "total_locations": len(location_groups),
        "locations_with_divergence": conflict_count,
        "correlated_items": correlated_items,
        "provenance_policy": "Cross-tool evidence correlation preserves raw tool provenance and never suppresses divergent results."
    }
