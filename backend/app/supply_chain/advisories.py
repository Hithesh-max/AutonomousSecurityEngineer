"""Security advisory lookup with honest metadata and service availability reporting."""
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)

# Curated offline advisory database for common known vulnerable packages
# (e.g., PyPI requests < 2.31.0, urllib3 < 2.0.7, lodash < 4.17.21, jinja2 < 3.1.3, etc.)
KNOWN_ADVISORIES = {
    ("pypi", "requests"): [
        {
            "id": "GHSA-j8r2-6x86-q33q",
            "cve": "CVE-2023-32681",
            "affected_range": "<2.31.0",
            "fixed_version": "2.31.0",
            "severity": "MEDIUM",
            "title": "Unintended leak of Proxy-Authorization header in requests"
        }
    ],
    ("pypi", "urllib3"): [
        {
            "id": "GHSA-v845-jxx5-vc9f",
            "cve": "CVE-2023-45803",
            "affected_range": "<2.0.7",
            "fixed_version": "2.0.7",
            "severity": "MEDIUM",
            "title": "urllib3 HTTP request body not stripped on redirect"
        }
    ],
    ("pypi", "jinja2"): [
        {
            "id": "GHSA-h5c8-rqwp-cp95",
            "cve": "CVE-2024-22195",
            "affected_range": "<3.1.3",
            "fixed_version": "3.1.3",
            "severity": "MEDIUM",
            "title": "HTML attribute injection in xmlattr filter"
        }
    ],
    ("npm", "lodash"): [
        {
            "id": "GHSA-p6mc-m468-83gw",
            "cve": "CVE-2021-23337",
            "affected_range": "<4.17.21",
            "fixed_version": "4.17.21",
            "severity": "HIGH",
            "title": "Command Injection in lodash"
        }
    ],
    ("npm", "axios"): [
        {
            "id": "GHSA-8hc4-vh64-cxmj",
            "cve": "CVE-2023-45857",
            "affected_range": "<1.6.0",
            "fixed_version": "1.6.0",
            "severity": "MEDIUM",
            "title": "Cross-Site Request Forgery in axios"
        }
    ]
}


def version_matches_range(version_str: str | None, constraint: str) -> bool:
    """Basic semver range check for advisory evaluation."""
    if not version_str or not version_str.strip():
        return False
    # If constraint is "<X.Y.Z"
    if constraint.startswith("<"):
        target = constraint[1:].strip()
        v_parts = [int(p) for p in version_str.split(".") if p.isdigit()]
        t_parts = [int(p) for p in target.split(".") if p.isdigit()]
        return v_parts < t_parts
    return False


def lookup_advisories(
    dependencies: list[dict[str, Any]],
    upstream_online: bool = True
) -> dict[str, Any]:
    """
    Match dependencies against vulnerability advisories.
    Handles advisory service connectivity and unavailable package metadata honestly.
    """
    results = []
    total_vulns = 0

    service_status = "CURATED_OFFLINE_ONLY"

    for dep in dependencies:
        eco = (dep.get("ecosystem") or "").lower()
        name = (dep.get("name") or "").lower()
        version = dep.get("version")

        key = (eco, name)
        matched_advisories = []

        if not version:
            results.append({
                "name": dep.get("name"),
                "ecosystem": eco,
                "version": None,
                "status": "METADATA_UNAVAILABLE",
                "detail": "Package version is unpinned or unavailable; cannot evaluate advisories accurately.",
                "advisories": []
            })
            continue

        if key in KNOWN_ADVISORIES:
            for adv in KNOWN_ADVISORIES[key]:
                if version_matches_range(version, adv["affected_range"]):
                    matched_advisories.append(adv)

        total_vulns += len(matched_advisories)
        results.append({
            "name": dep.get("name"),
            "ecosystem": eco,
            "version": version,
            "manifest": dep.get("manifest"),
            "status": "VULNERABLE" if matched_advisories else "NO_KNOWN_ADVISORY",
            "advisories": matched_advisories,
            "recommended_version": matched_advisories[0]["fixed_version"] if matched_advisories else None
        })

    return {
        "service_status": service_status,
        "checked_count": len(dependencies),
        "vulnerable_count": sum(1 for r in results if r.get("status") == "VULNERABLE"),
        "total_advisories": total_vulns,
        "dependencies": results,
        "limitations": [
            "Curated offline advisory examples only; no live advisory service was queried.",
            "No known advisory in this limited dataset does not establish safety.",
            "Unpinned dependencies cannot be confirmed safe without lockfiles.",
            "Transitive dependencies require full lockfile parsing."
        ]
    }
