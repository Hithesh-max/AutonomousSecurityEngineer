"""Tests for supply chain inventory, SBOM generation, advisories, and upgrades."""
from app.supply_chain.sbom import generate_cyclonedx_sbom, generate_spdx_sbom, generate_purl
from app.supply_chain.advisories import lookup_advisories, version_matches_range
from app.supply_chain.upgrades import propose_dependency_upgrade


def test_purl_generation():
    assert generate_purl("pypi", "requests", "2.31.0") == "pkg:pypi/requests@2.31.0"
    assert generate_purl("npm", "@types/node", "20.0.0") == "pkg:npm/%40types/node@20.0.0"
    assert generate_purl("pypi", "flask") == "pkg:pypi/flask"


def test_cyclonedx_sbom_generation():
    deps = [
        {"name": "requests", "version": "2.28.0", "ecosystem": "pypi", "manifest": "requirements.txt", "locked": False, "group": "runtime"},
        {"name": "urllib3", "version": "1.26.5", "ecosystem": "pypi", "manifest": "requirements.txt", "locked": True, "group": "runtime"}
    ]
    sbom = generate_cyclonedx_sbom("my-app", "repo-123", deps, "scan-456")
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    assert len(sbom["components"]) == 2
    assert sbom["components"][0]["purl"] == "pkg:pypi/requests@2.28.0"
    assert sbom["components"][0]["scope"] == "required"
    assert len(sbom["dependencies"]) == 1


def test_spdx_sbom_generation():
    deps = [
        {"name": "lodash", "version": "4.17.20", "ecosystem": "npm", "manifest": "package.json", "locked": False, "group": "dependencies"}
    ]
    spdx = generate_spdx_sbom("web-service", "repo-456", deps)
    assert spdx["spdxVersion"] == "SPDX-2.3"
    assert len(spdx["packages"]) == 2  # Root + 1 dep
    assert spdx["relationships"][0]["relationshipType"] == "DEPENDS_ON"


def test_advisories_lookup_vulnerable_and_safe():
    deps = [
        {"name": "requests", "version": "2.28.0", "ecosystem": "pypi", "manifest": "requirements.txt"},
        {"name": "requests", "version": "2.32.0", "ecosystem": "pypi", "manifest": "requirements.txt"},
        {"name": "unknown-lib", "version": None, "ecosystem": "pypi", "manifest": "requirements.txt"}
    ]
    report = lookup_advisories(deps, upstream_online=True)
    assert report["checked_count"] == 3
    assert report["vulnerable_count"] == 1  # 2.28.0 is vulnerable
    assert report["dependencies"][0]["status"] == "VULNERABLE"
    assert report["dependencies"][0]["recommended_version"] == "2.31.0"
    assert report["dependencies"][1]["status"] == "NO_KNOWN_ADVISORY"
    assert report["service_status"] == "CURATED_OFFLINE_ONLY"
    assert report["dependencies"][2]["status"] == "METADATA_UNAVAILABLE"


def test_dependency_upgrade_proposal():
    content = "flask==2.0.1\nrequests==2.28.0 # comment\npytest\n"
    res = propose_dependency_upgrade("requirements.txt", content, "requests", "2.31.0")
    assert res["manifest_path"] == "requirements.txt"
    assert res["package_name"] == "requests"
    assert len(res["edits"]) == 1
    assert res["edits"][0]["replacement_text"] == "requests==2.31.0 # comment"
