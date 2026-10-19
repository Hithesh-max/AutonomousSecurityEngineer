"""Standard SBOM (CycloneDX v1.5 and SPDX 2.3) generation and validation."""
from datetime import datetime, timezone
import json
from pathlib import PurePosixPath
from typing import Any
from uuid import uuid4


def generate_purl(ecosystem: str, name: str, version: str | None = None) -> str:
    """Generate Package URL (purl) specification string."""
    eco_map = {"pypi": "pypi", "npm": "npm", "maven": "maven", "cargo": "cargo"}
    pkg_type = eco_map.get(ecosystem.lower(), "generic")
    safe_name = name.replace("@", "%40")
    if version:
        return f"pkg:{pkg_type}/{safe_name}@{version}"
    return f"pkg:{pkg_type}/{safe_name}"


def generate_cyclonedx_sbom(
    repository_name: str,
    repository_id: str,
    dependencies: list[dict[str, Any]],
    scan_id: str | None = None
) -> dict:
    """
    Generate CycloneDX v1.5 JSON SBOM.
    Includes components, purls, scopes (required/optional), and dependency relationships.
    """
    now = datetime.now(timezone.utc).isoformat()
    serial_number = f"urn:uuid:{uuid4()}"

    components = []
    dep_relationships = []
    root_ref = f"pkg:generic/{repository_name}@1.0.0"

    root_deps = []

    for dep in dependencies:
        name = dep.get("name")
        version = dep.get("version") or "0.0.0"
        ecosystem = dep.get("ecosystem", "generic")
        locked = dep.get("locked", False)
        group = dep.get("group", "runtime")

        purl = generate_purl(ecosystem, name, dep.get("version"))
        bom_ref = f"{purl}#{dep.get('manifest', '')}"

        component = {
            "type": "library",
            "bom-ref": bom_ref,
            "name": name,
            "version": version,
            "purl": purl,
            "scope": "required" if group in ("runtime", "default", "dependencies") else "optional",
            "properties": [
                {"name": "ase:ecosystem", "value": ecosystem},
                {"name": "ase:manifest", "value": dep.get("manifest", "")},
                {"name": "ase:relationship", "value": "transitive" if locked else "direct"}
            ]
        }
        components.append(component)

        if not locked:
            root_deps.append(bom_ref)

    # Root application relationship
    dep_relationships.append({
        "ref": root_ref,
        "dependsOn": root_deps
    })

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial_number,
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [
                {
                    "vendor": "Autonomous Security Engineer",
                    "name": "ASE Supply Chain Auditor",
                    "version": "1.0.0"
                }
            ],
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": repository_name,
                "version": "1.0.0"
            },
            "properties": [
                {"name": "ase:repository_id", "value": str(repository_id)},
                {"name": "ase:scan_id", "value": str(scan_id or "")}
            ]
        },
        "components": components,
        "dependencies": dep_relationships
    }
    return sbom


def generate_spdx_sbom(
    repository_name: str,
    repository_id: str,
    dependencies: list[dict[str, Any]]
) -> dict:
    """Generate SPDX 2.3 JSON specification SBOM."""
    now = datetime.now(timezone.utc).isoformat()
    doc_spdx_id = "SPDXRef-DOCUMENT"

    packages = [
        {
            "SPDXID": "SPDXRef-Package-Root",
            "name": repository_name,
            "versionInfo": "1.0.0",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False
        }
    ]

    relationships = []

    for i, dep in enumerate(dependencies):
        pkg_id = f"SPDXRef-Package-{i}-{dep.get('name', 'pkg')}"
        packages.append({
            "SPDXID": pkg_id,
            "name": dep.get("name"),
            "versionInfo": dep.get("version") or "UNKNOWN",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": generate_purl(dep.get("ecosystem", "generic"), dep.get("name"), dep.get("version"))
                }
            ]
        })
        relationships.append({
            "spdxElementId": "SPDXRef-Package-Root",
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": pkg_id
        })

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": doc_spdx_id,
        "name": f"{repository_name}-SBOM",
        "documentNamespace": f"https://ase.local/spdx/{repository_id}/{uuid4()}",
        "creationInfo": {
            "created": now,
            "creators": ["Tool: Autonomous Security Engineer 1.0.0"]
        },
        "packages": packages,
        "relationships": relationships
    }
