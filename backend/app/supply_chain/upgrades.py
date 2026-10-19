"""Propose dependency upgrades with manifest/lockfile consistency."""
import json
import re
from typing import Any


def propose_dependency_upgrade(
    manifest_path: str,
    manifest_content: str,
    package_name: str,
    target_version: str
) -> dict[str, Any]:
    """
    Generate an edit to upgrade a package in requirements.txt or package.json.
    Maintains formatting and returns structured edits for review/approval.
    """
    if not re.fullmatch(r"[0-9][0-9A-Za-z.+_-]{0,80}", target_version):
        raise ValueError("Enter a concrete version without whitespace or dependency operators.")
    lines = manifest_content.splitlines()
    edits = []

    if manifest_path.endswith("requirements.txt"):
        pattern = re.compile(rf"^({re.escape(package_name)})(?:==|>=|<=|>|<|~=)([^\s#]+)(.*)$", re.IGNORECASE)
        for i, line in enumerate(lines):
            m = pattern.match(line.strip())
            if m:
                # Replace with target version
                comment = m.group(3) or ""
                new_line = f"{package_name}=={target_version}{comment}"
                edits.append({
                    "start_line": i + 1,
                    "end_line": i + 1,
                    "original_text": line,
                    "replacement_text": new_line
                })
                break

    elif manifest_path.endswith("package.json"):
        pattern = re.compile(rf'(\"{re.escape(package_name)}\"\s*:\s*\")[^"]+(\")', re.IGNORECASE)
        for i, line in enumerate(lines):
            m = pattern.search(line)
            if m:
                new_line = pattern.sub(rf'\g<1>{target_version}\g<2>', line)
                edits.append({
                    "start_line": i + 1,
                    "end_line": i + 1,
                    "original_text": line,
                    "replacement_text": new_line
                })
                break

    if not edits:
        raise ValueError(f"Could not locate package '{package_name}' in manifest '{manifest_path}'.")

    return {
        "manifest_path": manifest_path,
        "package_name": package_name,
        "target_version": target_version,
        "edits": edits,
        "explanation": f"Upgrade {package_name} to version {target_version}; security and compatibility must be verified.",
        "behavior_notes": "Verify compatibility with other dependencies before approving.",
        "limitations": ["Preview only; not persisted as an approved patch.", "Lockfiles are not regenerated; compatibility and advisory checks are not performed.", "Upgrading package versions may cause API deprecation or breaking changes."]
    }
