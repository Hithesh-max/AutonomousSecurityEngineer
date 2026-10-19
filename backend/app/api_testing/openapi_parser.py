"""OpenAPI specification parser and endpoint inventory extractor."""
import json
import re
from typing import Any
try:
    import yaml
except ImportError:
    yaml = None


def parse_openapi_spec(spec_text: str) -> dict[str, Any]:
    """Parse JSON or YAML OpenAPI specification and extract structured inventory."""
    try:
        spec = json.loads(spec_text)
    except Exception:
        if yaml is not None:
            try:
                spec = yaml.safe_load(spec_text)
            except Exception as e:
                raise ValueError(f"Failed to parse OpenAPI document as JSON or YAML: {str(e)}")
        else:
            raise ValueError("Failed to parse OpenAPI document as JSON (PyYAML is not installed for YAML parsing).")

    if not isinstance(spec, dict):
        raise ValueError("OpenAPI specification must be a JSON/YAML object.")

    version = spec.get("openapi") or spec.get("swagger")
    if not version:
        raise ValueError("Document is missing 'openapi' or 'swagger' version declaration.")

    info = spec.get("info") or {}
    if not isinstance(info, dict):
        raise ValueError("OpenAPI info must be an object.")
    title = info.get("title", "Untitled API")
    api_version = info.get("version", "1.0.0")

    paths = spec.get("paths", {})
    if not isinstance(paths, dict) or len(paths) > 1000:
        raise ValueError("OpenAPI paths must be an object with at most 1000 entries.")
    endpoints = []

    http_methods = {"get", "post", "put", "delete", "patch", "options", "head"}

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        for method in http_methods:
            if method in path_item:
                op = path_item[method]
                if not isinstance(op, dict):
                    continue

                operation_id = op.get("operationId", f"{method}_{path}")
                summary = op.get("summary", "")
                security = op.get("security", spec.get("security", [])) or []
                if not isinstance(security, list):
                    raise ValueError("OpenAPI security must be an array.")

                # Extract path/query parameters
                params = []
                for p in (op.get("parameters") or []) + (path_item.get("parameters") or []):
                    if isinstance(p, dict) and "name" in p:
                        params.append({
                            "name": p["name"],
                            "in": p.get("in", "query"),
                            "required": p.get("required", False)
                        })

                # Check if path contains object identifiers (e.g. {id}, {user_id}, {item_id})
                has_object_id = bool(re.search(r"\{[a-zA-Z0-9_\-]*id[a-zA-Z0-9_\-]*\}", path, re.IGNORECASE))
                is_admin_endpoint = bool(re.search(r"/(?:admin|manage|internal|system)/", path, re.IGNORECASE)) or any(
                    "admin" in str(tag).lower() for tag in op.get("tags", [])
                )

                endpoints.append({
                    "path": path,
                    "method": method.upper(),
                    "operation_id": operation_id,
                    "summary": summary,
                    "parameters": params,
                    "security_required": len(security) > 0,
                    "security_schemes": security,
                    "has_object_id": has_object_id,
                    "is_admin_endpoint": is_admin_endpoint,
                    "bola_candidate": has_object_id and method.upper() in ("GET", "PUT", "PATCH", "DELETE"),
                    "bfla_candidate": is_admin_endpoint
                })

    return {
        "title": title,
        "spec_version": str(version),
        "api_version": api_version,
        "total_endpoints": len(endpoints),
        "bola_candidates": sum(1 for e in endpoints if e["bola_candidate"]),
        "bfla_candidates": sum(1 for e in endpoints if e["bfla_candidate"]),
        "endpoints": endpoints
    }
