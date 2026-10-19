"""Semantic and line-level patch conflict analysis and consolidation."""
from collections import defaultdict
import re
from typing import Any


class ConflictType:
    LINE_OVERLAP = "LINE_OVERLAP"
    FUNCTION_CONFLICT = "FUNCTION_CONFLICT"
    DEPENDENCY_CONFLICT = "DEPENDENCY_CONFLICT"
    SEMANTIC_CONFLICT = "SEMANTIC_CONFLICT"


def extract_modified_functions(lines: list[str], edits: list[dict]) -> set[str]:
    """Identify function names touched by edits."""
    touched_funcs = set()
    func_pattern = re.compile(r"^\s*(?:def|async def|function|public\s+\w+|private\s+\w+)\s+([a-zA-Z_]\w*)")

    for edit in edits:
        start = max(1, edit.get("start_line", 1))
        end = min(len(lines), edit.get("end_line", start))
        # Look around edit window for function headers
        window_start = max(0, start - 15)
        for i in range(window_start, end):
            if i < len(lines):
                m = func_pattern.match(lines[i])
                if m:
                    touched_funcs.add(m.group(1))
    return touched_funcs


def detect_conflicts(proposals: list[Any], sources: dict[str, Any]) -> dict:
    """
    Examine a set of approved proposals across repository files for conflicts.
    Detects line overlaps, function overlaps, and dependency version contradictions.
    """
    conflicts = []
    file_to_proposals = defaultdict(list)

    for p in proposals:
        path = getattr(p, "source_path", None)
        if path:
            file_to_proposals[path].append(p)

    for path, patch_list in file_to_proposals.items():
        if len(patch_list) <= 1:
            continue

        source = sources.get(path)
        source_lines = source.lines if source else []

        # 1. Line overlap detection
        sorted_patches = []
        for p in patch_list:
            edits = getattr(p, "edits", []) or []
            for e in edits:
                sorted_patches.append({
                    "patch_id": str(p.id),
                    "start_line": e.get("start_line", 1),
                    "end_line": e.get("end_line", 1),
                    "replacement": e.get("replacement_text", "")
                })

        sorted_patches.sort(key=lambda x: x["start_line"])
        for i in range(len(sorted_patches) - 1):
            curr = sorted_patches[i]
            nxt = sorted_patches[i + 1]
            if curr["end_line"] >= nxt["start_line"] and curr["patch_id"] != nxt["patch_id"]:
                conflicts.append({
                    "type": ConflictType.LINE_OVERLAP,
                    "file_path": path,
                    "patch_ids": [curr["patch_id"], nxt["patch_id"]],
                    "line_range": [nxt["start_line"], min(curr["end_line"], nxt["end_line"])],
                    "description": (
                        f"Patches {curr['patch_id'][:8]} and {nxt['patch_id'][:8]} propose overlapping edits "
                        f"on lines {nxt['start_line']}-{curr['end_line']} of {path}."
                    ),
                    "requires_resolution": True
                })

        # 2. Semantic function conflict detection
        func_to_patches = defaultdict(list)
        for p in patch_list:
            edits = getattr(p, "edits", []) or []
            funcs = extract_modified_functions(source_lines, edits)
            for f in funcs:
                func_to_patches[f].append(str(p.id))

        for f, pids in func_to_patches.items():
            unique_pids = list(set(pids))
            if len(unique_pids) > 1:
                # Multiple proposals modify the same function
                conflicts.append({
                    "type": ConflictType.FUNCTION_CONFLICT,
                    "file_path": path,
                    "function_name": f,
                    "patch_ids": unique_pids,
                    "description": (
                        f"Multiple proposals touch function '{f}' in {path}. "
                        "Coordinated review is required to prevent logic conflicts."
                    ),
                    "requires_resolution": True
                })

        # 3. Dependency manifest conflict detection
        if path.endswith(("requirements.txt", "package.json", "pyproject.toml")):
            # Look for conflicting package version pins
            dep_pattern = re.compile(r"([a-zA-Z0-9_\-]+)\s*(?:==|>=|<=|>|<|~=|\^)\s*([0-9\.]+)")
            dep_pins = defaultdict(list)
            for p in patch_list:
                edits = getattr(p, "edits", []) or []
                for e in edits:
                    for line in e.get("replacement_text", "").splitlines():
                        m = dep_pattern.search(line)
                        if m:
                            pkg, ver = m.group(1).lower(), m.group(2)
                            dep_pins[pkg].append((str(p.id), ver))

            for pkg, pins in dep_pins.items():
                versions = {ver for _, ver in pins}
                if len(versions) > 1:
                    conflicts.append({
                        "type": ConflictType.DEPENDENCY_CONFLICT,
                        "file_path": path,
                        "package": pkg,
                        "patch_ids": [pid for pid, _ in pins],
                        "description": f"Conflicting version specifications for dependency '{pkg}' in {path}: {list(versions)}",
                        "requires_resolution": True
                    })

    return {
        "compatible": len(conflicts) == 0,
        "conflict_count": len(conflicts),
        "conflicts": conflicts
    }
