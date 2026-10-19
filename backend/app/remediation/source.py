"""Source location abstraction.

`SourceLocator` is the general interface. `BundledLabLocator` is the first adapter and *reuses* the verified
rule->line table already maintained in app.api.web_scans (it is imported, never edited or copied). The
validation steps intentionally mirror the existing /lab-source endpoint; a regression test asserts both agree.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Protocol
from urllib.parse import urlsplit

from sqlalchemy.orm import Session

from app.models.finding import Finding
from app.models.project import Project, ScanJob, Target
from app.network.scope import LAB_URL

MAX_SOURCE_BYTES = 100_000


class SourceUnavailable(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class SourceContext:
    kind: str                 # e.g. BUNDLED_LAB
    path: str                 # display path only; never used to open files
    start_line: int           # editable window, 1-based inclusive
    end_line: int
    highlight_line: int
    lines: tuple[str, ...]    # the FULL file, used for exact-match patch validation
    sha256: str               # hash of the full file bytes
    mapping_status: str
    mapping_note: str

    def window_text(self, with_numbers: bool = True) -> str:
        rows = range(self.start_line, self.end_line + 1)
        if with_numbers:
            return "\n".join(f"{n}| {self.lines[n - 1]}" for n in rows)
        return "\n".join(self.lines[n - 1] for n in rows)


class SourceLocator(Protocol):
    def locate(self, db: Session, finding: Finding, user_id) -> SourceContext: ...


class BundledLabLocator:
    kind = "BUNDLED_LAB"

    def locate(self, db: Session, finding: Finding, user_id) -> SourceContext:
        from app.api import web_scans as lab  # read-only reuse of the verified mapping table

        if finding.source != "DAST" or finding.scan_id is None:
            raise SourceUnavailable("SOURCE_UNAVAILABLE", "Only bundled-lab DAST findings have verified source mappings.")
        job = (db.query(ScanJob).join(Target).join(Project)
               .filter(ScanJob.id == finding.scan_id, Project.owner_id == user_id,
                       ScanJob.job_type == "WEB_SCAN", Target.url == LAB_URL).first())
        if not job:
            raise SourceUnavailable("SOURCE_UNAVAILABLE", "Finding does not belong to an authorized bundled-lab scan.")
        mapping = lab._LAB_MAPPINGS.get(str(finding.tool_rule_id))
        if not mapping:
            raise SourceUnavailable("SOURCE_UNAVAILABLE", "No verified bundled-lab source mapping for this rule.")
        route, parameter, start, end, highlight, expected = mapping

        parsed = urlsplit((finding.endpoint or {}).get("path", ""))
        if parsed.scheme != "http" or parsed.hostname != "ase-lab" or parsed.port != 8080:
            raise SourceUnavailable("SOURCE_UNAVAILABLE", "Finding endpoint is outside the bundled lab.")
        if route is not None and (parsed.path != route or finding.parameter != parameter):
            raise SourceUnavailable("SOURCE_UNAVAILABLE", "Finding does not match the bundled-lab route and parameter.")

        try:
            data = lab._LAB_SOURCE.read_bytes()
            if len(data) > MAX_SOURCE_BYTES:
                raise ValueError("too large")
            lines = data.decode("utf-8").splitlines()
            if len(lines) < end:
                raise ValueError("short")
        except (OSError, UnicodeError, ValueError):
            raise SourceUnavailable("SOURCE_UNAVAILABLE", "Bundled lab source is unavailable or changed.") from None
        if expected not in lines[highlight - 1]:
            raise SourceUnavailable("SOURCE_MAPPING_STALE", "Lab source changed; mapping needs review.")
        return SourceContext(kind=self.kind, path="lab/app.py", start_line=start, end_line=end,
                             highlight_line=highlight, lines=tuple(lines), sha256=sha256(data).hexdigest(),
                             mapping_status="BUNDLED_LAB_VERIFIED",
                             mapping_note="Matched against the bundled lab route, ZAP rule and parameter.")


def locator_for(finding: Finding) -> SourceLocator:
    """Single dispatch point; further adapters (managed repositories) plug in here."""
    if getattr(finding, "repository_id", None) is not None:
        from app.remediation.repository_source import RepositoryLocator
        return RepositoryLocator()
    return BundledLabLocator()
