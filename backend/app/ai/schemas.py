"""Validated shapes for model output. Anything not matching is rejected, never stored as a result."""
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _clean(value: str) -> str:
    if _CONTROL.search(value):
        raise ValueError("control characters are not allowed")
    return value.strip()


class ModelAnalysis(BaseModel):
    """What we accept from the model. Locations/IDs/model metadata are added by ASE, never by the model."""
    model_config = ConfigDict(extra="forbid")

    vulnerability_type: str = Field(min_length=3, max_length=120)
    cwe: str | None = Field(default=None, pattern=r"^CWE-\d{1,5}$")
    root_cause: str = Field(min_length=10, max_length=2000)
    security_impact: str = Field(min_length=10, max_length=1500)
    evidence_summary: str = Field(min_length=10, max_length=1500)
    recommended_fix: str = Field(min_length=10, max_length=2000)
    preconditions: list[str] = Field(default_factory=list, max_length=8)
    confidence: Literal["LOW", "MEDIUM", "HIGH"]
    limitations: list[str] = Field(default_factory=list, max_length=8)

    @field_validator("vulnerability_type", "root_cause", "security_impact", "evidence_summary", "recommended_fix")
    @classmethod
    def _text(cls, value: str) -> str:
        return _clean(value)

    @field_validator("preconditions", "limitations")
    @classmethod
    def _items(cls, values: list[str]) -> list[str]:
        return [_clean(item)[:400] for item in values]


class ModelEdit(BaseModel):
    model_config = ConfigDict(extra="forbid")
    start_line: int = Field(ge=1, le=100000)
    end_line: int = Field(ge=1, le=100000)
    original_text: str = Field(max_length=6000)
    replacement_text: str = Field(max_length=6000)


class ModelPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    edits: list[ModelEdit] = Field(min_length=1, max_length=5)
    explanation: str = Field(min_length=10, max_length=2000)
    behavior_notes: str = Field(default="", max_length=1500)
    limitations: list[str] = Field(default_factory=list, max_length=8)

    @field_validator("explanation", "behavior_notes")
    @classmethod
    def _text(cls, value: str) -> str:
        return _clean(value)
