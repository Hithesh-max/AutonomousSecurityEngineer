"""Patch lifecycle. Phase 2 only *uses* PATCH_PROPOSED -> SUPERSEDED; the rest is defined and unit-tested now so
that approval/application/verification (later phases) cannot skip steps."""

PATCH_STATES = ("PATCH_PROPOSED", "APPROVED", "APPLYING", "APPLIED", "VERIFYING", "VERIFIED",
                "REJECTED", "FAILED", "INCONCLUSIVE", "SUPERSEDED")
TERMINAL = {"VERIFIED", "REJECTED", "FAILED", "INCONCLUSIVE", "SUPERSEDED"}

TRANSITIONS = {
    "PATCH_PROPOSED": {"APPROVED", "REJECTED", "SUPERSEDED"},
    "APPROVED": {"APPLYING", "REJECTED", "SUPERSEDED"},
    "APPLYING": {"APPLIED", "FAILED"},
    "APPLIED": {"VERIFYING", "SUPERSEDED"},
    "VERIFYING": {"VERIFIED", "INCONCLUSIVE", "FAILED"},
}


class InvalidTransition(Exception):
    pass


def can_transition(current: str, new: str) -> bool:
    return new in TRANSITIONS.get(current, set())


def require_transition(current: str, new: str) -> None:
    if not can_transition(current, new):
        raise InvalidTransition(f"Cannot move a patch from {current} to {new}.")
