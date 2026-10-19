import pytest
from types import SimpleNamespace

from app.ai.errors import AIProviderError
from app.ai.providers import OpenAIProvider
from app.ai.schemas import ModelPatch
from app.remediation import states
from app.remediation.patching import PatchRejected, validate_and_render
from app.remediation.source import SourceContext
from tests.remediation.helpers import LAB_APP, LAB_LINES


def ctx(start=31, end=41):
    return SourceContext(kind="BUNDLED_LAB", path="lab/app.py", start_line=start, end_line=end, highlight_line=37,
                         lines=tuple(LAB_LINES), sha256="x" * 64, mapping_status="BUNDLED_LAB_VERIFIED", mapping_note="")


def patch(**edit):
    base = {"start_line": 37, "end_line": 37, "original_text": LAB_LINES[36], "replacement_text": LAB_LINES[36] + "  # ok"}
    base.update(edit)
    return ModelPatch(edits=[base], explanation="A valid explanation of the change.")


def code(p, source=None):
    with pytest.raises(PatchRejected) as e:
        validate_and_render(source or ctx(), p)
    return e.value.code


def test_valid_patch_renders_diff_and_hashes():
    v = validate_and_render(ctx(), patch())
    assert v.unified_diff.startswith("--- a/lab/app.py\n+++ b/lab/app.py") and len(v.patch_sha256) == 64
    assert v.checks["lines_added"] == 1 and v.checks["lines_removed"] == 1


@pytest.mark.parametrize("edit,expected", [
    ({"start_line": 20, "end_line": 20, "original_text": LAB_LINES[19]}, "PATCH_OUTSIDE_WINDOW"),
    ({"end_line": 36}, "PATCH_INVALID_RANGE"),
    ({"original_text": "something the model invented"}, "PATCH_ORIGINAL_MISMATCH"),
    ({"replacement_text": "                import os; os.system('x')"}, "PATCH_DANGEROUS_CONSTRUCT"),
    ({"replacement_text": "                eval(query)"}, "PATCH_DANGEROUS_CONSTRUCT"),
    ({"replacement_text": "                import json"}, "PATCH_NEW_IMPORT"),
    ({"replacement_text": "                rows = ("}, "PATCH_SYNTAX_ERROR"),
    ({"replacement_text": LAB_LINES[36]}, "PATCH_NO_CHANGE"),
    ({"replacement_text": "a\x00b"}, "PATCH_INVALID_CONTENT"),
])
def test_rejections(edit, expected):
    assert code(patch(**edit)) == expected


def test_overlap_and_size_limits():
    two = ModelPatch(edits=[{"start_line": 36, "end_line": 37, "original_text": "\n".join(LAB_LINES[35:37]), "replacement_text": "x = 1\ny = 2"},
                            {"start_line": 37, "end_line": 38, "original_text": "\n".join(LAB_LINES[36:38]), "replacement_text": "z = 1"}],
                     explanation="Overlapping edits for the test.")
    assert code(two) == "PATCH_OVERLAP"
    big = ModelPatch(edits=[{"start_line": 37, "end_line": 37, "original_text": LAB_LINES[36],
                             "replacement_text": "\n".join(f"                v{i} = {i}" for i in range(70))}],
                     explanation="Adds far too many lines for a minimal fix.")
    assert code(big) == "PATCH_TOO_LARGE"


def test_pydantic_limits_on_model_patch():
    with pytest.raises(Exception):
        ModelPatch(edits=[], explanation="No edits are not a patch at all.")
    with pytest.raises(Exception):
        ModelPatch(edits=[{"start_line": 1, "end_line": 1, "original_text": "a", "replacement_text": "b", "path": "/etc/passwd"}],
                   explanation="Extra path field must be rejected.")


def test_state_machine():
    assert states.can_transition("PATCH_PROPOSED", "APPROVED")
    for current, new in [("REJECTED", "APPLYING"), ("PATCH_PROPOSED", "APPLIED"), ("PATCH_PROPOSED", "VERIFYING"),
                         ("APPROVED", "VERIFIED"), ("VERIFIED", "APPLYING"), ("SUPERSEDED", "APPROVED"), ("APPLYING", "VERIFYING")]:
        assert not states.can_transition(current, new), (current, new)
        with pytest.raises(states.InvalidTransition):
            states.require_transition(current, new)
    assert set(states.TRANSITIONS) | states.TERMINAL == set(states.PATCH_STATES)


class FakeCompletions:
    def __init__(self, outcome): self.outcome = outcome
    def create(self, **kw):
        self.kwargs = kw
        if isinstance(self.outcome, Exception): raise self.outcome
        return self.outcome


def fake_client(outcome):
    return SimpleNamespace(chat=SimpleNamespace(completions=FakeCompletions(outcome)))


def reply(text="{}", finish="stop"):
    return SimpleNamespace(model="m-1", usage=SimpleNamespace(prompt_tokens=5, completion_tokens=7),
                           choices=[SimpleNamespace(message=SimpleNamespace(content=text), finish_reason=finish)])


def test_openai_adapter_success_and_request_shape():
    client = fake_client(reply('{"a":1}'))
    out = OpenAIProvider("sk-key", "m-1", 10, 1, client=client).complete_json(system="s", user="u", max_output_tokens=300)
    assert out.text == '{"a":1}' and (out.prompt_tokens, out.completion_tokens) == (5, 7)
    kw = client.chat.completions.kwargs
    assert kw["response_format"] == {"type": "json_object"} and kw["max_completion_tokens"] == 300 and kw["temperature"] == 0


@pytest.mark.parametrize("name,expected", [("APITimeoutError", "AI_TIMEOUT"), ("RateLimitError", "AI_RATE_LIMITED"),
                                           ("AuthenticationError", "AI_AUTH_FAILED"), ("InternalServerError", "AI_PROVIDER_ERROR")])
def test_openai_adapter_error_mapping_never_leaks_key(name, expected):
    error = type(name, (Exception,), {})("Incorrect API key provided: sk-key-SECRET")
    with pytest.raises(AIProviderError) as e:
        OpenAIProvider("sk-key-SECRET", "m", 10, 0, client=fake_client(error)).complete_json(system="s", user="u", max_output_tokens=10)
    assert e.value.code == expected and "SECRET" not in e.value.message and e.value.__cause__ is None


def test_openai_adapter_truncated_output_is_an_error():
    with pytest.raises(AIProviderError) as e:
        OpenAIProvider("k", "m", 10, 0, client=fake_client(reply("{", "length"))).complete_json(system="s", user="u", max_output_tokens=10)
    assert e.value.code == "AI_OUTPUT_TRUNCATED"


def test_openai_adapter_requires_key():
    with pytest.raises(ValueError):
        OpenAIProvider("", "m", 10, 0)
