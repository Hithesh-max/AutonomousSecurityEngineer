"""Static validation is not an execution sandbox or proof of remediation."""
import pytest
from app.verification.runner import detect_project_runner, run_bounded_process, verify_project_changes

def test_detect_nested_components(tmp_path):
    (tmp_path / "backend").mkdir()
    (tmp_path / "backend/requirements.txt").write_text("pytest\n")
    (tmp_path / "frontend").mkdir()
    (tmp_path / "frontend/package.json").write_text('{"name":"demo"}')
    result = detect_project_runner(tmp_path)
    assert result["runner_type"] == "MULTI_COMPONENT"
    assert result["build_cmd"] is None
    assert result["test_cmd"] is None

def test_untrusted_execution_disabled(tmp_path):
    with pytest.raises(RuntimeError, match="not an isolated execution sandbox"):
        run_bounded_process(["npm", "test"], tmp_path)

def test_no_approved_patches_requires_review(tmp_path):
    with pytest.raises(ValueError, match="No currently approved patches"):
        verify_project_changes(tmp_path, [], {}, [])
