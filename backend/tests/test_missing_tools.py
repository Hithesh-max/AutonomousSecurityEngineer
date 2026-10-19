import pytest
import os
from app.scanners.semgrep import SemgrepScanner
from app.scanners.gitleaks import GitleaksScanner
from app.scanners.trivy import TrivyScanner
from app.services.llm import AIRemediator
from app.workers.remediation_jobs import generate_ai_fix

def test_semgrep_missing_binary(monkeypatch):
    scanner = SemgrepScanner()
    # Mock subprocess.run to raise FileNotFoundError
    def mock_run(*args, **kwargs):
        raise FileNotFoundError("Binary not found")
    monkeypatch.setattr("app.scanners.controlled.shutil.which", lambda _: None)
    
    with pytest.raises(FileNotFoundError, match="Semgrep executable not found"):
        scanner.scan("/fake/path")

def test_gitleaks_missing_binary(monkeypatch):
    scanner = GitleaksScanner()
    def mock_run(*args, **kwargs):
        raise FileNotFoundError("Binary not found")
    monkeypatch.setattr("app.scanners.controlled.shutil.which", lambda _: None)
    
    with pytest.raises(FileNotFoundError, match="Gitleaks executable not found"):
        scanner.scan("/fake/path")

def test_trivy_missing_binary(monkeypatch):
    scanner = TrivyScanner()
    def mock_run(*args, **kwargs):
        raise FileNotFoundError("Binary not found")
    monkeypatch.setattr("subprocess.run", mock_run)
    
    with pytest.raises(FileNotFoundError, match="Trivy executable not found"):
        scanner.scan("/fake/path")

def test_llm_missing_api_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    remediator = AIRemediator()
    with pytest.raises(ValueError, match="OPENAI_API_KEY is not set"):
        remediator.generate_fix("title", "cwe", "evidence")

def test_llm_api_failure(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "fake_key")
    remediator = AIRemediator()
    
    # We must mock the actual import or initialization
    class FakeOpenAI:
        def __init__(self, *args, **kwargs):
            pass
        @property
        def chat(self):
            class Chat:
                @property
                def completions(self):
                    class Completions:
                        def create(self, *args, **kwargs):
                            raise Exception("Network error")
                    return Completions()
            return Chat()
            
    monkeypatch.setattr("openai.OpenAI", FakeOpenAI, raising=False)
    
    # If openai is installed, our FakeOpenAI will raise an Exception
    # We need to make sure the runtime error is properly captured and raised
    # Because of local imports in `generate_fix`, patching is tricky. 
    # Let's mock at the wrapper level if needed, or just let it fail naturally if openai is not patched.
    try:
        import openai
        monkeypatch.setattr("app.services.llm.OpenAI", FakeOpenAI, raising=False)
    except ImportError:
        pass
        
    with pytest.raises(RuntimeError, match="AI API failed"):
        remediator.generate_fix("title", "cwe", "evidence")

def test_generate_ai_fix_propagates_exception(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    
    # Instead of full DB mocking, we just want to ensure that if something fails inside, it raises.
    # We'll mock db session and Finding.
    class MockDB:
        def query(self, *args, **kwargs):
            return self
        def filter(self, *args, **kwargs):
            return self
        def first(self, *args, **kwargs):
            class MockFinding:
                id = "123"
                title = "Test"
                cwe = "123"
                evidence = "Test"
                remediation_plan = None
                status = "OPEN"
            return MockFinding()
        def commit(self): pass
        def rollback(self): pass
        def close(self): pass

    monkeypatch.setattr("app.workers.remediation_jobs.SessionLocal", lambda: MockDB())
    
    # generate_ai_fix should raise ValueError because OPENAI_API_KEY is not set
    with pytest.raises(ValueError, match="OPENAI_API_KEY is not set"):
        # Just call it directly, ignoring the decorator if we can, or just providing 1 string.
        # But celery wrapper might intercept. Let's just pass `None` for self, and `"123"` for finding_id.
        generate_ai_fix("123")
