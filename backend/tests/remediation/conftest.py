import pytest

from app.api import web_scans
from app.config.settings import settings
from tests.remediation.helpers import LAB_APP, make_provider


@pytest.fixture(autouse=True)
def lab_source_and_limits(monkeypatch):
    monkeypatch.setattr(web_scans, "_LAB_SOURCE", LAB_APP)
    monkeypatch.setattr(settings, "AI_MAX_REQUESTS_PER_HOUR", 1000)


@pytest.fixture
def use_provider(monkeypatch):
    def install(provider=None):
        provider = provider or make_provider()
        monkeypatch.setattr("app.ai.factory.get_provider", lambda: provider)
        return provider
    return install


@pytest.fixture
def auth(test_user_token):
    return {"Authorization": f"Bearer {test_user_token}"}


@pytest.fixture
def auth2(test_user_2_token):
    return {"Authorization": f"Bearer {test_user_2_token}"}
