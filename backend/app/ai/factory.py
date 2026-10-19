"""Configure the real AI provider without mock fallbacks."""

import os

from app.ai.errors import AINotConfigured
from app.ai.providers import (
    AIProvider,
    OpenAIProvider,
    GeminiProvider,
)
from app.config.settings import settings


def _provider_name() -> str:
    name = (settings.AI_PROVIDER or "").strip().lower()

    if name in ("openai", "openaiprovider"):
        return "openai"

    if name in ("gemini", "geminiprovider"):
        return "gemini"

    return name


def _api_key() -> str:
    if settings.AI_API_KEY:
        return settings.AI_API_KEY.strip()

    if _provider_name() == "gemini":
        return os.environ.get("GEMINI_API_KEY", "").strip()

    return os.environ.get("OPENAI_API_KEY", "").strip()


def provider_status() -> dict:
    name = _provider_name()

    if name not in ("openai", "gemini"):
        return {
            "configured": False,
            "provider": name,
            "model": settings.AI_MODEL,
            "is_mock": False,
            "is_external": True,
            "reason": "Unsupported AI provider.",
        }

    if not _api_key():
        return {
            "configured": False,
            "provider": name,
            "model": settings.AI_MODEL,
            "is_mock": False,
            "is_external": True,
            "reason": "AI provider API key is missing.",
        }

    return {
        "configured": True,
        "provider": name,
        "model": settings.AI_MODEL,
        "is_mock": False,
        "is_external": True,
        "reason": None,
    }


def get_provider() -> AIProvider:
    status = provider_status()

    if not status["configured"]:
        raise AINotConfigured(status["reason"])

    options = {
        "api_key": _api_key(),
        "model": settings.AI_MODEL,
        "timeout_seconds": settings.AI_TIMEOUT_SECONDS,
        "max_retries": settings.AI_MAX_RETRIES,
    }

    if status["provider"] == "gemini":
        return GeminiProvider(**options)

    return OpenAIProvider(**options)