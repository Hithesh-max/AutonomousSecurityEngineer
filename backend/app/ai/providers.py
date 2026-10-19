
"""AI provider abstraction for ASE.

Supports OpenAI, Google Gemini (OpenAI-compatible API),
and a deterministic mock provider for testing.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Protocol

from app.ai.errors import AIProviderError


@dataclass(frozen=True)
class ProviderResponse:
    text: str
    model: str
    prompt_tokens: int | None
    completion_tokens: int | None
    latency_ms: int


class AIProvider(Protocol):
    name: str
    model: str
    is_mock: bool
    is_external: bool

    def complete_json(
        self,
        *,
        system: str,
        user: str,
        max_output_tokens: int,
    ) -> ProviderResponse:
        ...


class OpenAIProvider:
    name = "openai"
    is_mock = False
    is_external = True

    def __init__(
        self,
        api_key: str,
        model: str,
        timeout_seconds: int,
        max_retries: int,
        client=None,
        base_url: str | None = None,
    ):
        if not api_key:
            raise ValueError("api_key is required")

        self.model = model
        self._timeout = timeout_seconds

        if client is not None:
            self._client = client
        else:
            from openai import OpenAI

            options = {
                "api_key": api_key,
                "timeout": timeout_seconds,
                "max_retries": max_retries,
            }

            if base_url:
                options["base_url"] = base_url

            self._client = OpenAI(**options)

    def complete_json(
        self,
        *,
        system: str,
        user: str,
        max_output_tokens: int,
    ) -> ProviderResponse:

        started = time.monotonic()

        try:
            response = self._client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                temperature=0,
                max_completion_tokens=max_output_tokens,
                response_format={"type": "json_object"},
            )

        except Exception as error:
            kind = type(error).__name__

            if "Timeout" in kind:
                raise AIProviderError(
                    "The AI provider timed out.",
                    "AI_TIMEOUT",
                ) from None

            if "RateLimit" in kind:
                raise AIProviderError(
                    "The AI provider rate-limited the request.",
                    "AI_RATE_LIMITED",
                ) from None

            if (
                "Authentication" in kind
                or "PermissionDenied" in kind
            ):
                raise AIProviderError(
                    "The AI provider rejected the configured credentials.",
                    "AI_AUTH_FAILED",
                ) from None

            raise AIProviderError(
                "The AI provider request failed.",
                "AI_PROVIDER_ERROR",
            ) from None

        try:
            choice = response.choices[0]
            text = choice.message.content or ""

            if getattr(choice, "finish_reason", None) == "length":
                raise AIProviderError(
                    "The AI response was truncated.",
                    "AI_OUTPUT_TRUNCATED",
                )

            usage = getattr(response, "usage", None)

            return ProviderResponse(
                text=text,
                model=str(
                    getattr(response, "model", self.model)
                ),
                prompt_tokens=getattr(
                    usage, "prompt_tokens", None
                ),
                completion_tokens=getattr(
                    usage, "completion_tokens", None
                ),
                latency_ms=int(
                    (time.monotonic() - started) * 1000
                ),
            )

        except AIProviderError:
            raise

        except Exception:
            raise AIProviderError(
                "The AI provider returned an unreadable response.",
                "AI_PROVIDER_ERROR",
            ) from None


class GeminiProvider(OpenAIProvider):
    """Google Gemini through its OpenAI-compatible API."""

    name = "gemini"
    is_mock = False
    is_external = True

    def __init__(
        self,
        api_key: str,
        model: str,
        timeout_seconds: int,
        max_retries: int,
        client=None,
    ):
        super().__init__(
            api_key=api_key,
            model=model,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
            client=client,
            base_url=(
                "https://generativelanguage.googleapis.com/"
                "v1beta/openai/"
            ),
        )

    def complete_json(
        self,
        *,
        system: str,
        user: str,
        max_output_tokens: int,
    ) -> ProviderResponse:

        started = time.monotonic()

        try:
            response = self._client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                max_tokens=max_output_tokens,
                response_format={"type": "json_object"},
            )

        except Exception as error:
            kind = type(error).__name__

            if "Timeout" in kind:
                raise AIProviderError(
                    "Gemini request timed out.",
                    "AI_TIMEOUT",
                ) from None

            if "RateLimit" in kind:
                raise AIProviderError(
                    "Gemini rate limit or quota exceeded.",
                    "AI_RATE_LIMITED",
                ) from None

            if (
                "Authentication" in kind
                or "PermissionDenied" in kind
            ):
                raise AIProviderError(
                    "Gemini rejected the API credentials.",
                    "AI_AUTH_FAILED",
                ) from None

            raise AIProviderError(
                "Gemini API request failed.",
                "AI_PROVIDER_ERROR",
            ) from None

        try:
            choice = response.choices[0]
            text = choice.message.content or ""

            if getattr(choice, "finish_reason", None) == "length":
                raise AIProviderError(
                    "Gemini response was truncated.",
                    "AI_OUTPUT_TRUNCATED",
                )

            usage = getattr(response, "usage", None)

            return ProviderResponse(
                text=text,
                model=str(
                    getattr(response, "model", self.model)
                ),
                prompt_tokens=getattr(
                    usage, "prompt_tokens", None
                ),
                completion_tokens=getattr(
                    usage, "completion_tokens", None
                ),
                latency_ms=int(
                    (time.monotonic() - started) * 1000
                ),
            )

        except AIProviderError:
            raise

        except Exception:
            raise AIProviderError(
                "Gemini returned an unreadable response.",
                "AI_PROVIDER_ERROR",
            ) from None


class MockProvider:
    """Deterministic test double, never selected in production."""

    name = "mock"
    model = "mock-deterministic"
    is_mock = True
    is_external = False

    def __init__(
        self,
        responder: Callable[[str, str], str],
    ):
        self._responder = responder
        self.calls: list[tuple[str, str]] = []

    def complete_json(
        self,
        *,
        system: str,
        user: str,
        max_output_tokens: int,
    ) -> ProviderResponse:

        self.calls.append((system, user))

        return ProviderResponse(
            text=self._responder(system, user),
            model=self.model,
            prompt_tokens=0,
            completion_tokens=0,
            latency_ms=0,
        )
