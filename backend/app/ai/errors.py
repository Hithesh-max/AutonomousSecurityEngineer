"""Typed AI errors. Messages are safe to show to users: they never contain credentials or prompts."""


class AIError(Exception):
    code = "AI_ERROR"
    http_status = 502

    def __init__(self, message: str, code: str | None = None):
        super().__init__(message)
        self.message = message
        if code:
            self.code = code


class AINotConfigured(AIError):
    code = "AI_PROVIDER_NOT_CONFIGURED"
    http_status = 503


class AIProviderError(AIError):
    code = "AI_PROVIDER_ERROR"
    http_status = 502


class AIOutputInvalid(AIError):
    """The model answered, but not with data that passes ASE's validation. Never stored as a result."""
    code = "AI_OUTPUT_INVALID"
    http_status = 502
