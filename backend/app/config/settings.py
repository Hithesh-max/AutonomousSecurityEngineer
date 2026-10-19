from pathlib import Path
from pydantic_settings import BaseSettings
from pydantic import Field, field_validator, SecretStr

class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql://ase_user:ase_password@localhost:5432/ase_db"
    REDIS_URL: str = "redis://localhost:6379/0"
    JWT_SECRET: str = Field(..., min_length=32, description="Must be at least 32 characters long. No default fallback.")
    
    @field_validator('JWT_SECRET')
    @classmethod
    def check_jwt_secret(cls, v: str) -> str:
        if v == "super_secret_key_change_me_in_prod" or "change_me_in_prod" in v:
            raise ValueError("JWT_SECRET contains a known placeholder value. Please use a secure random secret.")
        return v
    
    # AI Config
    AI_PROVIDER: str = "OpenAIProvider"
    AI_MODEL: str = "gpt-4o"
    AI_API_KEY: str = ""
    # AI remediation limits (Stage 3). All bounded; external transmission also needs per-request consent.
    AI_TIMEOUT_SECONDS: int = Field(45, ge=5, le=120)
    AI_MAX_RETRIES: int = Field(1, ge=0, le=3)
    AI_MAX_OUTPUT_TOKENS: int = Field(1500, ge=256, le=4000)
    AI_MAX_CONTEXT_CHARS: int = Field(16000, ge=2000, le=60000)
    AI_MAX_REQUESTS_PER_HOUR: int = Field(20, ge=1, le=500)
    
    ZIP_MAX_UPLOAD_BYTES: int = Field(20 * 1024 * 1024, ge=1024, le=100 * 1024 * 1024)
    ZIP_MAX_EXPANDED_BYTES: int = Field(100 * 1024 * 1024, ge=1024, le=500 * 1024 * 1024)
    ZIP_MAX_FILE_BYTES: int = Field(5 * 1024 * 1024, ge=1024, le=20 * 1024 * 1024)
    ZIP_MAX_ENTRIES: int = Field(3000, ge=1, le=10000)
    ZIP_MAX_COMPRESSION_RATIO: int = Field(100, ge=1, le=200)
    ZIP_UPLOAD_SECONDS: int = Field(60, ge=1, le=120)
    REPOSITORY_LIMIT_PER_USER: int = Field(50, ge=1, le=100)

    # Ciphertext-only share storage. The browser retains the decryption key.
    SECURE_SHARE_STORAGE_DIR: str = "./secure-shares"
    SECURE_SHARE_MAX_BYTES: int = Field(50 * 1024 * 1024, ge=1024, le=200 * 1024 * 1024)
    SECURE_SHARE_RETENTION_HOURS: int = Field(24, ge=1, le=168)
    SECURE_SHARE_MAX_DOWNLOADS: int = Field(5, ge=1, le=100)

    LAB_SCANNING_ENABLED: bool = False
    ZAP_API_KEY: SecretStr = SecretStr("")

    OPENAI_API_KEY: str = ""
    GEMINI_API_KEY: str = ""

    # Scanner Paths
    SCAN_WORKSPACE_ROOT: str = "./workspaces"
    
    model_config = {
        "env_file": ".env",
        "extra": "ignore"
    }

settings = Settings()
