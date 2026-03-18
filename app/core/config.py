from pydantic_settings import BaseSettings
from pydantic import field_validator
from typing import ClassVar


class Settings(BaseSettings):
    # Application
    APP_ENV: str = "development"
    SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    RESET_TOKEN_EXPIRE_MINUTES: int = 15

    # Database
    DATABASE_URL: str

    # Email
    MAIL_USERNAME: str = ""
    MAIL_PASSWORD: str = ""
    MAIL_FROM: str = "noreply@iot-security-suite.dev"
    MAIL_PORT: int = 587
    MAIL_SERVER: str = "sandbox.smtp.mailtrap.io"
    MAIL_STARTTLS: bool = True
    MAIL_SSL_TLS: bool = False

    # Rate limiting
    RATE_LIMIT_MAX_ATTEMPTS: int = 5
    RATE_LIMIT_WINDOW_SECONDS: int = 60

    # Test framework
    TARGET_BASE_URL: str = "http://localhost:8000"
    BRUTE_FORCE_WORKERS: int = 5
    TEST_REQUEST_TIMEOUT: int = 10

    ALLOWED_ENVIRONMENTS: ClassVar[list[str]] = [
        "development",
        "testing",
        "production",
    ]

    @field_validator("APP_ENV")
    @classmethod
    def validate_env(cls, v: str) -> str:
        allowed = ["development", "testing", "production"]
        if v not in allowed:
            raise ValueError(f"APP_ENV must be one of {allowed}")
        return v

    model_config = {"env_file": ".env",  "case_sensitive": True, "extra": "ignore"}

settings = Settings()