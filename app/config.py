"""Environment-driven configuration. Secrets are read from the environment only.

Nothing in this module may be persisted to SQLite/Postgres, written to logs,
returned in an MCP result, or rendered by the operator console.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

MCP_PROTOCOL_VERSION = "2026-07-28"
LEGACY_MCP_PROTOCOL_VERSION = "2025-06-18"
SERVICE_NAME = "egordian-aeo-mcp"
SERVICE_VERSION = "1.0.0"

EGORDIAN_BASE_URL_DEFAULT = "https://jocservice.egordian.com"

ALL_SCOPES = (
    "catalogue:read",
    "egordian:read",
    "egordian:write",
    "aeo:run",
    "aeo:approve",
    "admin",
)


def _bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, "") or default)
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    # --- deployment -------------------------------------------------------
    deployment_env: str = field(default_factory=lambda: os.getenv("DEPLOYMENT_ENV", "preview"))
    port: int = field(default_factory=lambda: _int("PORT", 8080))
    host: str = field(default_factory=lambda: os.getenv("HOST", "0.0.0.0"))
    public_base_url: str = field(default_factory=lambda: os.getenv("PUBLIC_BASE_URL", ""))

    # --- auth -------------------------------------------------------------
    auth_mode: str = field(default_factory=lambda: os.getenv("AUTH_MODE", "bearer"))
    # SERVICE_TOKENS format: "token|user|project1,project2|scope1,scope2; ..."
    service_tokens_raw: str = field(default_factory=lambda: os.getenv("SERVICE_TOKENS", ""))

    # --- persistence ------------------------------------------------------
    database_url: str = field(default_factory=lambda: os.getenv("DATABASE_URL", ""))
    overlay_db_path: str = field(
        default_factory=lambda: os.getenv("OVERLAY_DB_PATH", str(PROJECT_ROOT / "data.db"))
    )
    catalogue_db_path: str = field(
        default_factory=lambda: os.getenv(
            "CATALOGUE_DB_PATH", str(PROJECT_ROOT / "data" / "catalogue.sqlite")
        )
    )

    # --- eGordian ---------------------------------------------------------
    egordian_base_url: str = field(
        default_factory=lambda: os.getenv("EGORDIAN_BASE_URL", EGORDIAN_BASE_URL_DEFAULT)
    )
    egordian_auth_provider: str = field(
        default_factory=lambda: os.getenv("EGORDIAN_AUTH_PROVIDER", "none")
    )
    egordian_username: str = field(default_factory=lambda: os.getenv("EGORDIAN_USERNAME", ""))
    egordian_password: str = field(default_factory=lambda: os.getenv("EGORDIAN_PASSWORD", ""))
    egordian_bearer_token: str = field(default_factory=lambda: os.getenv("EGORDIAN_BEARER_TOKEN", ""))
    # JSON object of header-name -> env-var-name, e.g. {"Ocp-Apim-Key":"EG_APIM_KEY"}
    egordian_header_map: str = field(default_factory=lambda: os.getenv("EGORDIAN_HEADER_MAP", ""))
    egordian_timeout_s: float = field(default_factory=lambda: float(os.getenv("EGORDIAN_TIMEOUT_S", "20")))
    egordian_max_response_bytes: int = field(
        default_factory=lambda: _int("EGORDIAN_MAX_RESPONSE_BYTES", 4 * 1024 * 1024)
    )
    egordian_max_retries: int = field(default_factory=lambda: _int("EGORDIAN_MAX_RETRIES", 2))

    # --- capability switches (all mutating paths default OFF) -------------
    allow_egordian_writes: bool = field(default_factory=lambda: _bool("ALLOW_EGORDIAN_WRITES", False))
    allow_egordian_delete: bool = field(default_factory=lambda: _bool("ALLOW_EGORDIAN_DELETE", False))
    allow_admin_operations: bool = field(default_factory=lambda: _bool("ALLOW_ADMIN_OPERATIONS", False))
    egordian_write_mode: str = field(default_factory=lambda: os.getenv("EGORDIAN_WRITE_MODE", "assisted"))

    # --- limits -----------------------------------------------------------
    max_request_bytes: int = field(default_factory=lambda: _int("MAX_REQUEST_BYTES", 1024 * 1024))
    rate_limit_per_minute: int = field(default_factory=lambda: _int("RATE_LIMIT_PER_MINUTE", 120))
    catalogue_max_results: int = field(default_factory=lambda: _int("CATALOGUE_MAX_RESULTS", 50))
    handle_ttl_hours: int = field(default_factory=lambda: _int("HANDLE_TTL_HOURS", 8))

    # --- legacy client support -------------------------------------------
    allow_legacy_2025_clients: bool = field(
        default_factory=lambda: _bool("ALLOW_LEGACY_2025_CLIENTS", False)
    )

    def validate(self) -> list[str]:
        problems: list[str] = []
        if self.auth_mode not in {"bearer", "dev"}:
            problems.append(f"AUTH_MODE must be 'bearer' or 'dev', got {self.auth_mode!r}")
        if self.auth_mode == "dev" and self.deployment_env == "production":
            problems.append("AUTH_MODE=dev is refused when DEPLOYMENT_ENV=production")
        if self.egordian_auth_provider not in {"none", "basic", "bearer", "headers"}:
            problems.append("EGORDIAN_AUTH_PROVIDER must be none|basic|bearer|headers")
        if self.egordian_write_mode not in {"assisted", "gated_auto"}:
            problems.append("EGORDIAN_WRITE_MODE must be assisted|gated_auto")
        if not self.egordian_base_url.startswith("https://"):
            problems.append("EGORDIAN_BASE_URL must be https")
        return problems

    @property
    def egordian_credentials_present(self) -> bool:
        p = self.egordian_auth_provider
        if p == "basic":
            return bool(self.egordian_username and self.egordian_password)
        if p == "bearer":
            return bool(self.egordian_bearer_token)
        if p == "headers":
            return bool(self.egordian_header_map)
        return False

    @property
    def repository_backend(self) -> str:
        return "postgres" if self.database_url else "sqlite"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    get_settings.cache_clear()
