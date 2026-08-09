"""Configurable eGordian auth providers.

Secrets are read from the process environment (or an injected vault mapping)
only. They are never written to the repository, never logged, never included
in an MCP result, and never echoed by the operator console.
"""
from __future__ import annotations

import base64
import json
import os
import threading
import time
from dataclasses import dataclass
from typing import Any, Protocol

from ..config import Settings


class CredentialRequired(RuntimeError):
    """No usable eGordian credential is configured for this deployment."""


class AuthProvider(Protocol):
    name: str

    def headers(self, fetch_json: Any | None = None) -> dict[str, str]:
        ...

    def status(self) -> dict[str, Any]:
        ...


@dataclass
class NoneProvider:
    name: str = "none"

    def headers(self, fetch_json: Any | None = None) -> dict[str, str]:
        raise CredentialRequired(
            "No eGordian credentials are configured. Set EGORDIAN_AUTH_PROVIDER and the "
            "matching environment variables to enable live calls."
        )

    def status(self) -> dict[str, Any]:
        return {"provider": "none", "configured": False, "connected": False}


@dataclass
class BearerProvider:
    token: str
    name: str = "bearer"

    def headers(self, fetch_json: Any | None = None) -> dict[str, str]:
        if not self.token:
            raise CredentialRequired("EGORDIAN_BEARER_TOKEN is not set.")
        return {"Authorization": f"Bearer {self.token}"}

    def status(self) -> dict[str, Any]:
        return {"provider": "bearer", "configured": bool(self.token), "connected": bool(self.token)}


@dataclass
class HeaderMapProvider:
    """Multi-header provider: EGORDIAN_HEADER_MAP maps header name -> env var name."""
    mapping: dict[str, str]
    name: str = "headers"

    def headers(self, fetch_json: Any | None = None) -> dict[str, str]:
        out: dict[str, str] = {}
        missing: list[str] = []
        for header, env_name in self.mapping.items():
            value = os.getenv(env_name, "")
            if not value:
                missing.append(env_name)
            else:
                out[header] = value
        if missing:
            raise CredentialRequired(
                "Missing environment variable(s) for the header auth provider: "
                + ", ".join(sorted(missing))
            )
        return out

    def status(self) -> dict[str, Any]:
        present = {h: bool(os.getenv(e, "")) for h, e in self.mapping.items()}
        return {"provider": "headers", "configured": bool(self.mapping),
                "connected": bool(self.mapping) and all(present.values()),
                "header_names": sorted(self.mapping.keys())}


class BasicAccessTokenProvider:
    """Exchange Basic credentials for a token via the documented GET api/AccessToken.

    Route source: https://jocservice.egordian.com/Help (AccessToken section).
    """

    name = "basic"
    ROUTE = "api/AccessToken"
    DEFAULT_TTL_S = 1500

    def __init__(self, username: str, password: str, ttl_s: int = DEFAULT_TTL_S):
        self.username = username
        self.password = password
        self.ttl_s = ttl_s
        self._token: str | None = None
        self._expires_at: float = 0.0
        self._lock = threading.Lock()

    def _basic_header(self) -> dict[str, str]:
        raw = f"{self.username}:{self.password}".encode()
        return {"Authorization": "Basic " + base64.b64encode(raw).decode()}

    def headers(self, fetch_json: Any | None = None) -> dict[str, str]:
        if not (self.username and self.password):
            raise CredentialRequired("EGORDIAN_USERNAME / EGORDIAN_PASSWORD are not set.")
        with self._lock:
            if self._token and time.time() < self._expires_at:
                return {"Authorization": f"Bearer {self._token}"}
            if fetch_json is None:
                # Caller could not supply a transport; fall back to Basic directly.
                return self._basic_header()
            payload = fetch_json(self.ROUTE, self._basic_header())
            token = _extract_token(payload)
            if not token:
                raise CredentialRequired(
                    "GET api/AccessToken did not return a recognizable access token.")
            self._token = token
            self._expires_at = time.time() + self.ttl_s
            return {"Authorization": f"Bearer {token}"}

    def status(self) -> dict[str, Any]:
        configured = bool(self.username and self.password)
        return {"provider": "basic", "configured": configured,
                "connected": configured and bool(self._token),
                "token_route": self.ROUTE}


def _extract_token(payload: Any) -> str | None:
    if isinstance(payload, str):
        return payload.strip().strip('"') or None
    if isinstance(payload, dict):
        for key in ("access_token", "accessToken", "AccessToken", "token", "Token", "value"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None


def build_provider(settings: Settings) -> AuthProvider:
    kind = settings.egordian_auth_provider
    if kind == "bearer":
        return BearerProvider(settings.egordian_bearer_token)
    if kind == "basic":
        return BasicAccessTokenProvider(settings.egordian_username, settings.egordian_password)
    if kind == "headers":
        try:
            mapping = json.loads(settings.egordian_header_map or "{}")
        except json.JSONDecodeError:
            mapping = {}
        return HeaderMapProvider({str(k): str(v) for k, v in mapping.items()})
    return NoneProvider()
