"""Configuration loading and validation for the local Okta lab."""

from __future__ import annotations

import ipaddress
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


_OKTA_DOMAINS = ("okta.com", "oktapreview.com", "okta-emea.com")
_AUTH_SERVER_ID = re.compile(r"[A-Za-z0-9_-]+\Z")
_CONFIG_KEYS = {
    "org_url",
    "issuer",
    "client_id",
    "audience",
    "api_origin",
    "auth_server_id",
}


@dataclass(frozen=True)
class OktaConfig:
    org_url: str
    client_id: str
    audience: str = "api://iam-lab"
    api_origin: str = "http://127.0.0.1:8090"
    auth_server_id: str = "default"
    access_file: Path = Path(".runtime/access.json")

    def __getitem__(self, key: str) -> str | Path:
        if key not in {
            "org_url",
            "issuer",
            "client_id",
            "audience",
            "api_origin",
            "auth_server_id",
            "access_file",
        }:
            raise KeyError(key)
        return getattr(self, key)

    @property
    def issuer(self) -> str:
        return f"{self.org_url}/oauth2/{self.auth_server_id}"

    @property
    def jwks_url(self) -> str:
        return f"{self.issuer}/v1/keys"

    @property
    def bind_host(self) -> str:
        return urlsplit(self.api_origin).hostname or "127.0.0.1"

    @property
    def bind_port(self) -> int:
        return urlsplit(self.api_origin).port or 8090


def _nonempty_string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ValueError(f"{field} must be a non-empty string")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError(f"{field} contains invalid characters")
    return value


def _validate_org_url(value: object) -> str:
    org_url = _nonempty_string(value, "org_url")
    try:
        parsed = urlsplit(org_url)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        raise ValueError("org_url must be an Okta organization URL") from None
    if (
        parsed.scheme != "https"
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("org_url must be an HTTPS Okta organization URL")
    hostname = host.lower().rstrip(".")
    if not any(hostname.endswith(f".{domain}") for domain in _OKTA_DOMAINS):
        raise ValueError("org_url hostname must use an approved Okta domain")
    if hostname in _OKTA_DOMAINS:
        raise ValueError("org_url must name an Okta organization")
    return f"https://{hostname}"


def _validate_api_origin(value: object) -> str:
    origin = _nonempty_string(value, "api_origin")
    try:
        parsed = urlsplit(origin)
        host = parsed.hostname
        port = parsed.port
        is_loopback = host == "localhost" or (
            host is not None and ipaddress.ip_address(host).is_loopback
        )
    except ValueError:
        parsed = urlsplit("")
        is_loopback = False
        host = None
        port = None
    if (
        parsed.scheme != "http"
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or not is_loopback
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise ValueError("api_origin must be a loopback HTTP origin")
    bind_host = host.lower()
    if ":" in bind_host:
        bind_host = f"[{bind_host}]"
    return f"http://{bind_host}:{port or 8090}"


def _config_from_mapping(data: object) -> OktaConfig:
    if not isinstance(data, dict):
        raise ValueError("Okta configuration must be a JSON object")
    if set(data) - _CONFIG_KEYS:
        raise ValueError("Okta configuration contains unsupported fields")
    org_url = _validate_org_url(data.get("org_url"))
    client_id = _nonempty_string(data.get("client_id"), "client_id")
    audience = _nonempty_string(data.get("audience", "api://iam-lab"), "audience")
    if audience != "api://iam-lab":
        raise ValueError("audience must be api://iam-lab")
    api_origin = _validate_api_origin(data.get("api_origin", "http://127.0.0.1:8090"))
    explicit_auth_server_id = data.get("auth_server_id")
    if explicit_auth_server_id is not None:
        explicit_auth_server_id = _nonempty_string(explicit_auth_server_id, "auth_server_id")
        if not _AUTH_SERVER_ID.fullmatch(explicit_auth_server_id):
            raise ValueError("auth_server_id must be a safe path segment")
    configured_issuer = data.get(
        "issuer",
        f"{org_url}/oauth2/{explicit_auth_server_id or 'default'}",
    )
    configured_issuer = _nonempty_string(configured_issuer, "issuer")
    try:
        parsed_issuer = urlsplit(configured_issuer)
        issuer_port = parsed_issuer.port
    except ValueError:
        raise ValueError("issuer must match the configured Okta organization") from None
    issuer_path = parsed_issuer.path
    prefix = "/oauth2/"
    auth_server_id = issuer_path[len(prefix) :] if issuer_path.startswith(prefix) else ""
    if (
        parsed_issuer.scheme != "https"
        or (parsed_issuer.hostname or "").lower() != urlsplit(org_url).hostname
        or parsed_issuer.username is not None
        or parsed_issuer.password is not None
        or issuer_port is not None
        or not _AUTH_SERVER_ID.fullmatch(auth_server_id)
        or (
            explicit_auth_server_id is not None
            and (
                not _AUTH_SERVER_ID.fullmatch(explicit_auth_server_id)
                or explicit_auth_server_id != auth_server_id
            )
        )
        or parsed_issuer.query
        or parsed_issuer.fragment
    ):
        raise ValueError("issuer must be an HTTPS Okta authorization server for this org")
    return OktaConfig(
        org_url=org_url,
        client_id=client_id,
        audience=audience,
        api_origin=api_origin,
        auth_server_id=auth_server_id,
    )


def load_config(path: str | os.PathLike[str] | None = None) -> dict[str, str]:
    """Load JSON configuration from the OKTA_CONFIG path or local default."""
    config_path = Path(path or os.environ.get("OKTA_CONFIG", "config/local.json"))
    try:
        with config_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise ValueError("could not read valid Okta JSON configuration") from None
    config = _config_from_mapping(data)
    return {
        "org_url": config.org_url,
        "issuer": config.issuer,
        "client_id": config.client_id,
        "audience": config.audience,
        "api_origin": config.api_origin,
    }
