"""Loopback-only Okta access-token API for the IAM lab."""

from __future__ import annotations

import json
import logging
import math
import re
import time
import uuid
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

import jwt
from flask import Flask, jsonify, request
from jwt import InvalidTokenError
from jwt import PyJWKClient
from jwt.exceptions import PyJWKClientConnectionError
from werkzeug.serving import WSGIRequestHandler

from .config import OktaConfig, load_config


TENANTS = ("acme", "globex")
ENVIRONMENTS = ("dev", "prod")
MAX_MESSAGE_BYTES = 2048
# Permit worst-case JSON escapes without relaxing the decoded message limit.
MAX_BODY_BYTES = MAX_MESSAGE_BYTES * 6 + 128
JIT_GROUP = "iam-lab-jit-candidates"
_BEARER_TOKEN = re.compile(r"Bearer ([A-Za-z0-9._~-]+)\Z")
_LOG = logging.getLogger("okta_lab.audit")


class SafeRequestHandler(WSGIRequestHandler):
    """Avoid logging request targets, headers, tokens, or exception details."""

    def log_request(self, code: int | str = "-", size: int | str = "-") -> None:
        try:
            status = int(code)
        except (TypeError, ValueError):
            status = 0
        _LOG.info(
            json.dumps(
                {"action": "http_request", "status": status, "scope": "http"},
                separators=(",", ":"),
                sort_keys=True,
            )
        )

    def log_error(self, *_args: Any, **_kwargs: Any) -> None:
        _LOG.error('{"action":"http_error","status":500,"scope":"http"}')


class JwtVerifier:
    """Verify Okta custom-authorization-server access tokens via cached JWKS."""

    def __init__(self, config: OktaConfig | Mapping[str, Any], jwks_client: Any | None = None):
        self.config = config
        self.jwks_client = jwks_client or PyJWKClient(
            f"{_config_value(config, 'issuer')}/v1/keys",
            cache_jwk_set=True,
            lifespan=300,
            timeout=5,
        )

    def verify(self, token: str) -> dict[str, Any]:
        try:
            signing_key = self.jwks_client.get_signing_key_from_jwt(token)
        except PyJWKClientConnectionError as exc:
            raise JwksUnavailable from exc
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            issuer=_config_value(self.config, "issuer"),
            audience=_config_value(self.config, "audience"),
            options={"require": ["iss", "aud", "exp", "iat", "sub", "uid", "cid", "scp", "groups"]},
        )
        if not isinstance(claims.get("sub"), str) or not claims["sub"]:
            raise InvalidTokenError("invalid subject")
        if not _is_okta_uid(claims.get("uid")):
            raise InvalidTokenError("invalid Okta user identifier")
        if claims.get("cid") != _config_value(self.config, "client_id"):
            raise InvalidTokenError("invalid client")
        if not _string_list(claims.get("scp")) or not _string_list(claims.get("groups")):
            raise InvalidTokenError("invalid access-token claims")
        return claims

    def ready(self) -> None:
        try:
            if not self.jwks_client.get_signing_keys():
                raise JwksUnavailable
        except PyJWKClientConnectionError as exc:
            raise JwksUnavailable from exc


class JwksUnavailable(Exception):
    """Okta signing keys could not be fetched."""


def _config_value(
    config: OktaConfig | Mapping[str, Any], name: str, default: Any = None
) -> Any:
    if isinstance(config, Mapping):
        return config.get(name, default)
    return getattr(config, name, default)


def _string_list(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _is_okta_uid(value: object) -> bool:
    return isinstance(value, str) and value.startswith("00u") and len(value) > 3


def _audit(action: str, status: int, scope: str) -> None:
    _LOG.info(
        json.dumps(
            {"action": action, "status": status, "scope": scope},
            separators=(",", ":"),
            sort_keys=True,
        )
    )


def _read_access_policy(
    path: Path,
) -> tuple[set[str], dict[str, dict[str, float]], dict[str, int]]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            policy = json.load(handle)
    except FileNotFoundError:
        return set(), {}, {}
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise RuntimeError("access policy unavailable") from None
    if (
        not isinstance(policy, dict)
        or not {"blocked_subjects", "grants"}.issubset(policy)
        or set(policy) - {"blocked_subjects", "grants", "not_before"}
    ):
        raise RuntimeError("access policy invalid")
    blocked = policy["blocked_subjects"]
    grants = policy["grants"]
    not_before = policy.get("not_before", {})
    if (
        not _string_list(blocked)
        or not all(_is_okta_uid(uid) for uid in blocked)
        or not isinstance(grants, dict)
        or not isinstance(not_before, dict)
    ):
        raise RuntimeError("access policy invalid")
    parsed_grants: dict[str, dict[str, float]] = {}
    allowed_scopes = {
        f"{tenant}/{environment}"
        for tenant in TENANTS
        for environment in ENVIRONMENTS
    }
    for uid, scope_grants in grants.items():
        if not _is_okta_uid(uid) or not isinstance(scope_grants, dict):
            raise RuntimeError("access policy invalid")
        parsed_grants[uid] = {}
        for scope, expires_at in scope_grants.items():
            if (
                scope not in allowed_scopes
                or isinstance(expires_at, bool)
                or not isinstance(expires_at, (int, float))
                or not math.isfinite(expires_at)
                or expires_at <= 0
            ):
                raise RuntimeError("access policy invalid")
            parsed_grants[uid][scope] = float(expires_at)
    parsed_not_before: dict[str, int] = {}
    for uid, timestamp in not_before.items():
        if (
            not _is_okta_uid(uid)
            or isinstance(timestamp, bool)
            or not isinstance(timestamp, int)
            or timestamp < 0
        ):
            raise RuntimeError("access policy invalid")
        parsed_not_before[uid] = timestamp
    return set(blocked), parsed_grants, parsed_not_before


def create_app(
    config: OktaConfig | Mapping[str, Any] | None = None,
    jwt_verifier: Any | None = None,
) -> Flask:
    """Build the API; tests can inject a verifier without contacting Okta."""
    active_config = config or load_config()
    verifier = jwt_verifier if jwt_verifier is not None else JwtVerifier(active_config)
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_BYTES

    @app.errorhandler(413)
    def request_too_large(_error: Exception):
        return jsonify(error="request_too_large"), 413

    def token_claims() -> tuple[dict[str, Any] | None, tuple[Any, int] | None]:
        header = request.headers.get("Authorization", "")
        match = _BEARER_TOKEN.fullmatch(header)
        if not match:
            return None, (jsonify(error="unauthorized"), 401)
        try:
            claims = (
                verifier.verify(match.group(1))
                if hasattr(verifier, "verify")
                else verifier(match.group(1))
            )
        except JwksUnavailable:
            return None, (jsonify(error="authorization_unavailable"), 503)
        except Exception:
            return None, (jsonify(error="unauthorized"), 401)
        if (
            not isinstance(claims, dict)
            or not isinstance(claims.get("sub"), str)
            or not claims["sub"]
            or not _is_okta_uid(claims.get("uid"))
            or claims.get("cid") != _config_value(active_config, "client_id")
            or not _string_list(claims.get("scp"))
            or not _string_list(claims.get("groups"))
        ):
            return None, (jsonify(error="unauthorized"), 401)
        token_iat = claims.get("iat")
        if isinstance(token_iat, bool) or not isinstance(token_iat, (int, float)):
            return None, (jsonify(error="unauthorized"), 401)
        try:
            blocked, grants, not_before = _read_access_policy(
                Path(_config_value(active_config, "access_file", ".runtime/access.json"))
            )
        except RuntimeError:
            return None, (jsonify(error="authorization_unavailable"), 503)
        if claims["uid"] in blocked or token_iat < not_before.get(claims["uid"], 0):
            return None, (jsonify(error="forbidden"), 403)
        claims["_iam_lab_grants"] = grants
        claims["_iam_lab_not_before"] = not_before
        return claims, None

    @app.get("/healthz")
    def healthz():
        return jsonify(status="ok"), 200

    @app.get("/readyz")
    def readyz():
        try:
            if hasattr(verifier, "ready"):
                verifier.ready()
        except Exception:
            return jsonify(status="unavailable"), 503
        return jsonify(status="ready"), 200

    @app.get("/me")
    def me():
        claims, error = token_claims()
        if error:
            _audit("me", error[1], "self")
            return error
        permissions = sorted({scope for scope in claims["scp"] if scope == "messages.send"})
        _audit("me", 200, "self")
        return jsonify(permissions=permissions), 200

    @app.post("/tenants/<tenant>/<environment>/messages")
    def submit_message(tenant: str, environment: str):
        if tenant not in TENANTS or environment not in ENVIRONMENTS:
            _audit("message", 404, "invalid")
            return jsonify(error="not_found"), 404
        scope = f"{tenant}/{environment}"
        claims, error = token_claims()
        if error:
            _audit("message", error[1], scope)
            return error
        body = request.get_json(silent=True)
        if (
            not isinstance(body, dict)
            or set(body) != {"message"}
            or not isinstance(body["message"], str)
        ):
            _audit("message", 400, scope)
            return jsonify(error="invalid_request"), 400
        try:
            message_size = len(body["message"].encode("utf-8"))
        except UnicodeEncodeError:
            message_size = MAX_MESSAGE_BYTES + 1
        if not body["message"] or message_size > MAX_MESSAGE_BYTES:
            _audit("message", 400, scope)
            return jsonify(error="invalid_request"), 400
        if "messages.send" not in claims["scp"]:
            _audit("message", 403, scope)
            return jsonify(error="forbidden"), 403

        expected_group = f"iam-lab-{tenant}-{environment}-submitters"
        groups = claims["groups"]
        grants = claims["_iam_lab_grants"]
        grant_expiration = grants.get(claims["uid"], {}).get(scope)
        has_jit_grant = (
            JIT_GROUP in groups
            and grant_expiration is not None
            and grant_expiration > time.time()
        )
        if expected_group not in groups and not has_jit_grant:
            _audit("message", 403, scope)
            return jsonify(error="forbidden"), 403

        _audit("message", 202, scope)
        return jsonify(
            status="accepted",
            tenant=tenant,
            environment=environment,
            message_id=uuid.uuid4().hex,
        ), 202

    return app


def main() -> None:
    config = load_config()
    app = create_app(config)
    origin = urlsplit(str(config["api_origin"]))
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    app.run(
        host=origin.hostname or "127.0.0.1",
        port=origin.port or 8090,
        threaded=True,
        request_handler=SafeRequestHandler,
    )


if __name__ == "__main__":
    main()
