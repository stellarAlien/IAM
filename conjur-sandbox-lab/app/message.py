#!/usr/bin/env python3
"""Tenant-scoped message API backed by Conjur secrets."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import socket
import sys
import uuid
from http.server import BaseHTTPRequestHandler
from typing import Any

from app import BoundedThreadingHTTPServer, ConjurClient, ConjurError, REQUEST_TIMEOUT


TENANTS = ("acme", "globex")
ENVIRONMENTS = ("dev", "prod")
MAX_BODY_BYTES = 4096
MAX_MESSAGE_BYTES = 2048


def validate_scope(tenant: str, environment: str) -> tuple[str, str]:
    if tenant not in TENANTS:
        raise ValueError("TENANT must be acme or globex")
    if environment not in ENVIRONMENTS:
        raise ValueError("ENVIRONMENT must be dev or prod")
    return tenant, environment


def secret_name(tenant: str, environment: str, name: str) -> str:
    return f"tenants/{tenant}/{environment}/secrets/{name}"


def make_message_client_from_env() -> tuple[ConjurClient, str, str]:
    tenant, environment = validate_scope(
        os.environ.get("TENANT", ""), os.environ.get("ENVIRONMENT", "")
    )
    expected_login = f"host/tenants/{tenant}/{environment}/api"
    login = os.environ.get("CONJUR_AUTHN_LOGIN", expected_login)
    if login != expected_login:
        raise ValueError("CONJUR_AUTHN_LOGIN does not match configured scope")
    try:
        timeout = float(os.environ.get("CONJUR_TIMEOUT_SECONDS", str(REQUEST_TIMEOUT)))
    except ValueError:
        raise ValueError("CONJUR_TIMEOUT_SECONDS must be a number") from None
    client = ConjurClient(
        appliance_url=os.environ.get("CONJUR_APPLIANCE_URL", ""),
        account=os.environ.get("CONJUR_ACCOUNT", "sandbox"),
        login=expected_login,
        api_key=os.environ.get("CONJUR_AUTHN_API_KEY"),
        api_key_file=os.environ.get("CONJUR_AUTHN_API_KEY_FILE", "/run/secrets/host_api_key"),
        cert_file=os.environ.get("CONJUR_CERT_FILE"),
        timeout=timeout,
    )
    return client, tenant, environment


class MessageService:
    def __init__(self, client: ConjurClient, tenant: str, environment: str):
        self.tenant, self.environment = validate_scope(tenant, environment)
        self.client = client

    def _secret(self, name: str) -> bytes:
        value = self.client.get_secret(secret_name(self.tenant, self.environment, name))
        if not value:
            raise ConjurError("Configured secret is empty")
        return value

    def ready(self) -> None:
        self._secret("ingress-token")
        self._secret("signing-key")

    def authenticate(self, authorization: str | None) -> bool:
        expected = self._secret("ingress-token")
        supplied = b""
        well_formed = authorization is not None and authorization.startswith("Bearer ")
        if well_formed:
            token = authorization[7:]
            if token and " " not in token and "\t" not in token:
                try:
                    supplied = token.encode("ascii")
                except UnicodeEncodeError:
                    well_formed = False
            else:
                well_formed = False
        matches = hmac.compare_digest(expected, supplied)
        return well_formed and matches

    def accept(self, message: str) -> None:
        key = self._secret("signing-key")
        hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


def check_permissions(client: ConjurClient, tenant: str, environment: str) -> None:
    validate_scope(tenant, environment)
    own = (
        secret_name(tenant, environment, "ingress-token"),
        secret_name(tenant, environment, "signing-key"),
    )
    for variable in own:
        client.get_secret(variable)
    for other_tenant in TENANTS:
        for other_environment in ENVIRONMENTS:
            if (other_tenant, other_environment) == (tenant, environment):
                continue
            for name in ("ingress-token", "signing-key"):
                try:
                    client.get_secret(secret_name(other_tenant, other_environment, name))
                except ConjurError as exc:
                    if exc.status in (403, 404):
                        continue
                    raise
                raise ConjurError("Configured identity can read another scope's secret")


def handler_for(service: MessageService) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "ConjurMessageAPI/1.0"
        sys_version = ""

        def setup(self) -> None:
            super().setup()
            self.connection.settimeout(REQUEST_TIMEOUT)

        def log_message(self, _fmt: str, *_args: Any) -> None:
            status = getattr(self, "_response_status", "-")
            sys.stderr.write(f"http: {self.command} {status}\n")

        def _send(self, status: int, body: dict[str, Any]) -> None:
            encoded = json.dumps(body, separators=(",", ":")).encode("utf-8")
            self._response_status = status
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(encoded)

        def do_GET(self) -> None:
            if self.path == "/healthz":
                self._send(200, {"status": "ok"})
                return
            if self.path == "/readyz":
                try:
                    service.ready()
                except Exception:
                    self._send(503, {"status": "not_ready"})
                    return
                self._send(200, {"status": "ready"})
                return
            self._send(404, {"error": "not_found"})

        def do_POST(self) -> None:
            if self.path != "/messages":
                self._send(404, {"error": "not_found"})
                return
            if self.headers.get_all("Transfer-Encoding", []):
                self._send(400, {"error": "invalid_request"})
                return
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) != 1 or not re.fullmatch(r"[0-9]+", lengths[0]):
                self._send(400, {"error": "invalid_request"})
                return
            normalized_length = lengths[0].lstrip("0") or "0"
            if len(normalized_length) > 4 or int(normalized_length) > MAX_BODY_BYTES:
                self._send(413, {"error": "request_too_large"})
                return
            if self.headers.get_content_type() != "application/json":
                self._send(415, {"error": "application_json_required"})
                return
            try:
                raw = self.rfile.read(int(normalized_length))
            except (OSError, socket.timeout):
                self._send(408, {"error": "invalid_request"})
                return
            if len(raw) != int(normalized_length):
                self._send(400, {"error": "invalid_request"})
                return
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                self._send(400, {"error": "invalid_message"})
                return
            if not isinstance(payload, dict) or set(payload) != {"message"}:
                self._send(400, {"error": "invalid_message"})
                return
            message = payload["message"]
            if not isinstance(message, str):
                self._send(400, {"error": "invalid_message"})
                return
            try:
                message_bytes = message.encode("utf-8")
            except UnicodeEncodeError:
                self._send(400, {"error": "invalid_message"})
                return
            if not 1 <= len(message_bytes) <= MAX_MESSAGE_BYTES:
                self._send(400, {"error": "invalid_message"})
                return
            try:
                if not service.authenticate(self.headers.get("Authorization")):
                    self._send(401, {"error": "unauthorized"})
                    return
                service.accept(message)
            except ConjurError:
                self._send(503, {"error": "service_unavailable"})
                return
            except Exception:
                self._send(503, {"error": "service_unavailable"})
                return
            self._send(202, {
                "status": "accepted",
                "tenant": service.tenant,
                "environment": service.environment,
                "message_id": str(uuid.uuid4()),
            })

        def do_PUT(self) -> None:
            self._send(405, {"error": "method_not_allowed"})

        def do_DELETE(self) -> None:
            self._send(405, {"error": "method_not_allowed"})

    return Handler


def run_server() -> None:
    client, tenant, environment = make_message_client_from_env()
    host = os.environ.get("APP_HOST", "0.0.0.0")
    try:
        port = int(os.environ.get("APP_PORT", "8080"))
    except ValueError:
        raise ValueError("APP_PORT must be an integer") from None
    if not 1 <= port <= 65535:
        raise ValueError("APP_PORT must be between 1 and 65535")
    server = BoundedThreadingHTTPServer(
        (host, port), handler_for(MessageService(client, tenant, environment))
    )
    print(f"message API listening on {host}:{port} tenant={tenant} environment={environment}", flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    try:
        if args == ["check"]:
            client, tenant, environment = make_message_client_from_env()
            check_permissions(client, tenant, environment)
            print(f"Conjur access check passed for tenant={tenant} environment={environment}")
            return 0
        if args not in ([], ["server"]):
            print("usage: python message.py [server|check]", file=sys.stderr)
            return 2
        run_server()
        return 0
    except (ConjurError, ValueError) as exc:
        print(f"startup/check failed: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
