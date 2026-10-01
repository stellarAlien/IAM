#!/usr/bin/env python3
"""Small Conjur-backed payment-risk demo using only the Python standard library."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import re
import ssl
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from decimal import Decimal, InvalidOperation
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


DEFAULT_API_KEY_FILE = "/run/secrets/host_api_key"
MAX_BODY_BYTES = 16 * 1024
MAX_AMOUNT = Decimal("1000000")
MAX_ACTIVE_REQUESTS = 16
REQUEST_TIMEOUT = 5.0
WORKLOAD_SECRETS = {
    "checkout": ("lab/secrets/payment-api-key", "lab/secrets/fraud-model-key"),
    "fraud": ("lab/secrets/fraud-model-key", "lab/secrets/payment-api-key"),
}


class ConjurError(Exception):
    """A safe Conjur failure carrying only its HTTP status, if available."""

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str):
        return None


class ConjurClient:
    def __init__(
        self,
        appliance_url: str,
        account: str,
        login: str,
        api_key: str | None = None,
        api_key_file: str | None = DEFAULT_API_KEY_FILE,
        cert_file: str | None = None,
        timeout: float = REQUEST_TIMEOUT,
        opener: Any | None = None,
    ) -> None:
        parsed = urllib.parse.urlsplit(appliance_url)
        if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
            raise ValueError("CONJUR_APPLIANCE_URL must be an HTTPS URL")
        if parsed.query or parsed.fragment:
            raise ValueError("CONJUR_APPLIANCE_URL cannot contain a query or fragment")
        if not account or not login:
            raise ValueError("Conjur account and login must be set")
        if not math.isfinite(timeout) or timeout <= 0 or timeout > 60:
            raise ValueError("Conjur timeout must be greater than 0 and at most 60 seconds")

        self.base_url = appliance_url.rstrip("/")
        self.account = account
        self.login = login
        self._api_key = api_key
        self._api_key_file = api_key_file
        self.timeout = timeout
        if opener is None:
            context = ssl.create_default_context(cafile=cert_file)
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=context), NoRedirectHandler()
            )
        self._opener = opener

    @staticmethod
    def _component(value: str) -> str:
        return urllib.parse.quote(value, safe="")

    def _api_key_value(self) -> bytes:
        if self._api_key_file:
            try:
                with open(self._api_key_file, "rb") as secret_file:
                    key = secret_file.read().strip()
                    if key:
                        return key
            except FileNotFoundError:
                pass
            except OSError:
                raise ConjurError("Unable to read Conjur API key file") from None
        if self._api_key:
            key = self._api_key.encode("utf-8").strip()
            if key:
                return key
        raise ConjurError("Conjur API key is unavailable")

    def _open(self, request: urllib.request.Request) -> bytes:
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                status = getattr(response, "status", 200)
                if status != 200:
                    raise ConjurError("Conjur request was rejected", status)
                return response.read()
        except urllib.error.HTTPError as exc:
            raise ConjurError("Conjur request was rejected", exc.code) from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise ConjurError("Conjur request failed") from None

    def _authenticate(self) -> bytes:
        path = "/authn/{}/{}/authenticate".format(
            self._component(self.account), self._component(self.login)
        )
        request = urllib.request.Request(
            self.base_url + path,
            data=self._api_key_value(),
            headers={"Content-Type": "text/plain"},
            method="POST",
        )
        raw_token = self._open(request)
        if not raw_token:
            raise ConjurError("Conjur returned an empty authentication token")
        encoded_token = base64.b64encode(raw_token).decode("ascii")
        return f'Token token="{encoded_token}"'.encode("ascii")

    def _authenticated_request(self, path: str) -> bytes:
        for attempt in range(2):
            token = self._authenticate()
            request = urllib.request.Request(
                self.base_url + path,
                headers={"Authorization": token},
                method="GET",
            )
            try:
                with self._opener.open(request, timeout=self.timeout) as response:
                    status = getattr(response, "status", 200)
                    if status != 200:
                        raise ConjurError("Conjur request was rejected", status)
                    return response.read()
            except urllib.error.HTTPError as exc:
                if exc.code == 401 and attempt == 0:
                    continue
                raise ConjurError("Conjur request was rejected", exc.code) from None
            except (urllib.error.URLError, TimeoutError, OSError):
                raise ConjurError("Conjur request failed") from None
        raise ConjurError("Conjur authentication failed", 401)

    def get_secret(self, variable_id: str) -> bytes:
        path = "/secrets/{}/variable/{}".format(
            self._component(self.account), self._component(variable_id)
        )
        return self._authenticated_request(path)


def make_client_from_env() -> ConjurClient:
    appliance_url = os.environ.get("CONJUR_APPLIANCE_URL", "")
    account = os.environ.get("CONJUR_ACCOUNT", "sandbox")
    workload = os.environ.get("WORKLOAD", "checkout")
    if workload not in WORKLOAD_SECRETS:
        raise ValueError("WORKLOAD must be checkout or fraud")
    expected_login = f"host/lab/{workload}"
    login = os.environ.get("CONJUR_AUTHN_LOGIN", expected_login)
    if login != expected_login:
        raise ValueError("CONJUR_AUTHN_LOGIN does not match WORKLOAD")
    try:
        timeout = float(os.environ.get("CONJUR_TIMEOUT_SECONDS", str(REQUEST_TIMEOUT)))
    except ValueError:
        raise ValueError("CONJUR_TIMEOUT_SECONDS must be a number") from None
    return ConjurClient(
        appliance_url=appliance_url,
        account=account,
        login=login,
        api_key=os.environ.get("CONJUR_AUTHN_API_KEY"),
        api_key_file=os.environ.get("CONJUR_AUTHN_API_KEY_FILE", DEFAULT_API_KEY_FILE),
        cert_file=os.environ.get("CONJUR_CERT_FILE"),
        timeout=timeout,
    )


def _workload_config(workload: str) -> tuple[str, str]:
    try:
        return WORKLOAD_SECRETS[workload]
    except KeyError:
        raise ValueError("WORKLOAD must be checkout or fraud") from None


def _credential_version(client: ConjurClient) -> str:
    raw = client.get_secret("lab/secrets/credential-version")
    try:
        version = raw.decode("utf-8").strip()
    except UnicodeDecodeError:
        raise ConjurError("Credential version is invalid") from None
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", version):
        raise ConjurError("Credential version is invalid")
    return version


def evaluate(client: ConjurClient, workload: str, payload: Any) -> dict[str, Any]:
    """Validate an order and perform keyed payment signing or fraud scoring."""
    active_secret, _ = _workload_config(workload)
    if not isinstance(payload, dict) or set(payload) != {"order_id", "amount", "currency"}:
        raise ValueError("Expected order_id, amount, and currency")

    order_id = payload["order_id"]
    if not isinstance(order_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", order_id):
        raise ValueError("order_id must contain 1-80 letters, digits, underscores, or hyphens")
    amount_value = payload["amount"]
    if isinstance(amount_value, bool) or not isinstance(amount_value, (int, float)):
        raise ValueError("amount must be a finite number greater than 0 and at most 1000000")
    try:
        amount = Decimal(str(amount_value))
    except InvalidOperation:
        raise ValueError("amount must be a finite number greater than 0 and at most 1000000") from None
    if not amount.is_finite() or amount <= 0 or amount > MAX_AMOUNT:
        raise ValueError("amount must be a finite number greater than 0 and at most 1000000")
    currency = payload["currency"]
    if not isinstance(currency, str) or not re.fullmatch(r"[A-Za-z]{3}", currency):
        raise ValueError("currency must be a three-letter code")
    currency = currency.upper()

    key = client.get_secret(active_secret)
    canonical_order = json.dumps(
        {
            "amount": format(amount.normalize(), "f"),
            "currency": currency,
            "order_id": order_id,
        },
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    mac = hmac.new(key, canonical_order, hashlib.sha256).digest()
    version = _credential_version(client)

    if workload == "checkout":
        return {
            "order_id": order_id,
            "status": "signed",
            "credential_version": version,
        }
    # Convert keyed digest bits to a coarse score without exposing the digest.
    score = int.from_bytes(mac[:2], "big") % 101
    return {
        "order_id": order_id,
        "risk_score": score,
        "risk_level": "high" if score >= 70 else "low",
        "credential_version": version,
    }


def check_permissions(client: ConjurClient, workload: str) -> None:
    permitted_secret, forbidden_secret = _workload_config(workload)
    client.get_secret(permitted_secret)
    _credential_version(client)
    try:
        client.get_secret(forbidden_secret)
    except ConjurError as exc:
        if exc.status in (403, 404):
            return
        raise
    raise ConjurError("Workload identity can read a forbidden secret")


class PaymentRiskService:
    def __init__(self, client: ConjurClient, workload: str):
        _workload_config(workload)
        self.client = client
        self.workload = workload

    def ready(self) -> str:
        active_secret, _ = _workload_config(self.workload)
        self.client.get_secret(active_secret)
        return _credential_version(self.client)


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 32

    def __init__(self, *args: Any, max_active: int = MAX_ACTIVE_REQUESTS, **kwargs: Any):
        self._slots = threading.BoundedSemaphore(max_active)
        super().__init__(*args, **kwargs)

    def process_request(self, request: Any, client_address: Any) -> None:
        self._slots.acquire()
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


def handler_for(service: PaymentRiskService) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "ConjurPaymentRisk/1.0"
        sys_version = ""

        def log_message(self, fmt: str, *args: Any) -> None:
            # Request bodies and Conjur values are intentionally never logged.
            sys.stderr.write("http: " + (fmt % args) + "\n")

        def _send(self, status: int, body: dict[str, Any]) -> None:
            encoded = json.dumps(body, separators=(",", ":")).encode("utf-8")
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
                    version = service.ready()
                except ConjurError:
                    self._send(503, {"status": "not_ready"})
                    return
                except Exception:
                    self._send(503, {"status": "not_ready"})
                    return
                self._send(200, {"status": "ready", "credential_version": version})
                return
            self._send(404, {"error": "not_found"})

        def do_POST(self) -> None:
            if self.path != "/evaluate":
                self._send(404, {"error": "not_found"})
                return
            content_length = self.headers.get("Content-Length")
            if content_length is None or not content_length.isdecimal():
                self._send(400, {"error": "invalid_content_length"})
                return
            if int(content_length) > MAX_BODY_BYTES:
                self._send(413, {"error": "request_too_large"})
                return
            if self.headers.get_content_type() != "application/json":
                self._send(415, {"error": "application_json_required"})
                return
            try:
                payload = json.loads(self.rfile.read(int(content_length)))
                result = evaluate(service.client, service.workload, payload)
            except (json.JSONDecodeError, UnicodeDecodeError):
                self._send(400, {"error": "invalid_json"})
            except ValueError as exc:
                self._send(400, {"error": str(exc)})
            except ConjurError as exc:
                status = 403 if exc.status in (401, 403) else 503
                self._send(status, {"error": "secret_backend_unavailable"})
            except Exception:
                self._send(503, {"error": "request_unavailable"})
            else:
                self._send(200, result)

        def do_PUT(self) -> None:
            self._send(405, {"error": "method_not_allowed"})

        def do_DELETE(self) -> None:
            self._send(405, {"error": "method_not_allowed"})

    return Handler


def run_server() -> None:
    workload = os.environ.get("WORKLOAD", "checkout")
    service = PaymentRiskService(make_client_from_env(), workload)
    host = os.environ.get("APP_HOST", "0.0.0.0")
    try:
        port = int(os.environ.get("APP_PORT", "8080"))
    except ValueError:
        raise ValueError("APP_PORT must be an integer") from None
    if not 1 <= port <= 65535:
        raise ValueError("APP_PORT must be between 1 and 65535")
    server = BoundedThreadingHTTPServer((host, port), handler_for(service))
    print(f"payment-risk service listening on {host}:{port} workload={workload}", flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    try:
        if args == ["check"]:
            workload = os.environ.get("WORKLOAD", "checkout")
            check_permissions(make_client_from_env(), workload)
            print(f"Conjur access check passed for workload={workload}")
            return 0
        if args:
            print("usage: python app.py [check]", file=sys.stderr)
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
