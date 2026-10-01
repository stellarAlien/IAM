"""Native Okta OIDC sign-in using authorization code flow with PKCE."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import math
import os
import secrets
import tempfile
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

import jwt
import requests


REDIRECT_URI = "http://127.0.0.1:8765/callback"
RUNTIME_DIR = Path(".runtime")
ACCESS_TOKEN_FILE = RUNTIME_DIR / "access_token"
AUTHORIZATION_URL_FILE = RUNTIME_DIR / "authorization-url"
REQUEST_TIMEOUT = (5, 15)
CALLBACK_TIMEOUT = 180


class LoginError(Exception):
    """An expected, safely reportable sign-in failure."""


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def _url_base(value: str, label: str) -> str:
    if not isinstance(value, str):
        raise LoginError(f"Invalid {label} configuration")
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as exc:
        raise LoginError(f"Invalid {label} configuration") from exc
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or port is not None:
        raise LoginError(f"Invalid {label} configuration")
    if parsed.query or parsed.fragment:
        raise LoginError(f"Invalid {label} configuration")
    return value.rstrip("/")


def validate_config(config: dict[str, Any]) -> dict[str, str]:
    required = ("org_url", "issuer", "client_id", "audience", "api_origin")
    if not isinstance(config, dict):
        try:
            config = {key: getattr(config, key) for key in required}
        except (AttributeError, TypeError) as exc:
            raise LoginError("Invalid login configuration") from exc
    if not isinstance(config, dict) or any(not isinstance(config.get(key), str) or not config[key] for key in required):
        raise LoginError("Invalid login configuration")
    org_url = _url_base(config["org_url"], "Okta organization URL")
    issuer = _url_base(config["issuer"], "authorization server issuer")
    org_parts = urlsplit(org_url)
    issuer_parts = urlsplit(issuer)
    api_origin = config["api_origin"].rstrip("/")
    api = urlsplit(api_origin)
    if api.scheme not in ("http", "https") or not api.hostname or api.username or api.password or api.query or api.fragment:
        raise LoginError("Invalid API origin configuration")
    issuer_segments = issuer_parts.path.split("/")
    if issuer == org_url or len(issuer_segments) != 3 or issuer_segments[1] != "oauth2" or not issuer_segments[2]:
        raise LoginError("Use an authorization server issuer, not the Okta organization URL")
    if issuer_parts.hostname != org_parts.hostname or issuer_parts.port != org_parts.port:
        raise LoginError("Authorization server must belong to the configured Okta organization")
    if config["audience"] != "api://iam-lab":
        raise LoginError("Invalid API audience configuration")
    return {
        "org_url": org_url,
        "issuer": issuer,
        "client_id": config["client_id"],
        "audience": config["audience"],
        "api_origin": api_origin,
    }


def _runtime_dir() -> Path:
    path = RUNTIME_DIR
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.is_symlink() or not path.is_dir():
            raise LoginError("Runtime path is not a private directory")
        path.chmod(0o700)
    except OSError as exc:
        raise LoginError("Could not prepare private runtime directory") from exc
    return path


def _write_private(path: Path, content: str) -> None:
    _runtime_dir()
    temp_name: str | None = None
    try:
        fd, temp_name = tempfile.mkstemp(prefix=".login-", dir=path.parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as output:
                output.write(content)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace(temp_name, path)
            temp_name = None
            path.chmod(0o600)
        finally:
            if temp_name is not None:
                try:
                    os.unlink(temp_name)
                except OSError:
                    pass
    except OSError as exc:
        raise LoginError("Could not save private login data") from exc


def _remove_local_artifacts() -> None:
    _runtime_dir()
    for path in (ACCESS_TOKEN_FILE, AUTHORIZATION_URL_FILE):
        try:
            path.unlink(missing_ok=True)
        except OSError as exc:
            raise LoginError("Could not remove local login data") from exc


class _CallbackHTTPServer(HTTPServer):
    def __init__(self, address: tuple[str, int], expected_state: str, timeout: int):
        self.expected_state = expected_state
        self.authorization_code: str | None = None
        self.oauth_error = False
        super().__init__(address, _CallbackHandler)
        self.timeout = timeout


class _CallbackHandler(BaseHTTPRequestHandler):
    server: _CallbackHTTPServer

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, format: str, *args: Any) -> None:
        return

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        self._respond(code, "Invalid sign-in callback. You may retry sign-in.")

    def _respond(self, status: int, text: str) -> None:
        body = text.encode("ascii")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.path != "/callback" or parsed.fragment:
            self._respond(404, "Sign-in callback not found. You may close this window.")
            return
        try:
            params = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True, max_num_fields=12)
        except ValueError:
            self._respond(400, "Invalid sign-in callback. You may retry sign-in.")
            return
        if any(len(params.get(key, [])) != 1 for key in ("state",)):
            self._respond(400, "Invalid sign-in callback. You may retry sign-in.")
            return
        received_state = params["state"][0]
        if not hmac.compare_digest(received_state.encode('utf-8'), self.server.expected_state.encode('utf-8')):
            self._respond(400, "Sign-in state did not match. This request was rejected.")
            return
        if any(len(values) != 1 for key, values in params.items() if key in ("code", "error", "error_description")):
            self._respond(400, "Invalid sign-in callback. You may retry sign-in.")
            return
        if params.get("error"):
            self.server.oauth_error = True
            self._respond(400, "Sign-in was not completed. You may close this window.")
            return
        codes = params.get("code", [])
        if not codes or not codes[0]:
            self._respond(400, "Invalid sign-in callback. You may retry sign-in.")
            return
        self.server.authorization_code = codes[0]
        self._respond(200, "Sign-in complete. You may close this window.")


def receive_authorization_code(
    state: str,
    port: int = 8765,
    timeout: int = CALLBACK_TIMEOUT,
    on_listening: Any | None = None,
) -> str:
    try:
        server = _CallbackHTTPServer(("127.0.0.1", port), state, timeout)
    except OSError as exc:
        raise LoginError("Could not start the local sign-in callback listener") from exc
    try:
        if on_listening is not None:
            on_listening()
        deadline = time.monotonic() + timeout
        while server.authorization_code is None and not server.oauth_error:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise LoginError("Sign-in callback timed out")
            server.timeout = remaining
            server.handle_request()
        if server.oauth_error:
            raise LoginError("Okta sign-in was not completed")
        return server.authorization_code
    finally:
        server.server_close()


def _authorization_url(config: dict[str, str], state: str, nonce: str, challenge: str) -> str:
    parameters = {
        "client_id": config["client_id"],
        "response_type": "code",
        "response_mode": "query",
        "scope": "openid profile messages.send",
        "redirect_uri": REDIRECT_URI,
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return f'{config["issuer"]}/v1/authorize?{urlencode(parameters)}'


def _new_session() -> requests.Session:
    session = requests.Session()
    session.trust_env = False
    return session


def _json_response(response: requests.Response) -> dict[str, Any]:
    try:
        data = response.json()
    except (ValueError, json.JSONDecodeError) as exc:
        raise LoginError("Okta returned an invalid token response") from exc
    if not isinstance(data, dict):
        raise LoginError("Okta returned an invalid token response")
    return data


def _validate_jwt(token: str, issuer: str, audience: str, nonce: str | None = None) -> dict[str, Any]:
    if not isinstance(token, str) or not token or len(token) > 65536:
        raise LoginError("Okta returned an invalid token")
    try:
        key_client = jwt.PyJWKClient(f"{issuer}/v1/keys", timeout=10)
        signing_key = key_client.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            issuer=issuer,
            audience=audience,
            options={"require": ["iss", "aud", "exp", "iat", "sub"]},
        )
    except Exception as exc:
        raise LoginError("Okta returned an invalid token") from exc
    if not isinstance(claims.get("sub"), str) or not claims["sub"]:
        raise LoginError("Okta returned an invalid token")
    if nonce is not None and (not isinstance(claims.get("nonce"), str) or not hmac.compare_digest(claims["nonce"], nonce)):
        raise LoginError("Okta returned an invalid ID token")
    return claims


def exchange_code(config: dict[str, str], code: str, verifier: str, nonce: str, session: Any | None = None) -> str:
    http = session or _new_session()
    try:
        response = http.post(
            f'{config["issuer"]}/v1/token',
            data={
                "grant_type": "authorization_code",
                "client_id": config["client_id"],
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "code_verifier": verifier,
            },
            headers={"Accept": "application/json"},
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        raise LoginError("Could not contact the Okta token endpoint") from exc
    if response.status_code != 200:
        raise LoginError("Okta rejected the authorization code")
    result = _json_response(response)
    access_token = result.get("access_token")
    id_token = result.get("id_token")
    expires_in = result.get("expires_in")
    token_type = result.get("token_type")
    if (
        not isinstance(access_token, str)
        or not access_token
        or not isinstance(id_token, str)
        or not id_token
        or isinstance(expires_in, bool)
        or not isinstance(expires_in, (int, float))
        or not math.isfinite(expires_in)
        or expires_in <= 0
        or not isinstance(token_type, str)
        or token_type.lower() != "bearer"
    ):
        raise LoginError("Okta returned an incomplete token response")
    _validate_jwt(id_token, config["issuer"], config["client_id"], nonce)
    _validate_jwt(access_token, config["issuer"], config["audience"])
    return access_token


def login(config: dict[str, Any], no_browser: bool = False, session: Any | None = None, callback_port: int = 8765) -> None:
    settings = validate_config(config)
    _remove_local_artifacts()
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier, challenge = pkce_pair()
    authorization_url = _authorization_url(settings, state, nonce, challenge)

    def start_sign_in() -> None:
        if no_browser:
            _write_private(AUTHORIZATION_URL_FILE, authorization_url)
            print("Open .runtime/authorization-url locally to continue sign-in.")
            return
        print("Open browser sign-in; if unavailable configure a browser or run locally with --no-browser.")
        try:
            opened = webbrowser.open(authorization_url, new=1, autoraise=True)
        except Exception:
            opened = False
        if not opened:
            raise LoginError("Could not open a browser; retry with --no-browser")

    code = receive_authorization_code(state, callback_port, on_listening=start_sign_in)
    access_token = exchange_code(settings, code, verifier, nonce, session)
    _write_private(ACCESS_TOKEN_FILE, access_token)
    try:
        AUTHORIZATION_URL_FILE.unlink(missing_ok=True)
    except OSError:
        pass
    print("Sign-in complete; access token saved privately in .runtime/access_token.")


def logout(config: dict[str, Any] | None = None, revoke: bool = False, session: Any | None = None) -> None:
    revoke_error = False
    if revoke:
        token: str | None = None
        try:
            token = ACCESS_TOKEN_FILE.read_text(encoding="utf-8").strip()
        except OSError:
            revoke_error = ACCESS_TOKEN_FILE.exists()
        if token and config is not None:
            try:
                settings = validate_config(config)
                http = session or _new_session()
                response = http.post(
                    f'{settings["issuer"]}/v1/revoke',
                    data={"token": token, "token_type_hint": "access_token", "client_id": settings["client_id"]},
                    headers={"Accept": "application/json"},
                    timeout=REQUEST_TIMEOUT,
                    allow_redirects=False,
                )
                revoke_error = response.status_code != 200
            except Exception:
                revoke_error = True
        elif token:
            revoke_error = True
    _remove_local_artifacts()
    if revoke_error:
        raise LoginError("Local sign-in data was removed, but Okta token revocation failed")
    print("Local sign-in data removed; no remote Okta sign-out was performed.")


def _load_config(path: str) -> dict[str, Any]:
    from .config import load_config

    return load_config(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sign in to the Okta IAM lab")
    parser.add_argument("--config", default="config/local.json")
    parser.add_argument("--no-browser", action="store_true", help="save a private authorization URL for opening locally")
    parser.add_argument("--logout", action="store_true", help="remove local sign-in artifacts")
    parser.add_argument("--revoke", action="store_true", help="also request Okta revocation during logout")
    args = parser.parse_args(argv)
    try:
        if args.logout:
            config = None
            if args.revoke:
                try:
                    config = _load_config(args.config)
                except Exception:
                    config = None
            logout(config, args.revoke)
        else:
            config = _load_config(args.config)
            login(config, args.no_browser)
    except LoginError as exc:
        print(str(exc), file=__import__("sys").stderr)
        return 1
    except (OSError, ValueError):
        print("Could not complete sign-in with the selected configuration.", file=__import__("sys").stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
