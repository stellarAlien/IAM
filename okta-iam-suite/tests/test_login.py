from __future__ import annotations

import base64
import hashlib
import os
import threading
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from okta_lab import login
from okta_lab.config import OktaConfig


CONFIG = {
    "org_url": "https://dev-123456.okta.com",
    "issuer": "https://dev-123456.okta.com/oauth2/default",
    "client_id": "native-client",
    "audience": "api://iam-lab",
    "api_origin": "http://127.0.0.1:8090",
}


class LoginTests(unittest.TestCase):
    def test_pkce_and_authorization_request_use_expected_safe_parameters(self):
        verifier, challenge = login.pkce_pair()
        self.assertGreaterEqual(len(verifier), 43)
        self.assertEqual(
            challenge,
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode(),
        )
        url = urlsplit(login._authorization_url(CONFIG, "state", "nonce", challenge))
        values = parse_qs(url.query)
        self.assertEqual(url.path, "/oauth2/default/v1/authorize")
        self.assertEqual(values["redirect_uri"], [login.REDIRECT_URI])
        self.assertEqual(values["scope"], ["openid profile messages.send"])
        self.assertEqual(values["code_challenge_method"], ["S256"])
        self.assertNotIn("client_secret", values)

    def test_configuration_rejects_org_issuer_and_wrong_audience(self):
        for change in ({"issuer": CONFIG["org_url"]}, {"audience": "api://other"}):
            with self.subTest(change=change), self.assertRaises(login.LoginError):
                login.validate_config(CONFIG | change)

    def test_configuration_accepts_the_suite_config_object(self):
        settings = OktaConfig(org_url=CONFIG["org_url"], client_id=CONFIG["client_id"])
        self.assertEqual(login.validate_config(settings)["issuer"], CONFIG["issuer"])

    def test_callback_rejects_wrong_state_then_accepts_correct_state_without_logging(self):
        server = login._CallbackHTTPServer(("127.0.0.1", 0), "expected", 3)
        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()
        try:
            import http.client

            conn = http.client.HTTPConnection("127.0.0.1", server.server_port)
            conn.request("GET", "/callback?state=wrong&code=secret-code")
            response = conn.getresponse()
            response.read()
            self.assertEqual(response.status, 400)
            conn.close()
            server.timeout = 0.1
            thread.join(timeout=0.2)
            self.assertIsNone(server.authorization_code)
            server.timeout = 2
            thread = threading.Thread(target=server.handle_request, daemon=True)
            thread.start()
            conn = http.client.HTTPConnection("127.0.0.1", server.server_port)
            conn.request("GET", "/callback?state=expected&code=private-code")
            response = conn.getresponse()
            response.read()
            self.assertEqual(response.status, 200)
            conn.close()
            thread.join(timeout=2)
            self.assertEqual(server.authorization_code, "private-code")
        finally:
            server.server_close()

    def test_callback_rejects_duplicate_state_or_code_and_oauth_error(self):
        class CaptureServer(login._CallbackHTTPServer):
            pass

        for query in (
            "state=ok&state=ok&code=value",
            "state=ok&code=a&code=b",
            "state=ok&error=denied",
            "state=%C3%A9&code=value",
        ):
            server = CaptureServer(("127.0.0.1", 0), "ok", 2)
            thread = threading.Thread(target=server.handle_request, daemon=True)
            thread.start()
            import http.client

            conn = http.client.HTTPConnection("127.0.0.1", server.server_port)
            conn.request("GET", f"/callback?{query}")
            response = conn.getresponse()
            response.read()
            conn.close()
            thread.join(timeout=2)
            self.assertNotEqual(response.status, 200)
            self.assertIsNone(server.authorization_code)
            server.server_close()

    def test_callback_response_is_static_plain_text_for_unsupported_methods(self):
        server = login._CallbackHTTPServer(("127.0.0.1", 0), "expected", 2)
        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()
        import http.client

        conn = http.client.HTTPConnection("127.0.0.1", server.server_port)
        conn.request("POST", "/callback", body="private-request-body")
        response = conn.getresponse()
        body = response.read().decode()
        conn.close()
        thread.join(timeout=2)
        server.server_close()
        self.assertEqual(response.status, 501)
        self.assertEqual(response.getheader("Content-Type"), "text/plain; charset=utf-8")
        self.assertNotIn("private-request-body", body)

    def test_private_runtime_files_have_restricted_modes(self):
        with TemporaryDirectory() as directory:
            runtime = Path(directory) / ".runtime"
            token_file = runtime / "access_token"
            with patch.object(login, "RUNTIME_DIR", runtime):
                login._write_private(token_file, "validated-access-token")
                self.assertEqual(token_file.read_text().strip(), "validated-access-token")
                self.assertEqual(os.stat(runtime).st_mode & 0o777, 0o700)
                self.assertEqual(os.stat(token_file).st_mode & 0o777, 0o600)

    def test_failed_actor_switch_cannot_reuse_previous_token(self):
        with TemporaryDirectory() as directory:
            runtime = Path(directory) / '.runtime'
            runtime.mkdir()
            token = runtime / 'access_token'
            token.write_text('previous-actor-token')
            with patch.object(login, 'RUNTIME_DIR', runtime), \
                 patch.object(login, 'ACCESS_TOKEN_FILE', token), \
                 patch.object(login, 'AUTHORIZATION_URL_FILE', runtime / 'authorization-url'), \
                 patch.object(login, 'receive_authorization_code', side_effect=login.LoginError('Synthetic cancelled sign-in')):
                with self.assertRaises(login.LoginError):
                    login.login(CONFIG)
            self.assertFalse(token.exists())

    def test_token_exchange_disables_redirects_and_requires_both_validated_tokens(self):
        class Response:
            status_code = 200

            @staticmethod
            def json():
                return {"access_token": "access", "id_token": "identity", "token_type": "Bearer", "expires_in": 300}

        class Session:
            def post(self, url, **kwargs):
                self.url, self.kwargs = url, kwargs
                return Response()

        session = Session()
        with patch.object(login, "_validate_jwt", side_effect=[{"sub": "user"}, {"sub": "user"}]) as validate:
            token = login.exchange_code(login.validate_config(CONFIG), "code-value", "verifier-value", "nonce", session)
        self.assertEqual(token, "access")
        self.assertFalse(session.kwargs["allow_redirects"])
        self.assertEqual(session.kwargs["timeout"], login.REQUEST_TIMEOUT)
        self.assertEqual(validate.call_args_list[0].args, ("identity", CONFIG["issuer"], CONFIG["client_id"], "nonce"))
        self.assertEqual(validate.call_args_list[1].args, ("access", CONFIG["issuer"], CONFIG["audience"]))

    def test_jwt_validation_requires_signature_claims_audience_and_nonce(self):
        claims = {"iss": CONFIG["issuer"], "aud": CONFIG["client_id"], "exp": 500, "iat": 100, "sub": "user", "nonce": "nonce"}

        class KeyClient:
            def __init__(self, url, timeout):
                self.url, self.timeout = url, timeout

            def get_signing_key_from_jwt(self, token):
                self.token = token
                return type("SigningKey", (), {"key": "verified-key"})()

        with patch.object(login.jwt, "PyJWKClient", KeyClient), patch.object(login.jwt, "decode", return_value=claims) as decode:
            self.assertEqual(login._validate_jwt("signed.jwt.value", CONFIG["issuer"], CONFIG["client_id"], "nonce"), claims)
            kwargs = decode.call_args.kwargs
            self.assertEqual(kwargs["algorithms"], ["RS256"])
            self.assertEqual(kwargs["issuer"], CONFIG["issuer"])
            self.assertEqual(kwargs["audience"], CONFIG["client_id"])
            self.assertEqual(kwargs["options"]["require"], ["iss", "aud", "exp", "iat", "sub"])
            with self.assertRaisesRegex(login.LoginError, "ID token"):
                login._validate_jwt("signed.jwt.value", CONFIG["issuer"], CONFIG["client_id"], "different")

    def test_token_response_failure_is_generic_and_never_exposes_response_body(self):
        class Response:
            status_code = 400
            text = "do-not-print-this-code"

        class Session:
            def post(self, *args, **kwargs):
                return Response()

        with self.assertRaisesRegex(login.LoginError, "rejected") as raised:
            login.exchange_code(login.validate_config(CONFIG), "sensitive-code", "v", "n", Session())
        self.assertNotIn("do-not-print", str(raised.exception))
        self.assertNotIn("sensitive-code", str(raised.exception))

    def test_logout_deletes_local_files_even_when_revoke_fails(self):
        with TemporaryDirectory() as directory:
            runtime = Path(directory) / ".runtime"
            runtime.mkdir(mode=0o700)
            token_file = runtime / "access_token"
            auth_file = runtime / "authorization-url"
            token_file.write_text("private-token")
            auth_file.write_text("private-url")

            class Response:
                status_code = 500

            class Session:
                def post(self, url, **kwargs):
                    self.kwargs = kwargs
                    return Response()

            session = Session()
            with patch.object(login, "ACCESS_TOKEN_FILE", token_file), patch.object(login, "AUTHORIZATION_URL_FILE", auth_file), patch.object(login, "RUNTIME_DIR", runtime):
                with self.assertRaisesRegex(login.LoginError, "revocation failed"):
                    login.logout(CONFIG, revoke=True, session=session)
            self.assertFalse(token_file.exists())
            self.assertFalse(auth_file.exists())
            self.assertEqual(session.kwargs["data"]["client_id"], CONFIG["client_id"])
            self.assertFalse(session.kwargs["allow_redirects"])


if __name__ == "__main__":
    unittest.main()
