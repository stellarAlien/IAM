import base64
import http.client
import json
import sys
import threading
import tempfile
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))

import app


class FakeResponse:
    def __init__(self, body, status=200):
        self.body = body
        self.status = status

    def read(self):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class FakeOpener:
    def __init__(self, callback):
        self.callback = callback
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        response = self.callback(request, timeout, len(self.requests))
        if isinstance(response, Exception):
            raise response
        if isinstance(response, FakeResponse):
            return response
        return FakeResponse(response)


def http_error(code):
    return urllib.error.HTTPError("https://conjur.test", code, "failure", {}, None)


class ConjurClientTests(unittest.TestCase):
    def client(self, opener, **kwargs):
        return app.ConjurClient(
            "https://conjur.test/prefix",
            "acct/team",
            "host/lab/checkout",
            api_key="test-api-key",
            api_key_file=None,
            opener=opener,
            **kwargs,
        )

    def test_auth_and_secret_urls_encode_complete_components(self):
        def respond(request, _timeout, _count):
            if request.full_url.endswith("/authenticate"):
                return b"token-bytes"
            return b"secret-value"

        opener = FakeOpener(respond)
        secret = self.client(opener).get_secret("lab/secrets/key with/slash")
        self.assertEqual(secret, b"secret-value")
        auth, timeout = opener.requests[0]
        secret_request, _ = opener.requests[1]
        expected_login = urllib.parse.quote("host/lab/checkout", safe="")
        expected_account = urllib.parse.quote("acct/team", safe="")
        self.assertEqual(
            auth.full_url,
            f"https://conjur.test/prefix/authn/{expected_account}/{expected_login}/authenticate",
        )
        self.assertEqual(auth.data, b"test-api-key")
        self.assertEqual(timeout, app.REQUEST_TIMEOUT)
        encoded_token = base64.b64encode(b"token-bytes").decode()
        self.assertEqual(auth.headers["Content-type"], "text/plain")
        self.assertEqual(secret_request.get_header("Authorization"), f'Token token="{encoded_token}"'.encode())
        self.assertTrue(secret_request.full_url.endswith("/secrets/acct%2Fteam/variable/lab%2Fsecrets%2Fkey%20with%2Fslash"))

    def test_401_reauthenticates_once_with_fresh_key(self):
        with tempfile.TemporaryDirectory() as directory:
            key_file = Path(directory) / "api-key"
            key_file.write_text("first-key")
            count = 0

            def respond(request, _timeout, _number):
                nonlocal count
                if request.full_url.endswith("/authenticate"):
                    count += 1
                    key = request.data
                    key_file.write_text("rotated-key")
                    return f"token-{count}".encode()
                if request.get_header("Authorization").endswith(b"dG9rZW4tMQ==\""):
                    return http_error(401)
                return b"retrieved"

            opener = FakeOpener(respond)
            client = app.ConjurClient(
                "https://conjur.test", "sandbox", "host/lab/checkout",
                api_key_file=str(key_file), opener=opener,
            )
            self.assertEqual(client.get_secret("x"), b"retrieved")
            self.assertEqual([request.data for request, _ in opener.requests if request.data], [b"first-key", b"rotated-key"])
            self.assertEqual(len(opener.requests), 4)

    def test_403_is_not_retried(self):
        opener = FakeOpener(lambda request, _timeout, _n: b"token" if request.data else http_error(403))
        with self.assertRaises(app.ConjurError) as raised:
            self.client(opener).get_secret("private")
        self.assertEqual(raised.exception.status, 403)
        self.assertEqual(len(opener.requests), 2)

    def test_authentication_failure_is_not_retried(self):
        opener = FakeOpener(lambda _request, _timeout, _n: http_error(401))
        with self.assertRaises(app.ConjurError) as raised:
            self.client(opener).get_secret("private")
        self.assertEqual(raised.exception.status, 401)
        self.assertEqual(len(opener.requests), 1)

    def test_default_transport_disables_all_redirects(self):
        client = app.ConjurClient(
            "https://conjur.test", "sandbox", "host/lab/checkout", api_key="key", api_key_file=None
        )
        redirect_handlers = [
            handler for handler in client._opener.handlers
            if isinstance(handler, urllib.request.HTTPRedirectHandler)
        ]
        self.assertEqual(len(redirect_handlers), 1)
        redirect = redirect_handlers[0]
        request = urllib.request.Request("https://conjur.test/authenticate", data=b"api-key")
        self.assertIsNone(redirect.redirect_request(request, None, 307, "Temporary Redirect", {}, "https://other.test"))

    def test_redirect_http_error_is_safe_and_not_followed(self):
        calls = []

        class RedirectOpener:
            def open(self, request, timeout):
                calls.append(request.full_url)
                raise http_error(307)

        client = self.client(RedirectOpener())
        with self.assertRaises(app.ConjurError) as raised:
            client.get_secret("private")
        self.assertEqual(raised.exception.status, 307)
        self.assertEqual(calls, ["https://conjur.test/prefix/authn/acct%2Fteam/host%2Flab%2Fcheckout/authenticate"])
        self.assertNotIn("api-key", str(raised.exception))

    def test_non_200_redirect_response_is_rejected_without_reading_it_as_secret(self):
        opener = FakeOpener(lambda _request, _timeout, _n: FakeResponse(b"redirect-body", status=307))
        client = self.client(opener)
        with self.assertRaises(app.ConjurError) as raised:
            client.get_secret("private")
        self.assertEqual(raised.exception.status, 307)
        self.assertEqual(len(opener.requests), 1)

    def test_file_secret_precedes_environment_alternative(self):
        with tempfile.TemporaryDirectory() as directory:
            key_file = Path(directory) / "api-key"
            key_file.write_text(" file-key\n")
            client = app.ConjurClient(
                "https://conjur.test", "sandbox", "host/lab/checkout",
                api_key="environment-key", api_key_file=str(key_file),
                opener=FakeOpener(lambda _request, _timeout, _n: b"token"),
            )
            self.assertEqual(client._api_key_value(), b"file-key")


class ServiceTests(unittest.TestCase):
    def test_each_evaluation_reads_fresh_secret_and_version(self):
        class RotatingClient:
            def __init__(self):
                self.reads = []
                self.version = 0

            def get_secret(self, variable_id):
                self.reads.append(variable_id)
                if variable_id.endswith("credential-version"):
                    self.version += 1
                    return f"v{self.version}".encode()
                return f"key-{len(self.reads)}".encode()

        client = RotatingClient()
        payload = {"order_id": "ord-42", "amount": 14.5, "currency": "usd"}
        first = app.evaluate(client, "checkout", payload)
        second = app.evaluate(client, "checkout", payload)
        self.assertEqual(first["credential_version"], "v1")
        self.assertEqual(second["credential_version"], "v2")
        self.assertEqual(client.reads, [
            "lab/secrets/payment-api-key", "lab/secrets/credential-version",
            "lab/secrets/payment-api-key", "lab/secrets/credential-version",
        ])
        self.assertNotIn("signature", first)
        self.assertNotIn("digest", first)

    def test_fraud_role_uses_fraud_secret_and_returns_coarse_score(self):
        class Client:
            def __init__(self):
                self.reads = []

            def get_secret(self, variable_id):
                self.reads.append(variable_id)
                return b"v3" if variable_id.endswith("credential-version") else b"model-key"

        client = Client()
        result = app.evaluate(client, "fraud", {"order_id": "ord_1", "amount": 5, "currency": "EUR"})
        self.assertEqual(client.reads, ["lab/secrets/fraud-model-key", "lab/secrets/credential-version"])
        self.assertIn(result["risk_level"], ("low", "high"))
        self.assertTrue(0 <= result["risk_score"] <= 100)
        self.assertEqual(result["credential_version"], "v3")

    def test_invalid_amounts_and_payload_are_rejected_before_secret_access(self):
        class NoReadClient:
            def get_secret(self, _variable_id):
                raise AssertionError("invalid payload accessed a secret")

        client = NoReadClient()
        valid = {"order_id": "id", "amount": 1, "currency": "USD"}
        for amount in (0, -1, True, float("nan"), float("inf"), 1000001, "12"):
            with self.subTest(amount=amount), self.assertRaises(ValueError):
                app.evaluate(client, "checkout", {**valid, "amount": amount})
        with self.assertRaises(ValueError):
            app.evaluate(client, "checkout", {**valid, "unexpected": "field"})
        with self.assertRaises(ValueError):
            app.evaluate(client, "checkout", {**valid, "order_id": "unsafe/order"})

    def test_credential_version_is_restricted_to_nonsecret_token_shape(self):
        class Client:
            def get_secret(self, _variable_id):
                return b"value with spaces"

        with self.assertRaises(app.ConjurError):
            app._credential_version(Client())

    def test_permission_check_requires_forbidden_secret_denial(self):
        class Client:
            def __init__(self, status):
                self.status = status

            def get_secret(self, variable_id):
                if variable_id == "lab/secrets/credential-version":
                    return b"v1"
                if variable_id == "lab/secrets/fraud-model-key":
                    raise app.ConjurError("denied", self.status)
                return b"allowed"

        app.check_permissions(Client(404), "checkout")
        with self.assertRaises(app.ConjurError):
            app.check_permissions(Client(500), "checkout")
        with self.assertRaises(app.ConjurError):
            app.check_permissions(Client(None), "checkout")

    def test_health_and_readiness_have_distinct_dependency(self):
        class Client:
            def get_secret(self, variable_id):
                if variable_id.endswith("credential-version"):
                    return b"v1"
                raise app.ConjurError("down")

        service = app.PaymentRiskService(Client(), "checkout")
        handler = app.handler_for(service)
        self.assertIsNotNone(handler)
        with self.assertRaises(app.ConjurError):
            service.ready()

    def test_http_liveness_and_evaluation_response_do_not_expose_key_material(self):
        secret = b"never-return-this-payment-key"

        class Client:
            def __init__(self):
                self.reads = []

            def get_secret(self, variable_id):
                self.reads.append(variable_id)
                return b"v2" if variable_id.endswith("credential-version") else secret

        client = Client()
        server = app.BoundedThreadingHTTPServer(
            ("127.0.0.1", 0), app.handler_for(app.PaymentRiskService(client, "checkout"))
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=2)
        try:
            connection.request("GET", "/healthz")
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertEqual(json.loads(response.read()), {"status": "ok"})
            self.assertEqual(client.reads, [])

            connection.request(
                "POST", "/evaluate",
                body=json.dumps({"order_id": "ord-42", "amount": 3, "currency": "USD"}),
                headers={"Content-Type": "application/json"},
            )
            response = connection.getresponse()
            body = response.read()
            self.assertEqual(response.status, 200)
            self.assertEqual(json.loads(body)["credential_version"], "v2")
            self.assertNotIn(secret, body)
            self.assertNotIn(b"signature", body)
            self.assertEqual(client.reads, ["lab/secrets/payment-api-key", "lab/secrets/credential-version"])
        finally:
            connection.close()
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_unexpected_evaluation_failure_returns_generic_error_body(self):
        class BrokenClient:
            def get_secret(self, _variable_id):
                raise RuntimeError("sensitive backend detail")

        server = app.BoundedThreadingHTTPServer(
            ("127.0.0.1", 0), app.handler_for(app.PaymentRiskService(BrokenClient(), "checkout"))
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=2)
        try:
            connection.request(
                "POST", "/evaluate",
                body=json.dumps({"order_id": "ord-42", "amount": 3, "currency": "USD"}),
                headers={"Content-Type": "application/json"},
            )
            response = connection.getresponse()
            body = response.read()
            self.assertEqual(response.status, 503)
            self.assertEqual(json.loads(body), {"error": "request_unavailable"})
            self.assertNotIn(b"sensitive backend detail", body)
        finally:
            connection.close()
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_base_url_requires_https(self):
        with self.assertRaises(ValueError):
            app.ConjurClient("http://conjur.test", "sandbox", "host/lab/checkout")


if __name__ == "__main__":
    unittest.main()
