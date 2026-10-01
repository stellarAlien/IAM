import contextlib
import http.client
import io
import json
import os
import sys
import threading
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import message
from app import BoundedThreadingHTTPServer, ConjurError


class FakeConjur:
    def __init__(self):
        self.reads = []
        self.values = {}
        self.denied = set()

    def get_secret(self, name):
        self.reads.append(name)
        if name in self.denied:
            raise ConjurError("denied", 403)
        if name not in self.values:
            raise ConjurError("unavailable")
        value = self.values[name]
        if isinstance(value, Exception):
            raise value
        return value


class MessageTests(unittest.TestCase):
    def setUp(self):
        self.client = FakeConjur()
        self.tenant = "acme"
        self.environment = "dev"
        self.ingress = message.secret_name(self.tenant, self.environment, "ingress-token")
        self.signing = message.secret_name(self.tenant, self.environment, "signing-key")
        self.client.values.update({self.ingress: b"token-v1", self.signing: b"sign-v1"})
        self.server = BoundedThreadingHTTPServer(
            ("127.0.0.1", 0),
            message.handler_for(message.MessageService(self.client, self.tenant, self.environment)),
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=2)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    @staticmethod
    def json_body(value):
        return json.dumps(value, ensure_ascii=False).encode("utf-8")

    def post(self, payload, token="token-v1", extra_headers=None, path="/messages"):
        headers = {"Content-Type": "application/json"}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        headers.update(extra_headers or {})
        return self.request("POST", path, self.json_body(payload), headers)

    def test_health_does_not_call_conjur_and_readiness_checks_both_secrets(self):
        status, body = self.request("GET", "/healthz")
        self.assertEqual((status, json.loads(body)), (200, {"status": "ok"}))
        self.assertEqual(self.client.reads, [])
        status, body = self.request("GET", "/readyz")
        self.assertEqual((status, json.loads(body)), (200, {"status": "ready"}))
        self.assertEqual(self.client.reads, [self.ingress, self.signing])

    def test_valid_post_accepts_without_echoing_or_exposing_digest(self):
        message_text = "private message"
        status, body = self.post({"message": message_text})
        parsed = json.loads(body)
        self.assertEqual(status, 202)
        self.assertEqual(parsed["status"], "accepted")
        self.assertEqual((parsed["tenant"], parsed["environment"]), ("acme", "dev"))
        self.assertRegex(parsed["message_id"], r"^[0-9a-f-]{36}$")
        self.assertNotIn(message_text.encode(), body)
        self.assertNotIn(b"sign-v1", body)
        self.assertEqual(self.client.reads, [self.ingress, self.signing])

    def test_wrong_or_missing_bearer_is_401_and_never_reads_signing_key(self):
        for token in ("wrong-token", None):
            with self.subTest(token=token):
                self.client.reads.clear()
                status, body = self.post({"message": "private"}, token)
                self.assertEqual((status, json.loads(body)), (401, {"error": "unauthorized"}))
                self.assertEqual(self.client.reads, [self.ingress])

    def test_cross_scope_bearer_cannot_authenticate_or_select_tenant_by_header(self):
        foreign_token = b"globex-prod-token"
        status, body = self.request(
            "POST", "/messages", self.json_body({"message": "private"}),
            {"Content-Type": "application/json", "Authorization": "Bearer globex-prod-token", "X-Tenant": "globex"},
        )
        self.assertEqual((status, json.loads(body)), (401, {"error": "unauthorized"}))
        self.assertEqual(self.client.reads, [self.ingress])
        self.client.values[message.secret_name("globex", "prod", "ingress-token")] = foreign_token
        status, body = self.request(
            "POST", "/messages", self.json_body({"message": "private"}),
            {"Content-Type": "application/json", "Authorization": "Bearer token-v1", "X-Tenant": "globex"},
        )
        self.assertEqual(status, 202)
        self.assertEqual(json.loads(body)["tenant"], "acme")

    def test_rotated_secrets_are_read_fresh_for_each_request(self):
        self.post({"message": "one"})
        self.client.values[self.ingress] = b"token-v2"
        self.client.values[self.signing] = b"sign-v2"
        status, _ = self.post({"message": "two"}, "token-v2")
        self.assertEqual(status, 202)
        self.assertEqual(self.client.reads, [self.ingress, self.signing, self.ingress, self.signing])

    def test_secret_outage_returns_generic_503_without_sensitive_data(self):
        self.client.values[self.ingress] = ConjurError("secret backend outage")
        status, body = self.post({"message": "private"})
        self.assertEqual((status, json.loads(body)), (503, {"error": "service_unavailable"}))
        self.assertNotIn(b"outage", body)
        self.assertEqual(self.client.reads, [self.ingress])

    def test_readiness_returns_no_secrets_on_failure(self):
        self.client.values[self.signing] = ConjurError("secret backend outage")
        status, body = self.request("GET", "/readyz")
        self.assertEqual((status, json.loads(body)), (503, {"status": "not_ready"}))
        self.assertNotIn(b"sign-v1", body)

    def test_rejects_invalid_message_shapes_and_utf8_limits(self):
        invalid = [
            {}, {"message": ""}, {"message": 1}, {"message": "ok", "tenant": "globex"},
            {"message": "é" * 1025},
        ]
        for payload in invalid:
            with self.subTest(payload=str(payload)[:24]):
                status, body = self.post(payload)
                self.assertEqual((status, json.loads(body)), (400, {"error": "invalid_message"}))
        self.assertEqual(self.client.reads, [])

    def test_accepts_exact_utf8_message_limit(self):
        status, _ = self.post({"message": "é" * 1024})
        self.assertEqual(status, 202)

    def test_rejects_missing_json_type_transfer_encoding_and_oversize(self):
        body = b'{"message":"x"}'
        cases = [
            ("/messages", body, {"Authorization": "Bearer token-v1"}, 415),
            ("/messages", body, {"Authorization": "Bearer token-v1", "Content-Type": "application/json", "Transfer-Encoding": "chunked"}, 400),
            ("/messages", b"x" * 4097, {"Authorization": "Bearer token-v1", "Content-Type": "application/json"}, 413),
        ]
        for path, payload, headers, expected in cases:
            with self.subTest(expected=expected):
                status, _ = self.request("POST", path, payload, headers)
                self.assertEqual(status, expected)
        self.assertEqual(self.client.reads, [])

    def test_malformed_json_and_bad_content_length_are_rejected(self):
        status, body = self.request(
            "POST", "/messages", b"{", {"Content-Type": "application/json", "Authorization": "Bearer token-v1"}
        )
        self.assertEqual((status, json.loads(body)), (400, {"error": "invalid_message"}))
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=2)
        try:
            connection.putrequest("POST", "/messages")
            connection.putheader("Content-Type", "application/json")
            connection.putheader("Content-Length", "not-a-number")
            connection.endheaders()
            response = connection.getresponse()
            self.assertEqual(response.status, 400)
            self.assertEqual(json.loads(response.read()), {"error": "invalid_request"})
        finally:
            connection.close()

    def test_path_does_not_choose_scope_and_logs_hide_path_and_credentials(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            status, _ = self.post({"message": "private"}, path="/tenants/globex/prod/messages?secret=do-not-log")
        self.assertEqual(status, 404)
        logged = stderr.getvalue()
        self.assertNotIn("globex", logged)
        self.assertNotIn("do-not-log", logged)
        self.assertNotIn("token-v1", logged)
        self.assertEqual(self.client.reads, [])


class ScopeAndPermissionTests(unittest.TestCase):
    def test_scope_validation_and_explicit_host_login(self):
        for scope in (("other", "dev"), ("acme", "stage")):
            with self.subTest(scope=scope), self.assertRaises(ValueError):
                message.validate_scope(*scope)
        env = {
            "TENANT": "acme", "ENVIRONMENT": "dev", "CONJUR_APPLIANCE_URL": "https://conjur.test",
            "CONJUR_AUTHN_API_KEY": "placeholder", "CONJUR_AUTHN_API_KEY_FILE": "",
        }
        with mock.patch.dict(os.environ, env, clear=True):
            client, tenant, environment = message.make_message_client_from_env()
        self.assertEqual((client.login, tenant, environment), ("host/tenants/acme/dev/api", "acme", "dev"))
        env["CONJUR_AUTHN_LOGIN"] = "host/tenants/globex/dev/api"
        with mock.patch.dict(os.environ, env, clear=True), self.assertRaises(ValueError):
            message.make_message_client_from_env()

    def test_permission_check_reads_own_pair_and_requires_all_six_foreign_denials(self):
        client = FakeConjur()
        own = [
            message.secret_name("acme", "dev", "ingress-token"),
            message.secret_name("acme", "dev", "signing-key"),
        ]
        foreign = [
            message.secret_name(tenant, environment, name)
            for tenant in message.TENANTS for environment in message.ENVIRONMENTS
            if (tenant, environment) != ("acme", "dev") for name in ("ingress-token", "signing-key")
        ]
        client.values.update({name: b"value" for name in own})
        client.denied.update(foreign)
        message.check_permissions(client, "acme", "dev")
        self.assertEqual(client.reads, own + foreign)

        client.values[foreign[-1]] = b"over-permitted"
        client.denied.remove(foreign[-1])
        with self.assertRaisesRegex(ConjurError, "another scope"):
            message.check_permissions(client, "acme", "dev")


if __name__ == "__main__":
    unittest.main()
