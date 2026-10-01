from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.exceptions import PyJWKClientConnectionError

from okta_lab.api import JwtVerifier, SafeRequestHandler, create_app
from okta_lab.config import OktaConfig, load_config


class FakeJwksClient:
    def __init__(self, public_key):
        self.public_key = public_key

    def get_signing_key_from_jwt(self, _token):
        return type("SigningKey", (), {"key": self.public_key})()

    def get_signing_keys(self):
        return [self.public_key]


class OfflineJwksClient:
    def get_signing_key_from_jwt(self, _token):
        raise PyJWKClientConnectionError("offline")

    def get_signing_keys(self):
        raise PyJWKClientConnectionError("offline")


class OktaApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.access_file = Path(self.tempdir.name) / "access.json"
        self.config = OktaConfig(
            org_url="https://dev-123.okta.com",
            client_id="lab-client",
            access_file=self.access_file,
        )
        self.verifier = JwtVerifier(
            self.config, FakeJwksClient(self.private_key.public_key())
        )
        self.app = create_app(self.config, self.verifier)
        self.app.testing = True
        self.client = self.app.test_client()

    def token(self, **overrides):
        claims = {
            "iss": self.config.issuer,
            "aud": self.config.audience,
            "cid": self.config.client_id,
            "uid": "00u-user-123",
            "sub": "user-123",
            "iat": int(time.time()) - 1,
            "exp": int(time.time()) + 300,
            "scp": ["messages.send"],
            "groups": ["iam-lab-acme-dev-submitters"],
        }
        claims.update(overrides)
        return jwt.encode(claims, self.private_key, algorithm="RS256", headers={"kid": "lab"})

    def headers(self, token=None):
        return {"Authorization": f"Bearer {token or self.token()}"}

    def post_message(self, **kwargs):
        defaults = {"json": {"message": "hello"}, "headers": self.headers()}
        defaults.update(kwargs)
        if "data" in kwargs and "json" not in kwargs:
            defaults.pop("json")
        return self.client.post("/tenants/acme/dev/messages", **defaults)

    def write_policy(self, policy):
        self.access_file.write_text(json.dumps(policy), encoding="utf-8")

    def test_health_and_readiness_do_not_disclose_configuration(self):
        health = self.client.get("/healthz")
        ready = self.client.get("/readyz")
        self.assertEqual(health.status_code, 200)
        self.assertEqual(ready.status_code, 200)
        self.assertNotIn(b"dev-123", health.data + ready.data)

    def test_http_request_logging_contains_no_request_target_or_details(self):
        with self.assertLogs("okta_lab.audit", level="INFO") as captured:
            SafeRequestHandler.log_request(None, 202, "-")
            SafeRequestHandler.log_error(None, "sensitive request data: %s", "not logged")
        self.assertEqual(
            json.loads(captured.records[0].getMessage()),
            {"action": "http_request", "scope": "http", "status": 202},
        )
        self.assertEqual(
            json.loads(captured.records[1].getMessage()),
            {"action": "http_error", "scope": "http", "status": 500},
        )
        self.assertNotIn("sensitive request data", " ".join(captured.output))

    def test_jwks_network_outage_is_unavailable_not_invalid_token(self):
        app = create_app(self.config, JwtVerifier(self.config, OfflineJwksClient()))
        client = app.test_client()
        self.assertEqual(client.get("/readyz").status_code, 503)
        response = client.post(
            "/tenants/acme/dev/messages",
            json={"message": "hello"},
            headers=self.headers(),
        )
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json(), {"error": "authorization_unavailable"})

    def test_submit_accepts_scoped_signed_access_token_without_echoing_message(self):
        response = self.post_message(json={"message": "private message text"})
        self.assertEqual(response.status_code, 202)
        payload = response.get_json()
        self.assertEqual(
            {key: payload[key] for key in ("status", "tenant", "environment")},
            {"status": "accepted", "tenant": "acme", "environment": "dev"},
        )
        self.assertEqual(set(payload), {"status", "tenant", "environment", "message_id"})
        self.assertRegex(payload["message_id"], r"^[0-9a-f]{32}$")
        self.assertNotIn(b"private message text", response.data)

    def test_access_token_signature_issuer_audience_expiration_and_claims_are_verified(self):
        good = self.token()
        self.assertEqual(self.post_message(headers=self.headers(good)).status_code, 202)
        bad_tokens = [
            self.token(iss="https://other.okta.com/oauth2/default"),
            self.token(aud="lab-client"),
            self.token(exp=int(time.time()) - 1),
            self.token(iat=int(time.time()) + 60),
            self.token(scp="messages.send"),
            self.token(groups=[1]),
        ]
        for token in bad_tokens:
            with self.subTest(token_claims="invalid"):
                self.assertEqual(self.post_message(headers=self.headers(token)).status_code, 401)
        wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        forged = jwt.encode(
            {
                "iss": self.config.issuer,
                "aud": self.config.audience,
                "cid": self.config.client_id,
                "uid": "00u-user-123",
                "sub": "user-123",
                "iat": int(time.time()) - 1,
                "exp": int(time.time()) + 300,
                "scp": ["messages.send"],
                "groups": ["iam-lab-acme-dev-submitters"],
            },
            wrong_key,
            algorithm="RS256",
        )
        self.assertEqual(self.post_message(headers=self.headers(forged)).status_code, 401)
        self.assertEqual(
            self.post_message(headers=self.headers(self.token(cid="another-client"))).status_code,
            401,
        )
        self.assertEqual(
            self.post_message(headers=self.headers(self.token(uid=""))).status_code,
            401,
        )
        self.assertEqual(
            self.post_message(headers=self.headers(self.token(uid="user-id"))).status_code,
            401,
        )

    def test_requires_exact_scope_and_tenant_environment_group(self):
        self.assertEqual(
            self.post_message(headers=self.headers(self.token(scp=["profile"]))).status_code,
            403,
        )
        self.assertEqual(
            self.post_message(
                headers=self.headers(self.token(groups=["iam-lab-acme-prod-submitters"]))
            ).status_code,
            403,
        )
        self.assertEqual(
            self.client.post(
                "/tenants/globex/prod/messages",
                json={"message": "hello"},
                headers=self.headers(),
            ).status_code,
            403,
        )

    def test_scope_and_body_cannot_be_selected_by_request_data(self):
        self.assertEqual(
            self.post_message(json={"message": "hello", "tenant": "globex"}).status_code,
            400,
        )
        self.assertEqual(
            self.client.post(
                "/tenants/acme/test/messages",
                json={"message": "hello"},
                headers=self.headers(),
            ).status_code,
            404,
        )
        self.assertEqual(
            self.client.post(
                "/tenants/acme/dev/messages",
                data=json.dumps({"message": "hello"}),
                content_type="application/json",
                headers={**self.headers(), "X-Tenant": "globex"},
            ).status_code,
            202,
        )

    def test_message_body_requires_one_bounded_utf8_message(self):
        for body in ({}, {"message": ""}, {"message": "x", "extra": True}):
            with self.subTest(body="invalid"):
                self.assertEqual(self.post_message(json=body).status_code, 400)
        self.assertEqual(
            self.post_message(
                data=json.dumps({"message": "é" * 1025}, ensure_ascii=False),
                content_type="application/json",
            ).status_code,
            400,
        )
        self.assertEqual(
            self.post_message(
                data=json.dumps({"message": "é" * 1024}, ensure_ascii=False),
                content_type="application/json",
            ).status_code,
            202,
        )
        oversized = self.client.post(
            "/tenants/acme/dev/messages",
            data=b'{"message":"' + b"a" * 13000 + b'"}',
            content_type="application/json",
            headers=self.headers(),
        )
        self.assertEqual(oversized.status_code, 413)

    def test_worst_case_json_escaping_preserves_decoded_message_limit(self):
        for message in ('😀' * 512, '\u0001' * 2048):
            payload = json.dumps({'message': message})
            self.assertGreater(len(payload.encode()), 4096)
            self.assertEqual(self.post_message(data=payload, content_type='application/json').status_code, 202)
        invalid = json.dumps({'message': '😀' * 513})
        self.assertEqual(self.post_message(data=invalid, content_type='application/json').status_code, 400)

    def test_authentication_and_local_denylist_are_checked_fresh_each_request(self):
        self.assertEqual(self.post_message(headers={}).status_code, 401)
        self.assertEqual(self.post_message().status_code, 202)
        self.write_policy({"blocked_subjects": ["00u-user-123"], "grants": {}})
        self.assertEqual(self.post_message().status_code, 403)
        self.write_policy({"blocked_subjects": [], "grants": {}})
        self.assertEqual(self.post_message().status_code, 202)

    def test_release_not_before_rejects_old_token_but_allows_fresh_token(self):
        self.write_policy(
            {
                "blocked_subjects": [],
                "grants": {},
                "not_before": {"00u-user-123": int(time.time())},
            }
        )
        self.assertEqual(
            self.post_message(headers=self.headers(self.token(iat=int(time.time()) - 2))).status_code,
            403,
        )
        self.assertEqual(
            self.post_message(headers=self.headers(self.token(iat=int(time.time())))).status_code,
            202,
        )

    def test_jit_group_requires_matching_unexpired_local_grant(self):
        jit_token = self.token(groups=["iam-lab-jit-candidates"])
        self.assertEqual(self.post_message(headers=self.headers(jit_token)).status_code, 403)
        self.write_policy(
            {
                "blocked_subjects": [],
                "grants": {
                    "00u-user-123": {"acme/dev": time.time() + 60}
                },
            }
        )
        self.assertEqual(self.post_message(headers=self.headers(jit_token)).status_code, 202)
        self.write_policy(
            {
                "blocked_subjects": [],
                "grants": {
                    "00u-user-123": {"acme/dev": time.time() - 1}
                },
            }
        )
        self.assertEqual(self.post_message(headers=self.headers(jit_token)).status_code, 403)

    def test_malformed_local_policy_fails_closed(self):
        self.access_file.write_text("not-json", encoding="utf-8")
        response = self.post_message()
        self.assertEqual(response.status_code, 503)
        self.assertNotIn(b"not-json", response.data)

    def test_malformed_local_jit_grants_fail_closed(self):
        for expiration in ("", "soon", True, float("nan"), float("inf")):
            with self.subTest(expiration_type=type(expiration).__name__):
                self.write_policy(
                    {
                        "blocked_subjects": [],
                        "grants": {"00u-user-123": {"acme/dev": expiration}},
                    }
                )
                self.assertEqual(self.post_message().status_code, 503)

    def test_finite_float_grant_expiration_matches_management_writer(self):
        self.write_policy(
            {
                "blocked_subjects": [],
                "grants": {"00u-user-123": {"acme/dev": time.time() + 30.5}},
            }
        )
        token = self.token(groups=["iam-lab-jit-candidates"])
        self.assertEqual(self.post_message(headers=self.headers(token)).status_code, 202)

    def test_me_exposes_only_scope_derived_permissions(self):
        response = self.client.get("/me", headers=self.headers())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"permissions": ["messages.send"]})
        self.assertNotIn(b"user-123", response.data)
        self.assertEqual(
            self.client.get("/me", headers=self.headers(self.token(scp=["profile"]))).get_json(),
            {"permissions": []},
        )

    def test_audit_logs_are_structured_without_subject_or_message(self):
        with self.assertLogs("okta_lab.audit", level="INFO") as captured:
            self.post_message(json={"message": "never log this"})
        record = json.loads(captured.records[0].getMessage())
        self.assertEqual(record, {"action": "message", "scope": "acme/dev", "status": 202})
        self.assertNotIn("user-123", captured.output[0])
        self.assertNotIn("never log this", captured.output[0])

    def test_configuration_enforces_okta_org_and_loopback_origin(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "okta.json"
            path.write_text(
                json.dumps(
                    {
                        "org_url": "https://dev-123.okta-emea.com/",
                        "issuer": "https://dev-123.okta-emea.com/oauth2/default",
                        "client_id": "lab-client",
                    }
                ),
                encoding="utf-8",
            )
            config = load_config(path)
            self.assertIsInstance(config, dict)
            self.assertEqual(config["org_url"], "https://dev-123.okta-emea.com")
            self.assertEqual(config["issuer"], "https://dev-123.okta-emea.com/oauth2/default")
            self.assertEqual(
                set(config), {"org_url", "issuer", "client_id", "audience", "api_origin"}
            )
            path.write_text(
                json.dumps(
                    {
                        "org_url": "https://dev-123.okta-emea.com",
                        "issuer": "https://dev-123.okta-emea.com/oauth2/iam-custom",
                        "client_id": "lab-client",
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(
                load_config(path)["issuer"],
                "https://dev-123.okta-emea.com/oauth2/iam-custom",
            )
            path.write_text(
                json.dumps(
                    {
                        "org_url": "https://dev-123.okta-emea.com",
                        "auth_server_id": "iam-custom",
                        "client_id": "lab-client",
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(
                load_config(path)["issuer"],
                "https://dev-123.okta-emea.com/oauth2/iam-custom",
            )
            path.write_text(
                json.dumps(
                    {
                        "org_url": "https://dev-123.okta-emea.com",
                        "issuer": "https://dev-123.okta-emea.com/oauth2/iam-custom",
                        "auth_server_id": "iam-custom",
                        "client_id": "lab-client",
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(
                load_config(path)["issuer"],
                "https://dev-123.okta-emea.com/oauth2/iam-custom",
            )
            path.write_text(
                json.dumps(
                    {
                        "org_url": "https://dev-123.okta-emea.com",
                        "issuer": "https://dev-123.okta-emea.com/oauth2/iam-custom",
                        "auth_server_id": "default",
                        "client_id": "lab-client",
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                load_config(path)
            path.write_text(
                json.dumps(
                    {
                        "org_url": "https://dev-123.okta-emea.com",
                        "issuer": "https://other.okta-emea.com/oauth2/default",
                        "client_id": "lab-client",
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                load_config(path)
            path.write_text(
                json.dumps(
                    {
                        "org_url": "https://dev-123.okta-emea.com",
                        "issuer": "https://dev-123.okta-emea.com/oauth2/iam-custom/extra",
                        "client_id": "lab-client",
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                load_config(path)
            for org_url in (
                "http://dev-123.okta.com",
                "https://dev-123.example.com",
                "https://user:pass@dev-123.okta.com",
                "https://dev-123.okta.com/path",
            ):
                with self.subTest(org_url=org_url):
                    path.write_text(
                        json.dumps({"org_url": org_url, "client_id": "lab-client"}),
                        encoding="utf-8",
                    )
                    with self.assertRaises(ValueError):
                        load_config(path)
            path.write_text(
                json.dumps(
                    {
                        "org_url": "https://dev-123.okta.com",
                        "client_id": "lab-client",
                        "api_origin": "http://0.0.0.0:8090",
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                load_config(path)
            path.write_text(
                json.dumps(
                    {
                        "org_url": "https://dev-123.okta.com",
                        "client_id": "lab-client",
                        "access_file": ".runtime/alternate.json",
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                load_config(path)


if __name__ == "__main__":
    unittest.main()
