import contextlib
import importlib.util
import io
from pathlib import Path
import secrets
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPTS = Path(__file__).parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import tenants
from manage import APIError, OperationError

SPEC = importlib.util.spec_from_file_location('container_security', SCRIPTS / 'container-security.py')
container_security = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(container_security)

SCOPES = [('acme', 'dev'), ('acme', 'prod'), ('globex', 'dev'), ('globex', 'prod')]


class FakeClient:
    account_name = 'sandbox'

    def __init__(self):
        self.values = {}
        self.roles = {}
        self.writes = []

    def policy(self, *_args):
        return {'created_roles': self.roles}

    def read(self, identifier):
        if identifier not in self.values:
            raise APIError(404)
        return self.values[identifier]

    def write(self, identifier, value):
        self.values[identifier] = value
        self.writes.append(identifier)


class TenantTests(unittest.TestCase):
    def setUp(self):
        self.output = io.StringIO()
        stdout = contextlib.redirect_stdout(self.output)
        stdout.__enter__()
        self.addCleanup(stdout.__exit__, None, None, None)
        scopes = patch.object(tenants, 'scopes', return_value=SCOPES)
        scopes.start()
        self.addCleanup(scopes.stop)

    def test_provision_preserves_all_scopes_and_secrets_on_repeat(self):
        client = FakeClient()
        client.roles = {f'sandbox:host:{tenants.prefix(*scope)}/{kind}': {'api_key': secrets.token_urlsafe(48)}
                        for scope in SCOPES for kind in ('api', 'sender')}
        with tempfile.TemporaryDirectory() as temp, patch.object(tenants, 'ROOT', Path(temp)):
            tenants.provision(client)
            first = dict(client.values)
            client.roles = {}
            tenants.provision(client)
            self.assertEqual(first, client.values)
            self.assertEqual(len(client.writes), 8)
            for scope in SCOPES:
                for kind in ('api', 'sender'):
                    path = Path(temp) / f'{scope[0]}_{scope[1]}_{kind}_key'
                    self.assertEqual(path.stat().st_mode & 0o777, 0o444 if kind == 'api' else 0o600)
                    self.assertNotIn(path.read_text(), self.output.getvalue())

    def test_missing_existing_host_key_is_not_reissued(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(tenants, 'ROOT', Path(temp)):
            with self.assertRaises(OperationError):
                tenants.provision(FakeClient())

    def test_scope_rotation_does_not_touch_other_scopes(self):
        client = FakeClient()
        tenants.rotate(client, 'globex', 'prod')
        self.assertEqual(client.writes, ['tenants/globex/prod/secrets/ingress-token', 'tenants/globex/prod/secrets/signing-key'])
        with self.assertRaises(OperationError):
            tenants.rotate(client, '../acme', 'prod')
        self.assertEqual(len(client.writes), 2)

    def test_live_matrix_checks_all_pairs_and_token_rotation(self):
        client = FakeClient()
        for scope in SCOPES:
            client.write(f'{tenants.prefix(*scope)}/secrets/ingress-token', secrets.token_urlsafe(48).encode())
        def fake_post(tenant, environment, token=None):
            actual = client.read(f'{tenants.prefix(tenant, environment)}/secrets/ingress-token')
            return (202, {'tenant': tenant, 'environment': environment}) if token == actual else (401, {})
        with patch.object(tenants, 'post', side_effect=fake_post) as post:
            tenants.verify(client)
        self.assertEqual(post.call_count, 25)

    def test_unexpected_cross_scope_acceptance_fails_verification(self):
        client = FakeClient()
        for scope in SCOPES:
            client.write(f'{tenants.prefix(*scope)}/secrets/ingress-token', secrets.token_urlsafe(48).encode())
        with patch.object(tenants, 'post', side_effect=lambda tenant, environment, token=None:
                          (202, {'tenant': tenant, 'environment': environment}) if token else (401, {})):
            with self.assertRaises(OperationError):
                tenants.verify(client)

    def test_sender_checks_own_token_and_denies_every_other_secret(self):
        clients = []
        def scoped_client(login, key_file):
            own_token = login.removeprefix('host/').removesuffix('/sender') + '/secrets/ingress-token'
            class ScopedClient:
                def read(self, identifier):
                    clients.append((login, identifier))
                    if identifier != own_token:
                        raise APIError(403)
                    return b'generated-token'
            return ScopedClient()
        with patch.object(tenants, 'AdminClient', side_effect=scoped_client):
            tenants.verify_senders()
        self.assertEqual(len(clients), 32)

    def test_sender_overgrant_fails(self):
        client = FakeClient()
        client.read = lambda _identifier: b'generated-value'
        with patch.object(tenants, 'AdminClient', return_value=client):
            with self.assertRaises(OperationError):
                tenants.verify_senders()


class ContainerConfigurationTests(unittest.TestCase):
    def configuration(self):
        return {
            'Config': {'User': '10001:10001', 'Labels': {'com.docker.compose.project': 'lab'}},
            'HostConfig': {'ReadonlyRootfs': True, 'Privileged': False, 'CapDrop': ['ALL'], 'CapAdd': [],
                           'SecurityOpt': ['no-new-privileges:true'], 'PidsLimit': 64, 'Memory': 128 * 1024 * 1024,
                           'NanoCpus': 500000000, 'PortBindings': {}, 'PidMode': '', 'NetworkMode': 'lab_acme-dev'},
            'NetworkSettings': {'Networks': {'lab_acme-dev': {}}},
        }

    def test_valid_boundary_passes(self):
        container_security.configuration_checks('acme-dev', self.configuration())

    def test_privileged_root_and_network_sharing_fail(self):
        for field, value in [('Privileged', True), ('ReadonlyRootfs', False), ('CapAdd', ['SYS_ADMIN']), ('PidsLimit', -1)]:
            config = self.configuration()
            config['HostConfig'][field] = value
            with self.assertRaises(ValueError):
                container_security.configuration_checks('acme-dev', config)
        config = self.configuration()
        config['NetworkSettings']['Networks']['lab_globex-prod'] = {}
        with self.assertRaises(ValueError):
            container_security.configuration_checks('acme-dev', config)


if __name__ == '__main__':
    unittest.main()
