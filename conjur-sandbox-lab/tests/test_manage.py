import contextlib
import importlib.util
import io
from pathlib import Path
import secrets
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location('manage', Path(__file__).parents[1] / 'scripts/manage.py')
manage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(manage)


class FakeClient:
    account_name = 'sandbox'

    def __init__(self):
        self.values = {}
        self.writes = []
        self.policies = []
        self.roles = {}
        self.fail_write = None

    def read(self, identifier):
        if identifier not in self.values:
            raise manage.APIError(404)
        return self.values[identifier]

    def write(self, identifier, value):
        if identifier == self.fail_write:
            raise manage.APIError(503)
        self.values[identifier] = value
        self.writes.append(identifier)

    def policy(self, branch, filename):
        self.policies.append((branch, filename))
        return {'created_roles': self.roles} if filename == '02-app-identity.yml' else {}


class ManagementTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        root_patch = patch.object(manage, 'ROOT', self.root)
        root_patch.start()
        self.addCleanup(root_patch.stop)
        output_patch = contextlib.redirect_stdout(io.StringIO())
        self.output = output_patch.__enter__()
        self.addCleanup(output_patch.__exit__, None, None, None)

    def test_bootstrap_parses_current_conjurctl_output_privately(self):
        key = secrets.token_hex(32)
        source = self.root / 'bootstrap.out'
        source.write_text(f'Token-Signing Public Key: public\nAPI key for admin: {key}\n')
        manage.bootstrap_key()
        destination = self.root / 'admin_api_key'
        self.assertEqual(destination.read_text(), key)
        self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
        self.assertFalse(source.exists())
        self.assertNotIn(key, self.output.getvalue())

    def test_unexpected_bootstrap_output_is_preserved(self):
        source = self.root / 'bootstrap.out'
        source.write_text('Unexpected account output')
        with self.assertRaises(manage.OperationError):
            manage.bootstrap_key()
        self.assertTrue(source.exists())
        self.assertFalse((self.root / 'admin_api_key').exists())

    def test_bootstrap_is_idempotent(self):
        key = secrets.token_hex(32)
        (self.root / 'admin_api_key').write_text(key)
        manage.bootstrap_key()
        self.assertEqual((self.root / 'admin_api_key').read_text(), key)

    def test_policy_host_keys_persist_and_are_never_printed(self):
        client = FakeClient()
        keys = {workload: secrets.token_hex(32) for workload in ('checkout', 'fraud')}
        client.roles = {f'sandbox:host:lab/{workload}': {'api_key': key} for workload, key in keys.items()}
        manage.load_policies(client)
        client.roles = {}
        manage.load_policies(client)
        for workload, key in keys.items():
            self.assertEqual((self.root / f'{workload}_api_key').read_text(), key)
            self.assertNotIn(key, self.output.getvalue())
        self.assertEqual(client.policies[:3], [('root', '01-root.yml'), ('lab', '02-app-identity.yml'), ('lab', '03-secrets.yml')])

    def test_missing_existing_identity_key_fails_without_rotating_identity(self):
        with self.assertRaises(manage.OperationError):
            manage.load_policies(FakeClient())

    def test_seed_preserves_values_on_repeat(self):
        client = FakeClient()
        manage.seed(client)
        initial = dict(client.values)
        manage.seed(client)
        self.assertEqual(client.values, initial)
        self.assertEqual(client.writes[-1], manage.VERSION_ID)
        for identifier in manage.SECRET_IDS:
            self.assertNotIn(client.values[identifier].decode(), self.output.getvalue())

    def test_rotation_changes_both_keys_and_publishes_marker_last(self):
        client = FakeClient()
        manage.rotate(client)
        initial = dict(client.values)
        version = manage.rotate(client)
        self.assertEqual(client.writes[-1], manage.VERSION_ID)
        self.assertEqual(client.values[manage.VERSION_ID].decode(), version)
        for identifier in manage.SECRET_IDS:
            self.assertNotEqual(client.values[identifier], initial[identifier])

    def test_partial_rotation_does_not_publish_success_marker(self):
        client = FakeClient()
        manage.rotate(client)
        version = client.read(manage.VERSION_ID)
        client.fail_write = manage.SECRET_IDS[1]
        with self.assertRaises(manage.APIError):
            manage.rotate(client)
        self.assertEqual(client.read(manage.VERSION_ID), version)


if __name__ == '__main__':
    unittest.main()
