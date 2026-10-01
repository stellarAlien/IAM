import argparse
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from okta_lab import manage


class FakeAPI:
    def __init__(self):
        self.calls = []
        self.names = {}
        self.users = {}
        self.existing = []

    def call(self, method, path, payload=None, params=None):
        self.calls.append((method, path, payload, params))
        if path == '/api/v1/groups' and method == 'GET':
            return self.existing
        if path == '/api/v1/groups' and method == 'POST':
            identifier = '00g' + str(len(self.names))
            self.names[identifier] = payload['profile']['name']
            return {'id': identifier}
        if method == 'GET' and path.startswith('/api/v1/groups/'):
            return {'type': 'OKTA_GROUP', 'profile': {'name': self.names[path.split('/')[-1]]}}
        if method == 'GET' and path == '/api/v1/users':
            return self.existing
        if method == 'POST' and path == '/api/v1/users':
            user = {'id': '00u1', 'status': 'STAGED', **payload}
            self.users[user['id']] = user
            return user
        if method == 'GET' and path.startswith('/api/v1/users/'):
            if path.endswith('/groups'):
                return []
            return self.users[path.split('/')[-1]]
        return None


class ManagementTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        root = patch.object(manage, 'ROOT', self.root)
        root.start()
        self.addCleanup(root.stop)
        self.out = io.StringIO()
        redirect = contextlib.redirect_stdout(self.out)
        redirect.__enter__()
        self.addCleanup(redirect.__exit__, None, None, None)
        self.api = FakeAPI()
        self.state = {'org_url': 'https://integrator-test.okta.com', 'groups': {}, 'users': {}}

    def setup_actor(self):
        manage.groups(self.api, self.state)
        args = argparse.Namespace(actor='alice', login='iam-lab-alice@example.test', scope='globex/dev')
        manage.join(self.api, self.state, args)
        return args

    def test_group_provision_is_idempotent_and_scoped(self):
        manage.groups(self.api, self.state)
        manage.groups(self.api, self.state)
        self.assertEqual(len(self.api.names), 6)
        self.assertTrue(all(name.startswith('iam-lab-') for name in self.api.names.values()))
        self.assertEqual((self.root / 'registry.json').stat().st_mode & 0o777, 0o600)

    def test_no_adoption_of_external_same_name_group(self):
        self.api.existing = [{'profile': {'name': 'iam-lab-users'}}]
        with self.assertRaises(manage.LabError):
            manage.groups(self.api, self.state)
        self.assertFalse(any(call[0] == 'POST' for call in self.api.calls))

    def test_user_staged_without_password_or_existing_user_adoption(self):
        self.setup_actor()
        creation = next(call for call in self.api.calls if call[:2] == ('POST', '/api/v1/users'))
        self.assertEqual(creation[3], {'activate': 'false'})
        self.assertNotIn('credentials', creation[2])
        self.assertNotIn('iam-lab-alice@example.test', self.out.getvalue())
        self.api.existing = [{'id': 'external'}]
        with self.assertRaises(manage.LabError):
            manage.join(self.api, self.state, argparse.Namespace(actor='eve', login='iam-lab-eve@example.test'))

    def test_registered_user_mismatch_blocks_mutation(self):
        self.setup_actor()
        self.api.users['00u1']['profile']['login'] = 'changed@example.test'
        with self.assertRaises(manage.LabError):
            manage.registered_user(self.api, self.state, 'alice')

    def test_move_blocks_old_token_and_removes_roles_before_new_grant(self):
        args = self.setup_actor()
        self.api.calls.clear()
        manage.move(self.api, self.state, args)
        policy = manage.local_policy()
        self.assertEqual(policy['blocked_subjects'], ['00u1'])
        mutations = [call for call in self.api.calls if call[0] in ('DELETE', 'PUT')]
        self.assertEqual([call[0] for call in mutations], ['DELETE'] * 5 + ['PUT'])
        target_group = self.state['groups']['iam-lab-globex-dev-submitters']
        self.assertEqual(mutations[-1][1], f'/api/v1/groups/{target_group}/users/00u1')

    def test_registry_org_cannot_change(self):
        manage.save(self.root / 'registry.json', self.state)
        with self.assertRaises(manage.LabError):
            manage.registry({'org_url': 'https://integrator-other.okta.com'})

    def test_confirmation_is_explicit(self):
        with self.assertRaises(manage.LabError):
            manage.confirm(argparse.Namespace(confirm=''))
        manage.confirm(argparse.Namespace(confirm='lab-only'))

    def test_local_block_removes_jit_grants(self):
        manage.save(self.root / 'access.json', {'blocked_subjects': [], 'grants': {'00u1': {'acme/prod': 9999999999}}})
        manage.block('00u1')
        self.assertEqual(manage.local_policy(), {'blocked_subjects': ['00u1'], 'grants': {}})

    def test_api_token_has_no_redirect_or_environment_proxy(self):
        token = self.root / 'okta_api_token'
        token.write_text('synthetic-offline-test-token')
        with patch.dict(manage.os.environ, {'OKTA_API_TOKEN_FILE': str(token)}):
            api = manage.Okta(self.state)
        self.assertFalse(api.session.trust_env)
        response = type('Response', (), {'status_code': 429})()
        with patch.object(api.session, 'request', return_value=response) as request:
            with self.assertRaises(manage.LabError):
                api.call('POST', '/api/v1/users')
        self.assertFalse(request.call_args.kwargs['allow_redirects'])
        self.assertEqual(request.call_count, 1)

    def test_containment_does_not_require_management_token_or_network(self):
        self.state['users']['eve'] = {'id': '00uSyntheticEve', 'login': 'iam-lab-eve@example.test'}
        manage.save(self.root / 'registry.json', self.state)
        with patch.object(manage, 'load_config', return_value=self.state), \
             patch.object(manage.sys, 'argv', ['manage', 'contain', '--actor', 'eve']), \
             patch.object(manage, 'Okta') as api:
            manage.main()
        api.assert_not_called()
        self.assertEqual(manage.local_policy()['blocked_subjects'], ['00uSyntheticEve'])

    def test_release_sets_cutoff_and_keeps_old_token_blocking_semantics(self):
        self.setup_actor()
        self.api.users['00u1']['status'] = 'ACTIVE'
        manage.block('00u1')
        with patch.object(manage, 'load_config', return_value=self.state), \
             patch.object(manage.sys, 'argv', ['manage', 'release', '--actor', 'alice', '--confirm', 'lab-only']), \
             patch.object(manage, 'Okta', return_value=self.api), patch.object(manage.time, 'time', return_value=1234):
            manage.main()
        policy = manage.local_policy()
        self.assertEqual(policy['blocked_subjects'], [])
        self.assertEqual(policy['not_before'], {'00u1': 1235})

    def test_remote_offboarding_failure_preserves_local_block(self):
        self.setup_actor()
        original = self.api.call
        def failing_call(method, path, *args, **kwargs):
            if path.endswith('/sessions'):
                raise manage.LabError('Synthetic management outage')
            return original(method, path, *args, **kwargs)
        with patch.object(manage, 'load_config', return_value=self.state), \
             patch.object(manage.sys, 'argv', ['manage', 'leave', '--actor', 'alice', '--confirm', 'deactivate-lab-user']), \
             patch.object(manage, 'Okta', return_value=self.api), patch.object(self.api, 'call', side_effect=failing_call):
            with self.assertRaises(manage.LabError):
                manage.main()
        self.assertEqual(manage.local_policy()['blocked_subjects'], ['00u1'])

    def test_jit_limit_rejected_before_user_mutation(self):
        self.setup_actor()
        self.api.calls.clear()
        with patch.object(manage, 'load_config', return_value=self.state), \
             patch.object(manage.sys, 'argv', ['manage', 'jit', '--actor', 'alice', '--scope', 'acme/prod', '--minutes', '16', '--confirm', 'lab-only']), \
             patch.object(manage, 'Okta', return_value=self.api):
            with self.assertRaises(manage.LabError):
                manage.main()
        self.assertEqual(self.api.calls, [])


if __name__ == '__main__':
    unittest.main()
