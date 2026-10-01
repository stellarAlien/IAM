import contextlib
import importlib.util
import io
import json
from pathlib import Path
import secrets
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPTS = Path(__file__).parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import exercise
from manage import APIError, OperationError

SPEC = importlib.util.spec_from_file_location('exercise_report', SCRIPTS / 'exercise-report.py')
report = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(report)


class FakeClient:
    account = 'sandbox'
    account_name = 'sandbox'

    def __init__(self, deny=False, status=403):
        self.deny = deny
        self.status = status
        self.calls = []
        self.secret = secrets.token_urlsafe(48).encode()
        self.authentications = 0
        self.roles = {}

    def authenticate(self):
        self.authentications += 1

    def operation(self, *call):
        self.calls.append(call)
        if self.deny:
            raise APIError(self.status)
        return self.secret

    def read(self, identifier):
        return self.operation('read', identifier)

    def write(self, identifier, value):
        return self.operation('write', identifier, value)

    def request(self, method, path, *args):
        return self.operation(method, path, *args)

    def policy(self, branch, filename):
        self.calls.append(('policy', branch, filename))
        return {'created_roles': self.roles}


class ExerciseTests(unittest.TestCase):
    def setUp(self):
        self.output = io.StringIO()
        redirect = contextlib.redirect_stdout(self.output)
        redirect.__enter__()
        self.addCleanup(redirect.__exit__, None, None, None)

    def records(self):
        return [json.loads(line) for line in self.output.getvalue().splitlines()]

    def test_allowed_read_never_prints_secret_or_digest(self):
        client = FakeClient()
        self.assertEqual(exercise.attempt(client, 'eve', 'payment'), 'allow')
        record = self.records()[0]
        self.assertTrue(record['alert'])
        self.assertNotIn(client.secret.decode(), self.output.getvalue())
        self.assertEqual(set(record), {'timestamp', 'event_id', 'source', 'actor', 'action', 'outcome', 'http_status', 'alert', 'canary_signal'})

    def test_denial_records_no_response_body(self):
        for status in (403, 404):
            self.assertEqual(exercise.attempt(FakeClient(True, status), 'eve', 'fraud'), 'deny')
        self.assertEqual([record['http_status'] for record in self.records()], [403, 404])

    def test_outage_is_not_treated_as_security_success(self):
        for status in (401, 429, 503):
            with self.assertRaises(APIError):
                exercise.attempt(FakeClient(True, status), 'eve', 'payment')
        self.assertEqual(self.records(), [])

    def test_expected_denial_fails_when_access_succeeds(self):
        with self.assertRaises(OperationError):
            exercise.act(FakeClient(), 'eve', 'payment', 'deny')

    def test_actor_validation_before_authentication(self):
        client = FakeClient()
        for actor, action, expected in [('admin', 'payment', 'observe'), ('eve', 'dump', 'observe'), ('eve', 'payment', 'yes')]:
            with self.assertRaises(OperationError):
                exercise.act(client, actor, action, expected)
        self.assertEqual(client.authentications, 0)

    def test_watch_reuses_existing_token_and_observes_containment(self):
        client = FakeClient()
        def contain(_seconds):
            client.deny = True
        with patch.object(exercise.time, 'sleep', side_effect=contain):
            exercise.act(client, 'eve', 'watch-payment')
        records = self.records()
        self.assertEqual(client.authentications, 1)
        self.assertEqual(len(records), 21)
        self.assertEqual(records[1]['outcome'], 'allowed')
        self.assertTrue(all(record['outcome'] == 'denied' for record in records[2:]))

    def test_metadata_does_not_use_secret_value_endpoint(self):
        client = FakeClient()
        exercise.attempt(client, 'alice', 'metadata')
        self.assertEqual(client.calls[0][:2], ('GET', '/resources/sandbox/variable/lab%2Fsecrets%2Fpayment-api-key'))

    def test_escalation_uses_current_actor_not_admin(self):
        client = FakeClient(True)
        exercise.attempt(client, 'eve', 'escalate')
        self.assertIn(b'!user /lab-eve', client.calls[0][2])
        self.assertNotIn(b'admin', client.calls[0][2])

    def test_canary_emits_detection_signal(self):
        exercise.attempt(FakeClient(), 'eve', 'canary')
        self.assertTrue(self.records()[0]['canary_signal'])
        self.assertFalse(self.records()[0]['alert'])

    def test_intentional_overgrant_requires_confirmation(self):
        client = FakeClient()
        with patch.dict(exercise.os.environ, {'EXERCISE_CONFIRM': ''}):
            with self.assertRaises(OperationError):
                exercise.administer(client, 'expose')
        self.assertEqual(client.calls, [])

    def test_recovery_contains_before_rotating(self):
        client = FakeClient()
        steps = []
        with patch.object(exercise, 'patch_policy', side_effect=lambda _client, file: steps.append(file)), \
             patch.object(exercise, 'rotate', side_effect=lambda _client: steps.append('rotate')):
            exercise.administer(client, 'recover')
        self.assertEqual(steps, ['contain.yml', 'rotate'])

    def test_setup_captures_distinct_private_user_keys_and_preserves_on_repeat(self):
        client = FakeClient()
        keys = {actor: secrets.token_urlsafe(48) for actor in exercise.ACTORS}
        client.roles = {f'sandbox:user:lab-{actor}': {'api_key': key} for actor, key in keys.items()}
        with tempfile.TemporaryDirectory() as temp, patch.object(exercise, 'ROOT', Path(temp)), patch.object(exercise, 'patch_policy') as reset:
            exercise.setup(client)
            client.roles = {}
            exercise.setup(client)
            for actor, key in keys.items():
                self.assertEqual((Path(temp) / f'{actor}_api_key').read_text(), key)
                self.assertNotIn(key, self.output.getvalue())
            self.assertEqual(reset.call_args.args[1], 'reset.yml')

    def test_setup_does_not_reissue_missing_existing_identity(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(exercise, 'ROOT', Path(temp)):
            with self.assertRaises(OperationError):
                exercise.setup(FakeClient())

    def test_report_ignores_foreign_data_and_never_echoes_arbitrary_fields(self):
        exercise.event('eve', 'payment', 'allowed', 200, response='secret-value-must-not-be-echoed')
        exercise.event('facilitator', 'contain', 'eve-group-access-revoked', 200)
        records = self.output.getvalue()
        self.output.truncate(0)
        self.output.seek(0)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'events.jsonl'
            path.write_text(records + '\nmalformed\n' + json.dumps({'source': 'server-audit', 'actor': 'admin'}) + '\n')
            report.summarize(path)
        self.assertIn('observed payment reads: 1', self.output.getvalue())
        self.assertIn('CLIENT OBSERVATIONS ONLY', self.output.getvalue())
        self.assertNotIn('secret-value-must-not-be-echoed', self.output.getvalue())


if __name__ == '__main__':
    unittest.main()
