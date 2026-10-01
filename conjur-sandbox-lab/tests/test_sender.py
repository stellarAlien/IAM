import importlib.util
import io
from pathlib import Path
import secrets
import stat
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location('send_message', Path(__file__).parents[1] / 'scripts/send-message.py')
sender = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sender)
GATEWAY_SPEC = importlib.util.spec_from_file_location('test_gateway', Path(__file__).parents[1] / 'scripts/test-gateway.py')
gateway = importlib.util.module_from_spec(GATEWAY_SPEC)
GATEWAY_SPEC.loader.exec_module(gateway)


class Response:
    def __init__(self, value):
        self.value = value

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        pass

    def read(self):
        return self.value


class SenderTests(unittest.TestCase):
    def test_gateway_denial_requires_exact_status_and_safe_body(self):
        result = type('Result', (), {'stdout': '{"error":"unauthorized"}\nHTTP_STATUS:401\n', 'returncode': 22})()
        gateway.check_response(result, 401)
        result.stdout = '{"error":"unauthorized"}\nHTTP_STATUS:429\n'
        with self.assertRaises(ValueError):
            gateway.check_response(result, 401)
        result.stdout = '{"error":"gateway_failure"}\nHTTP_STATUS:401\n'
        with self.assertRaises(ValueError):
            gateway.check_response(result, 401)

    def test_gateway_success_requires_response_scope(self):
        result = type('Result', (), {'stdout': '{"status":"accepted","tenant":"acme","environment":"dev"}\nHTTP_STATUS:202\n', 'returncode': 0})()
        gateway.check_response(result, 202, ('acme', 'dev'))
        with self.assertRaises(ValueError):
            gateway.check_response(result, 202, ('globex', 'dev'))

    def test_scoped_identity_and_private_curl_header_file(self):
        requests = []
        header_paths = []
        key = secrets.token_urlsafe(48)
        caller = secrets.token_urlsafe(48)
        body = 'Synthetic test message'
        class Opener:
            def open(self, request, timeout):
                requests.append(request)
                return Response(b'opaque-conjur-token' if len(requests) == 1 else caller.encode())
        def curl(command, input, check):
            self.assertEqual(command[:2], ['curl', '--disable'])
            self.assertEqual(command[-1], 'https://localhost:8444/tenants/globex/prod/messages')
            self.assertNotIn(caller, ' '.join(command))
            self.assertNotIn(key, ' '.join(command))
            self.assertNotIn(body, ' '.join(command))
            self.assertIn(b'Synthetic test message', input)
            header = Path(command[command.index('--header') + 1][1:])
            header_paths.append(header)
            self.assertEqual(stat.S_IMODE(header.stat().st_mode), 0o600)
            self.assertEqual(header.read_text(), f'Authorization: Bearer {caller}\n')
            return type('Result', (), {'returncode': 22})()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / '.runtime').mkdir()
            (root / '.runtime/acme_dev_sender_key').write_text(key)
            (root / '.env').write_text('CONJUR_ACCOUNT=demo\nCONJUR_HTTPS_PORT=9443\n')
            with patch.object(sender, '__file__', str(root / 'scripts/send-message.py')), \
                 patch.object(sender.sys, 'argv', ['send-message.py', '--target-tenant', 'globex', '--target-environment', 'prod']), \
                 patch.object(sender.sys, 'stdin', io.StringIO(body)), \
                 patch.dict(sender.os.environ, {}, clear=True), \
                 patch.object(sender.ssl, 'create_default_context'), \
                 patch.object(sender.urllib.request, 'build_opener', return_value=Opener()), \
                 patch.object(sender.subprocess, 'run', side_effect=curl):
                self.assertEqual(sender.main(), 22)
        self.assertEqual(requests[0].full_url, 'https://localhost:9443/authn/demo/host%2Ftenants%2Facme%2Fdev%2Fsender/authenticate')
        self.assertEqual(requests[0].data, key.encode())
        self.assertEqual(requests[1].full_url, 'https://localhost:9443/secrets/demo/variable/tenants%2Facme%2Fdev%2Fsecrets%2Fingress-token')
        self.assertTrue(all(not header.exists() for header in header_paths))

    def test_message_validation_precedes_credentials_or_network(self):
        for message in ('', 'é' * 1025):
            with patch.object(sender.sys, 'argv', ['send-message.py']), \
                 patch.object(sender.sys, 'stdin', io.StringIO(message)), \
                 patch.object(sender.urllib.request, 'build_opener') as opener:
                with self.assertRaises(ValueError):
                    sender.main()
                opener.assert_not_called()


if __name__ == '__main__':
    unittest.main()
