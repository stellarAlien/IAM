import io
from pathlib import Path
import unittest
from unittest.mock import patch

from okta_lab import send


class SenderTests(unittest.TestCase):
    def test_curl_header_is_private_and_token_not_an_argument(self):
        token = 'synthetic-jwt-for-offline-transport-test'
        files = []
        with patch.object(send, 'load_config', return_value={'api_origin': 'http://127.0.0.1:8090'}), \
             patch.object(send.Path, 'read_text', return_value=token), \
             patch.object(send.sys, 'argv', ['send', '--tenant', 'globex', '--environment', 'prod']), \
             patch.object(send.sys, 'stdin', io.StringIO('Synthetic message')), \
             patch.object(send.subprocess, 'run') as curl:
            curl.side_effect = lambda command, input, check: self.private_command(command, input, token, files)
            self.assertEqual(send.main(), 22)
        self.assertTrue(all(not file.exists() for file in files))

    def private_command(self, command, input, token, files):
        self.assertNotIn(token, ' '.join(command))
        self.assertEqual(command[-1], 'http://127.0.0.1:8090/tenants/globex/prod/messages')
        header = Path(command[command.index('--header') + 1][1:])
        files.append(header)
        self.assertEqual(header.stat().st_mode & 0o777, 0o600)
        with header.open() as stream:
            self.assertEqual(stream.read(), 'Authorization: Bearer ' + token + '\n')
        self.assertIn(b'Synthetic message', input)
        return type('Result', (), {'returncode': 22})()

    def test_missing_or_invalid_message_never_reads_token(self):
        with patch.object(send, 'load_config', return_value={'api_origin': 'http://127.0.0.1:8090'}), \
             patch.object(send.sys, 'argv', ['send']), \
             patch.object(send.sys, 'stdin', io.StringIO('')), patch.object(send.Path, 'read_text') as read:
            with self.assertRaises(ValueError):
                send.main()
        read.assert_not_called()

    def test_unicode_at_utf8_limit_is_sent_without_ascii_expansion(self):
        message = '😀' * 512
        with patch.object(send, 'load_config', return_value={'api_origin': 'http://127.0.0.1:8090'}), \
             patch.object(send.Path, 'read_text', return_value='synthetic-token'), \
             patch.object(send.sys, 'argv', ['send']), \
             patch.object(send.sys, 'stdin', io.StringIO(message)), \
             patch.object(send.subprocess, 'run', return_value=type('Result', (), {'returncode': 0})()) as curl:
            self.assertEqual(send.main(), 0)
        payload = curl.call_args.kwargs['input']
        self.assertLess(len(payload), 4096)
        self.assertIn(message.encode('utf-8'), payload)


if __name__ == '__main__':
    unittest.main()
