"""Scoped curl request using the privately saved PKCE access token."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from .config import load_config


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--tenant', choices=('acme', 'globex'), default='acme')
    parser.add_argument('--environment', choices=('dev', 'prod'), default='dev')
    args = parser.parse_args()
    config = load_config()
    message = sys.stdin.read(4097).rstrip('\n')
    if not 1 <= len(message.encode('utf-8')) <= 2048:
        raise ValueError('Message must be 1..2048 UTF-8 bytes.')
    token = Path('.runtime/access_token').read_text().strip()
    if not token or any(character.isspace() for character in token):
        raise ValueError('Run PKCE login first.')
    with tempfile.TemporaryDirectory(prefix='okta-lab-') as directory:
        path = Path(directory) / 'authorization'
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'w') as stream:
            stream.write('Authorization: Bearer ' + token + '\n')
        result = subprocess.run([
            'curl', '--disable', '--noproxy', '*', '--silent', '--show-error', '--fail-with-body',
            '--max-time', '15', '--header', '@' + str(path), '--header', 'Content-Type: application/json',
            '--data-binary', '@-', '--write-out', '\nHTTP_STATUS:%{http_code}\n',
            config['api_origin'] + f'/tenants/{args.tenant}/{args.environment}/messages',
        ], input=json.dumps({'message': message}, ensure_ascii=False).encode('utf-8'), check=False)
        return result.returncode


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception:
        print('ERROR: Send failed; check local API, configured scope and private PKCE token.', file=sys.stderr)
        sys.exit(1)
