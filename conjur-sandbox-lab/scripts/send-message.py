"""Send via curl with a scoped host credential; no admin credential is read."""

import argparse
import base64
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--tenant', choices=('acme', 'globex'), default='acme')
    parser.add_argument('--environment', choices=('dev', 'prod'), default='dev')
    parser.add_argument('--target-tenant', choices=('acme', 'globex'))
    parser.add_argument('--target-environment', choices=('dev', 'prod'))
    args = parser.parse_args()
    message = sys.stdin.read(4097).rstrip('\n')
    if not message or len(message.encode()) > 2048:
        raise ValueError('Message must be 1..2048 UTF-8 bytes; pass it on stdin.')
    root = Path(__file__).resolve().parents[1]
    config = {}
    if (root / '.env').exists():
        for line in (root / '.env').read_text().splitlines():
            if '=' in line and not line.lstrip().startswith('#'):
                name, value = line.split('=', 1)
                config[name.strip()] = value.strip().strip('"\'')
    account = os.environ.get('CONJUR_ACCOUNT', config.get('CONJUR_ACCOUNT', 'sandbox'))
    port = os.environ.get('CONJUR_HTTPS_PORT', config.get('CONJUR_HTTPS_PORT', '8443'))
    ca = root / '.runtime/tls.crt'
    login = f'host/tenants/{args.tenant}/{args.environment}/sender'
    key_file = root / f'.runtime/{args.tenant}_{args.environment}_sender_key'
    key = key_file.read_bytes().strip()
    if not key:
        raise ValueError('Sender identity key is empty; provision or restore it.')
    base = f'https://localhost:{int(port)}'
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), NoRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(ca))),
    )
    quote = lambda value: urllib.parse.quote(value, safe='')
    request = urllib.request.Request(f'{base}/authn/{quote(account)}/{quote(login)}/authenticate', data=key, method='POST')
    with opener.open(request, timeout=10) as response:
        token = base64.b64encode(response.read()).decode()
    identifier = f'tenants/{args.tenant}/{args.environment}/secrets/ingress-token'
    request = urllib.request.Request(f'{base}/secrets/{quote(account)}/variable/{quote(identifier)}',
                                     headers={'Authorization': f'Token token="{token}"'})
    with opener.open(request, timeout=10) as response:
        caller_token = response.read().decode()
    target_tenant = args.target_tenant or args.tenant
    target_environment = args.target_environment or args.environment
    with tempfile.TemporaryDirectory(prefix='conjur-message-') as directory:
        header = Path(directory) / 'authorization'
        descriptor = os.open(header, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'w') as stream:
            stream.write(f'Authorization: Bearer {caller_token}\n')
        result = subprocess.run([
            'curl', '--disable', '--noproxy', '*', '--fail-with-body', '--silent', '--show-error',
            '--max-time', '15', '--cacert', str(ca), '--header', f'@{header}',
            '--header', 'Content-Type: application/json', '--data-binary', '@-',
            '--write-out', '\nHTTP_STATUS:%{http_code}\n',
            f'https://localhost:8444/tenants/{target_tenant}/{target_environment}/messages',
        ], input=json.dumps({'message': message}).encode(), check=False)
        return result.returncode


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception:
        print('ERROR: Message send failed; check scoped identity, TLS trust, curl, and service health.', file=sys.stderr)
        sys.exit(1)
