"""Verify the real localhost TLS/curl path without publishing credentials."""

import json
from pathlib import Path
import subprocess
import sys


def check_response(result, expected, scope=None):
    body, separator, status = result.stdout.rpartition('\nHTTP_STATUS:')
    if not separator or status.strip() != str(expected):
        raise ValueError('Gateway did not return the expected HTTP status; check TLS, routing and authorization locally.')
    if result.returncode != (0 if expected == 202 else 22):
        raise ValueError('curl failed before the expected gateway authorization result.')
    payload = json.loads(body)
    if expected == 202:
        if payload.get('status') != 'accepted' or (payload.get('tenant'), payload.get('environment')) != scope:
            raise ValueError('Gateway response did not match the configured scope.')
    elif payload != {'error': 'unauthorized'}:
        raise ValueError('Gateway rejection did not come from API caller authorization.')


def main():
    root = Path(__file__).resolve().parents[1]
    for tenant in ('acme', 'globex'):
        for environment in ('dev', 'prod'):
            command = [sys.executable, str(root / 'scripts/send-message.py'),
                       '--tenant', tenant, '--environment', environment]
            result = subprocess.run(command, input='Synthetic HTTPS gateway acceptance',
                                    text=True, capture_output=True, check=False)
            check_response(result, 202, (tenant, environment))
            print(f'PASS HTTPS/curl accepted {tenant}/{environment}; response scope matched.')
    for target in (('globex', 'dev'), ('acme', 'prod')):
        result = subprocess.run([
            sys.executable, str(root / 'scripts/send-message.py'), '--tenant', 'acme', '--environment', 'dev',
            '--target-tenant', target[0], '--target-environment', target[1],
        ], input='Synthetic cross-scope HTTPS probe', text=True, capture_output=True, check=False)
        check_response(result, 401)
        print(f'PASS HTTPS/curl denied acme/dev credentials at {target[0]}/{target[1]}.')
    result = subprocess.run([
        'curl', '--disable', '--noproxy', '*', '--fail-with-body', '--silent', '--show-error',
        '--max-time', '15', '--cacert', str(root / '.runtime/tls.crt'),
        '--header', 'Content-Type: application/json', '--data-binary', '{"message":"Synthetic no-token probe"}',
        '--write-out', '\nHTTP_STATUS:%{http_code}\n',
        'https://localhost:8444/tenants/acme/dev/messages',
    ], text=True, capture_output=True, check=False)
    check_response(result, 401)
    print('PASS HTTPS/curl missing credentials rejected. No raw response/credential evidence was printed.')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('ERROR: HTTPS/curl acceptance failed; inspect local TLS, routing, scoped credentials and status codes.', file=sys.stderr)
        sys.exit(1)
