"""Provision and verify tenant/environment identities; never print credentials."""

import json
from pathlib import Path
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request

from manage import AdminClient, APIError, NoRedirect, OperationError, ROOT, private_write


def scopes():
    config = json.loads(Path('/config/tenants.json').read_text())
    return [(tenant, environment) for tenant in config['tenants'] for environment in config['environments']]


def prefix(tenant, environment):
    return f'tenants/{tenant}/{environment}'


def provision(client):
    result = client.policy('root', '05-tenants.yml')
    roles = result.get('created_roles', {})
    for tenant, environment in scopes():
        for kind in ('api', 'sender'):
            path = ROOT / f'{tenant}_{environment}_{kind}_key'
            role = roles.get(f'{client.account_name}:host:{prefix(tenant, environment)}/{kind}')
            if role and role.get('api_key'):
                private_write(path, role['api_key'], 0o444 if kind == 'api' else 0o600)
            elif not path.exists() or not path.stat().st_size:
                raise OperationError(f'Missing existing {tenant}/{environment}/{kind} key; restore the private backup.')
        for name in ('ingress-token', 'signing-key'):
            identifier = f'{prefix(tenant, environment)}/secrets/{name}'
            try:
                client.read(identifier)
            except APIError as error:
                if error.status != 404:
                    raise
                client.write(identifier, secrets.token_urlsafe(48).encode())
    print('Tenant identities provisioned; existing secrets preserved. No shared tenant credentials.')


def rotate(client, tenant, environment):
    if (tenant, environment) not in scopes():
        raise OperationError('Unknown tenant/environment.')
    for name in ('ingress-token', 'signing-key'):
        client.write(f'{prefix(tenant, environment)}/secrets/{name}', secrets.token_urlsafe(48).encode())
    print(f'Rotated {tenant}/{environment} caller token and signing key; other scopes unchanged.')


def post(tenant, environment, token=None):
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token.decode()
    request = urllib.request.Request(
        f'http://{tenant}-{environment}:8080/messages',
        data=json.dumps({'message': 'Synthetic tenant-isolation acceptance test'}).encode(),
        headers=headers, method='POST',
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=15) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, {}


def verify(client):
    tokens = {scope: client.read(f'{prefix(*scope)}/secrets/ingress-token') for scope in scopes()}
    for target in scopes():
        if post(*target)[0] != 401:
            raise OperationError('Missing credentials did not fail closed.')
        for source, token in tokens.items():
            status, body = post(*target, token)
            expected = 202 if source == target else 401
            if status != expected:
                raise OperationError(f'Caller boundary failed: {source} -> {target}, HTTP {status}.')
            if source == target and (body.get('tenant'), body.get('environment')) != target:
                raise OperationError('Response tenant/environment mismatch.')
    old_tokens = dict(tokens)
    rotate(client, *scopes()[0])
    for target in scopes():
        expected = 401 if target == scopes()[0] else 202
        if post(*target, old_tokens[target])[0] != expected:
            raise OperationError('Scope-specific rotation isolation failed.')
    replacement = client.read(f'{prefix(*scopes()[0])}/secrets/ingress-token')
    if post(*scopes()[0], replacement)[0] != 202:
        raise OperationError('Fresh caller token did not restore access.')
    print('All 16 caller scope pairs checked; missing credentials rejected; isolated rotation passed.')


def verify_senders():
    for own_scope in scopes():
        tenant, environment = own_scope
        client = AdminClient(login=f'host/{prefix(*own_scope)}/sender',
                             key_file=ROOT / f'{tenant}_{environment}_sender_key')
        client.read(f'{prefix(*own_scope)}/secrets/ingress-token')
        for other_scope in scopes():
            names = ('signing-key',) if other_scope == own_scope else ('ingress-token', 'signing-key')
            for name in names:
                try:
                    client.read(f'{prefix(*other_scope)}/secrets/{name}')
                except APIError as error:
                    if error.status not in (403, 404):
                        raise
                else:
                    raise OperationError('Sender identity can retrieve a forbidden secret.')
    print('All sender identities can retrieve only their own caller token, not signing keys or other scopes.')


def main():
    args = sys.argv[1:]
    client = AdminClient()
    if args == ['init']:
        provision(client)
    elif args == ['test']:
        verify_senders()
        verify(client)
    elif len(args) == 3 and args[0] == 'rotate':
        rotate(client, args[1], args[2])
    else:
        raise OperationError('Usage: tenants.py init|test|rotate TENANT ENVIRONMENT')


if __name__ == '__main__':
    try:
        main()
    except OperationError as error:
        print(f'ERROR: {error}', file=sys.stderr)
        sys.exit(1)
    except Exception:
        print('ERROR: Tenant operation failed; check service health and private runtime state.', file=sys.stderr)
        sys.exit(1)
