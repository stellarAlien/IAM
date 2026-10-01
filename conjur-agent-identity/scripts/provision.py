"""Additive tool-only Conjur identities. Run through the trusted sandbox manager."""

import json
from pathlib import Path
import secrets
import sys

sys.path.insert(0, '/tools')
from manage import AdminClient, APIError, OperationError, private_write


def main():
    client = AdminClient()
    data = Path('/agent-policy/conjur-tools.yml').read_bytes()
    result = json.loads(client.request('POST', f'/policies/{client.account}/policy/root', data, 'application/x-yaml'))
    directory = Path('/agent-runtime/tool-keys')
    directory.mkdir(mode=0o700, exist_ok=True)
    for tool in ('payment-db', 'stripe-reconcile'):
        role = result.get('created_roles', {}).get(f'{client.account_name}:host:agent-lab/{tool}')
        destination = directory / f'{tool}.key'
        if role and role.get('api_key'):
            private_write(destination, role['api_key'])
        elif not destination.exists() or not destination.stat().st_size:
            raise OperationError('Existing tool host key is missing; restore rather than rotate implicitly.')
    for identifier in ('agent-lab/acme/dev/payment-db/credential', 'agent-lab/acme/dev/stripe-reconcile/credential', 'agent-lab/acme/prod/admin/credential'):
        try:
            client.read(identifier)
        except APIError as error:
            if error.status != 404:
                raise
            client.write(identifier, secrets.token_urlsafe(48).encode())
    print('Agent tool identities provisioned additively; existing keys/values preserved; no production-admin grant.')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('ERROR: Agent tool provisioning failed; inspect private state and restore existing keys if missing.', file=sys.stderr)
        sys.exit(1)
