"""Manual, scoped security exercise; output is secret-free client evidence."""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import sys
import time
import urllib.parse
import uuid

from manage import AdminClient, APIError, OperationError, ROOT, private_write, rotate


ACTORS = ('alice', 'bob', 'eve')
PAYMENT = 'lab/secrets/payment-api-key'
FRAUD = 'lab/secrets/fraud-model-key'
CANARY = 'lab/exercise/canary'
ACTIONS = ('metadata', 'payment', 'fraud', 'canary', 'tamper', 'escalate', 'watch-payment')


def event(actor, action, outcome, status, **fields):
    record = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'event_id': str(uuid.uuid4()), 'source': 'exercise-client-observation',
        'actor': actor, 'action': action, 'outcome': outcome, 'http_status': status,
        **fields,
    }
    print(json.dumps(record, sort_keys=True), flush=True)


def patch_policy(client, filename):
    client.request('PATCH', f'/policies/{client.account}/policy/root',
                   (Path('/policy/exercise') / filename).read_bytes(), 'application/x-yaml')


def setup(client):
    result = client.policy('root', '04-human-exercise.yml')
    for actor in ACTORS:
        key_file = ROOT / f'{actor}_api_key'
        role = result.get('created_roles', {}).get(f'{client.account_name}:user:lab-{actor}')
        if role and role.get('api_key'):
            private_write(key_file, role['api_key'], 0o444)
        elif not key_file.exists() or not key_file.stat().st_size:
            raise OperationError(f'{actor} already exists but its key is missing; restore it rather than resetting the user.')
    try:
        client.read(CANARY)
    except APIError as error:
        if error.status != 404:
            raise
        client.write(CANARY, secrets.token_urlsafe(48).encode())
    patch_policy(client, 'reset.yml')
    event('facilitator', 'setup', 'baseline-restored', 200)


def administer(client, action):
    if action == 'setup':
        setup(client)
    elif action == 'expose':
        if os.environ.get('EXERCISE_CONFIRM') != 'lab-only':
            raise OperationError('Intentional overgrant requires CONFIRM=lab-only; use only synthetic lab secrets.')
        patch_policy(client, 'expose.yml')
        event('facilitator', action, 'payment-read-overgrant-enabled', 200)
    elif action == 'contain':
        patch_policy(client, 'contain.yml')
        event('facilitator', action, 'eve-group-access-revoked', 200)
    elif action == 'reset':
        patch_policy(client, 'reset.yml')
        event('facilitator', action, 'baseline-restored', 200)
    elif action == 'recover':
        # Close the access path before replacing potentially exposed values.
        patch_policy(client, 'contain.yml')
        rotate(client)
        event('facilitator', action, 'contained-and-workload-secrets-rotated', 200)
    else:
        raise OperationError('Unknown facilitator action.')


def attempt(client, actor, action):
    try:
        if action in ('payment', 'fraud', 'canary', 'watch-payment'):
            client.read({'payment': PAYMENT, 'watch-payment': PAYMENT, 'fraud': FRAUD, 'canary': CANARY}[action])
        elif action == 'metadata':
            identifier = urllib.parse.quote(PAYMENT, safe='')
            client.request('GET', f'/resources/{client.account}/variable/{identifier}')
        elif action == 'tamper':
            client.write(PAYMENT, secrets.token_urlsafe(48).encode())
        elif action == 'escalate':
            body = f'- !grant\n  role: !group /lab/checkout-readers\n  member: !user /lab-{actor}\n'.encode()
            client.request('POST', f'/policies/{client.account}/policy/root', body, 'application/x-yaml')
        else:
            raise OperationError('Unknown actor action.')
    except APIError as error:
        if error.status not in (403, 404):
            raise
        event(actor, action, 'denied', error.status)
        return 'deny'
    event(actor, action, 'allowed', 200,
          alert=actor == 'eve' and action != 'canary',
          canary_signal=actor == 'eve' and action == 'canary')
    return 'allow'


def act(client, actor, action, expected='observe'):
    if actor not in ACTORS or action not in ACTIONS or expected not in ('observe', 'allow', 'deny'):
        raise OperationError('Invalid actor, action, or expected outcome.')
    client.authenticate()
    event(actor, 'authenticate', 'authenticated', 200)
    if action == 'watch-payment':
        if expected != 'observe':
            raise OperationError('watch-payment is observational; omit EXPECT.')
        for index in range(20):
            attempt(client, actor, action)
            if index < 19:
                time.sleep(3)
        return
    result = attempt(client, actor, action)
    if expected != 'observe' and result != expected:
        raise OperationError(f'Observed {result}; expected {expected}. Stop and investigate the policy.')


def main():
    args = sys.argv[1:]
    if len(args) == 2 and args[0] == 'admin':
        administer(AdminClient(), args[1])
    elif len(args) in (2, 3) and args[0] == 'actor':
        actor = os.environ['EXERCISE_ACTOR']
        if actor not in ACTORS:
            raise OperationError('Unknown actor.')
        client = AdminClient(login=f'lab-{actor}', key_file='/run/secrets/actor_api_key')
        act(client, actor, args[1], args[2] if len(args) == 3 else 'observe')
    else:
        raise OperationError('Usage: exercise.py admin ACTION | actor ACTION [observe|allow|deny]')


if __name__ == '__main__':
    try:
        main()
    except OperationError as error:
        print(f'ERROR: {error}', file=sys.stderr)
        sys.exit(1)
    except Exception:
        print('ERROR: Exercise failed; check private identity files, TLS trust, and service health.', file=sys.stderr)
        sys.exit(1)
