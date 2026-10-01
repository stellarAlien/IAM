"""Guarded Okta lifecycle automation restricted to privately registered lab objects."""

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import sys
import time
import urllib.parse

import requests

from .config import load_config


ROOT = Path('.runtime')
SCOPES = ('acme/dev', 'acme/prod', 'globex/dev', 'globex/prod')
GROUPS = ('iam-lab-users', 'iam-lab-jit-candidates') + tuple('iam-lab-' + scope.replace('/', '-') + '-submitters' for scope in SCOPES)
ACTORS = ('alice', 'bob', 'eve')


class LabError(Exception):
    pass


def save(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    temporary = path.with_suffix('.tmp')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(value, stream, indent=2)
    temporary.replace(path)


def registry(config):
    path = ROOT / 'registry.json'
    if path.exists():
        state = json.loads(path.read_text())
        if state.get('org_url') != config['org_url']:
            raise LabError('Registry belongs to another Okta org; do not reuse it.')
        return state
    return {'org_url': config['org_url'], 'groups': {}, 'users': {}}


class Okta:
    def __init__(self, config):
        self.org = config['org_url']
        token_file = os.environ.get('OKTA_API_TOKEN_FILE', str(ROOT / 'okta_api_token'))
        self.token = Path(token_file).read_text().strip()
        if not self.token:
            raise LabError('Management token is empty.')
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.headers.update({'Authorization': 'SSWS ' + self.token, 'Accept': 'application/json'})

    def call(self, method, path, payload=None, params=None):
        if not path.startswith('/api/v1/') or '?' in path or '..' in path:
            raise LabError('Invalid management API path.')
        response = self.session.request(method, self.org + path, json=payload, params=params,
                                        timeout=15, allow_redirects=False)
        if response.status_code == 429:
            raise LabError('Okta rate limit reached; wait before retrying. No mutation was automatically retried.')
        if not 200 <= response.status_code < 300:
            raise LabError(f'Okta management operation failed (HTTP {response.status_code}); inspect System Log privately.')
        return response.json() if response.content else None


def registered_user(api, state, actor):
    if actor not in ACTORS or actor not in state['users']:
        raise LabError('Actor is not a registered suite-created user.')
    entry = state['users'][actor]
    user = api.call('GET', '/api/v1/users/' + entry['id'])
    if user.get('id') != entry['id'] or user.get('profile', {}).get('login') != entry['login']:
        raise LabError('User registry mismatch; operation blocked.')
    return entry


def local_policy():
    path = ROOT / 'access.json'
    return json.loads(path.read_text()) if path.exists() else {'blocked_subjects': [], 'grants': {}}


def block(uid):
    policy = local_policy()
    policy['blocked_subjects'] = sorted(set(policy['blocked_subjects']) | {uid})
    policy['grants'].pop(uid, None)
    save(ROOT / 'access.json', policy)


def confirm(args, phrase='lab-only'):
    if args.confirm != phrase:
        raise LabError(f'Mutation requires --confirm {phrase}. Synthetic lab org only.')


def groups(api, state):
    for name in GROUPS:
        if name in state['groups']:
            group = api.call('GET', '/api/v1/groups/' + state['groups'][name])
            if group.get('profile', {}).get('name') != name or group.get('type') != 'OKTA_GROUP':
                raise LabError('Registered group changed; operation blocked.')
            continue
        matches = api.call('GET', '/api/v1/groups', params={'q': name, 'limit': 200})
        if any(group.get('profile', {}).get('name') == name for group in matches):
            raise LabError('Unregistered same-name group exists; do not adopt external objects automatically.')
        group = api.call('POST', '/api/v1/groups', {'profile': {'name': name, 'description': 'Synthetic IAM suite; no production assignments'}})
        state['groups'][name] = group['id']
        save(ROOT / 'registry.json', state)
    print('Suite groups provisioned; no users assigned or external groups modified.')


def group_id(api, state, name):
    identifier = state['groups'].get(name)
    if not identifier:
        raise LabError('Run groups provisioning first.')
    group = api.call('GET', '/api/v1/groups/' + identifier)
    if group.get('type') != 'OKTA_GROUP' or group.get('profile', {}).get('name') != name:
        raise LabError('Group registry mismatch.')
    return identifier


def join(api, state, args):
    if args.actor not in ACTORS or not re.fullmatch(r'iam-lab-[A-Za-z0-9._+\-]+@[^\s@]+\.[^\s@]+', args.login):
        raise LabError('Choose alice/bob/eve and a synthetic iam-lab-* login at an email domain you control.')
    if args.actor in state['users']:
        user = registered_user(api, state, args.actor)
        identifier = group_id(api, state, 'iam-lab-users')
        api.call('PUT', f'/api/v1/groups/{identifier}/users/{user["id"]}')
        print('Existing actor preserved; lab-users membership ensured. No profile or credential reset.')
        return
    matches = api.call('GET', '/api/v1/users', params={'filter': 'profile.login eq ' + json.dumps(args.login), 'limit': 200})
    if matches:
        raise LabError('Login exists outside registry; will not adopt or modify it.')
    user = api.call('POST', '/api/v1/users', {'profile': {'firstName': 'IAM Lab', 'lastName': args.actor.title(),
                                                        'email': args.login, 'login': args.login}}, params={'activate': 'false'})
    state['users'][args.actor] = {'id': user['id'], 'login': args.login}
    save(ROOT / 'registry.json', state)
    identifier = group_id(api, state, 'iam-lab-users')
    api.call('PUT', f'/api/v1/groups/{identifier}/users/{user["id"]}')
    print('Synthetic user staged and assigned to lab-users. Activate/enroll manually in Okta; no password printed.')


def move(api, state, args):
    if args.scope not in SCOPES:
        raise LabError('Unknown scope.')
    user = registered_user(api, state, args.actor)
    # Block existing JWTs before altering signed group membership.
    block(user['id'])
    for name in GROUPS[1:]:
        identifier = group_id(api, state, name)
        api.call('DELETE', f'/api/v1/groups/{identifier}/users/{user["id"]}')
    name = 'iam-lab-' + args.scope.replace('/', '-') + '-submitters'
    api.call('PUT', f'/api/v1/groups/{group_id(api, state, name)}/users/{user["id"]}')
    print('Old lab memberships removed before new scoped access. Actor remains locally blocked until reviewed release.')


def review(api, state):
    report = {'generated_at': datetime.now(timezone.utc).isoformat(), 'actors': {}}
    for actor in state['users']:
        user = registered_user(api, state, actor)
        data = api.call('GET', '/api/v1/users/' + user['id'])
        memberships = api.call('GET', '/api/v1/users/' + user['id'] + '/groups')
        report['actors'][actor] = {'status': data['status'], 'groups': [group['profile']['name'] for group in memberships],
                                    'locally_blocked': user['id'] in local_policy()['blocked_subjects']}
    save(ROOT / 'review.json', report)
    print(f'Private access review saved for {len(report["actors"])} actors. Review before sharing; not an access-certification product.')


def audit(api, state):
    since = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    users = [entry['id'] for entry in state['users'].values()]
    events = []
    for uid in users:
        events.extend(api.call('GET', '/api/v1/logs', params={'since': since, 'limit': 100,
                      'filter': f'actor.id eq "{uid}" or target.id eq "{uid}"'}))
    save(ROOT / 'system-log.json', events)
    print(f'Private System Log first-page snapshots saved ({len(events)} records, last hour). Not a complete or immutable audit export.')


def doctor(config):
    session = requests.Session()
    session.trust_env = False
    response = session.get(config['issuer'] + '/.well-known/openid-configuration', timeout=15, allow_redirects=False)
    if response.status_code != 200:
        raise LabError('Issuer discovery failed.')
    discovery = response.json()
    if discovery.get('issuer') != config['issuer'] or 'S256' not in discovery.get('code_challenge_methods_supported', []):
        raise LabError('Issuer/PKCE discovery mismatch.')
    for name in ('authorization_endpoint', 'token_endpoint', 'jwks_uri'):
        if urllib.parse.urlsplit(discovery.get(name, '')).netloc != urllib.parse.urlsplit(config['org_url']).netloc:
            raise LabError('Discovery endpoint origin mismatch.')
    print('Issuer discovery and PKCE supported. Client assignment, scopes, MFA and policy require live sign-in verification.')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('doctor', 'groups', 'join', 'move', 'leave', 'review', 'audit', 'contain', 'jit', 'release'))
    parser.add_argument('--actor', choices=ACTORS)
    parser.add_argument('--login', default='')
    parser.add_argument('--scope', default='')
    parser.add_argument('--minutes', type=int, default=5)
    parser.add_argument('--confirm', default='')
    args = parser.parse_args()
    config = load_config()
    if args.action == 'doctor':
        doctor(config)
        return
    state = registry(config)
    if args.action == 'contain':
        if args.actor not in state['users']:
            raise LabError('Actor is not registered.')
        uid = state['users'][args.actor]['id']
        if not re.fullmatch(r'00u[A-Za-z0-9]+', uid):
            raise LabError('Invalid registered user ID.')
        block(uid)
        print('Local API access blocked even for an already-issued JWT; Okta authentication unchanged.')
        return
    api = Okta(config)
    if args.action == 'groups':
        confirm(args)
        groups(api, state)
    elif args.action == 'join':
        confirm(args)
        join(api, state, args)
    elif args.action == 'move':
        confirm(args)
        move(api, state, args)
    elif args.action in ('contain', 'leave'):
        if args.action == 'leave':
            confirm(args, 'deactivate-lab-user')
        user = registered_user(api, state, args.actor)
        block(user['id'])
        if args.action == 'leave':
            api.call('DELETE', f'/api/v1/users/{user["id"]}/sessions', params={'oauthTokens': 'true'})
            status = api.call('GET', '/api/v1/users/' + user['id'])['status']
            if status != 'DEPROVISIONED':
                api.call('POST', f'/api/v1/users/{user["id"]}/lifecycle/deactivate', params={'sendEmail': 'false'})
            print('Local access blocked; Okta session/token revocation and deactivation requested. Verify final status privately.')
        else:
            print('Local API access blocked even for an already-issued JWT; Okta authentication unchanged.')
    elif args.action == 'release':
        confirm(args)
        user = registered_user(api, state, args.actor)
        policy = local_policy()
        if api.call('GET', '/api/v1/users/' + user['id'])['status'] != 'ACTIVE':
            raise LabError('Release requires an ACTIVE user.')
        # An issued token with stale group claims must not regain old access.
        policy.setdefault('not_before', {})[user['id']] = int(time.time()) + 1
        policy['blocked_subjects'] = [uid for uid in policy['blocked_subjects'] if uid != user['id']]
        save(ROOT / 'access.json', policy)
        print('Local block released; tokens issued before this release remain denied. Perform fresh PKCE sign-in.')
    elif args.action == 'jit':
        confirm(args)
        if args.scope not in SCOPES or not 1 <= args.minutes <= 15:
            raise LabError('JIT duration must be 1..15 minutes and scope must be valid.')
        user = registered_user(api, state, args.actor)
        identifier = group_id(api, state, 'iam-lab-jit-candidates')
        api.call('PUT', f'/api/v1/groups/{identifier}/users/{user["id"]}')
        policy = local_policy()
        policy['grants'].setdefault(user['id'], {})[args.scope] = time.time() + args.minutes * 60
        save(ROOT / 'access.json', policy)
        print('Expiring local JIT grant recorded; requires fresh candidate-group JWT and no local block. Not Okta PAM.')
    elif args.action == 'review':
        review(api, state)
    else:
        audit(api, state)


if __name__ == '__main__':
    lock = ROOT / 'operation.lock'
    acquired = False
    try:
        ROOT.mkdir(mode=0o700, exist_ok=True)
        os.chmod(ROOT, 0o700)
        lock.mkdir()
        acquired = True
        main()
    except LabError as error:
        print(f'ERROR: {error}', file=sys.stderr)
        sys.exit(1)
    except Exception:
        print('ERROR: Okta suite operation failed; inspect private config/token files and tenant state.', file=sys.stderr)
        sys.exit(1)
    finally:
        if acquired:
            lock.rmdir()
