"""Private, ephemeral administrative operations; never print credentials."""

import base64
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid


ROOT = Path('/runtime')
SECRET_IDS = ('lab/secrets/payment-api-key', 'lab/secrets/fraud-model-key')
VERSION_ID = 'lab/secrets/credential-version'


class OperationError(Exception):
    pass


class APIError(OperationError):
    def __init__(self, status):
        self.status = status
        super().__init__(f'Conjur request failed (HTTP {status}).')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def private_write(path, value, mode=0o600):
    temporary = path.with_suffix('.tmp')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(descriptor, 'w') as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(value)
    temporary.replace(path)


def bootstrap_key():
    destination = ROOT / 'admin_api_key'
    if destination.exists() and destination.stat().st_size:
        return
    source = ROOT / 'bootstrap.out'
    if not source.exists():
        raise OperationError('Admin bootstrap output is missing. Run make init or restore the runtime backup.')
    text = source.read_text()
    match = re.search(r'^API key for admin:\s*(\S+)\s*$', text, re.MULTILINE)
    if not match:
        raise OperationError('Unexpected conjurctl account output; retained privately for recovery.')
    private_write(destination, match.group(1))
    source.unlink()


class AdminClient:
    def __init__(self, login='admin', key_file=None):
        self.base = os.environ['CONJUR_APPLIANCE_URL'].rstrip('/')
        if urllib.parse.urlsplit(self.base).scheme != 'https':
            raise OperationError('Conjur administrative traffic requires HTTPS.')
        self.account_name = os.environ['CONJUR_ACCOUNT']
        self.account = urllib.parse.quote(self.account_name, safe='')
        self.login = urllib.parse.quote(login, safe='')
        self.key = Path(key_file or ROOT / 'admin_api_key').read_bytes().strip()
        if not self.key:
            raise OperationError('Identity API key is missing; provision or restore it.')
        context = ssl.create_default_context(cafile=os.environ['CONJUR_CERT_FILE'])
        self.transport = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect(),
            urllib.request.HTTPSHandler(context=context),
        )
        self.token = None

    def request(self, method, path, data=None, content_type='application/octet-stream', authenticated=True):
        if authenticated and self.token is None:
            self.authenticate()
        headers = {'Content-Type': content_type}
        if authenticated:
            headers['Authorization'] = f'Token token="{self.token}"'
        request = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with self.transport.open(request, timeout=15) as response:
                return response.read()
        except urllib.error.HTTPError as error:
            raise APIError(error.code) from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise OperationError('Unable to reach Conjur securely; check health and CA trust.') from None

    def authenticate(self):
        raw = self.request('POST', f'/authn/{self.account}/{self.login}/authenticate', self.key, authenticated=False)
        self.token = base64.b64encode(raw).decode('ascii')

    def read(self, identifier):
        identifier = urllib.parse.quote(identifier, safe='')
        return self.request('GET', f'/secrets/{self.account}/variable/{identifier}')

    def write(self, identifier, value):
        identifier = urllib.parse.quote(identifier, safe='')
        self.request('POST', f'/secrets/{self.account}/variable/{identifier}', value)

    def policy(self, branch, filename):
        branch = urllib.parse.quote(branch, safe='')
        raw = self.request('POST', f'/policies/{self.account}/policy/{branch}',
                           (Path('/policy') / filename).read_bytes(), 'application/x-yaml')
        return json.loads(raw)


def load_policies(client):
    client.policy('root', '01-root.yml')
    result = client.policy('lab', '02-app-identity.yml')
    roles = result.get('created_roles', {})
    for workload in ('checkout', 'fraud'):
        path = ROOT / f'{workload}_api_key'
        role = roles.get(f'{client.account_name}:host:lab/{workload}')
        if role and role.get('api_key'):
            private_write(path, role['api_key'], 0o444)
        elif not path.exists() or not path.stat().st_size:
            raise OperationError(f'{workload} identity already exists but its local key is missing; restore the runtime backup.')
    client.policy('lab', '03-secrets.yml')
    print('Policies loaded; checkout and fraud have separate read-only permissions.')


def rotate(client):
    for identifier in SECRET_IDS:
        client.write(identifier, secrets.token_urlsafe(48).encode())
    version = str(uuid.uuid4())
    client.write(VERSION_ID, version.encode())
    print(f'Credential rotation completed; non-secret version: {version}')
    return version


def seed(client):
    try:
        client.read(VERSION_ID)
    except APIError as error:
        if error.status != 404:
            raise
        rotate(client)
        return
    for identifier in SECRET_IDS:
        client.read(identifier)
    print('Existing secret values preserved.')


def evaluate(workload):
    data = json.dumps({'order_id': 'sandbox-order-001', 'amount': 129.95, 'currency': 'USD'}).encode()
    request = urllib.request.Request(f'http://{workload}:8080/evaluate', data=data,
                                     headers={'Content-Type': 'application/json'}, method='POST')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=15) as response:
        if response.status != 200:
            raise OperationError(f'{workload} evaluation failed.')
        return json.loads(response.read())


def integration_test(client):
    before = [client.read(identifier) for identifier in SECRET_IDS]
    old_version = client.read(VERSION_ID).decode()
    first = {workload: evaluate(workload) for workload in ('checkout', 'fraud')}
    if any(result.get('credential_version') != old_version for result in first.values()):
        raise OperationError('Workloads did not report the current credential version.')
    new_version = rotate(client)
    after = [client.read(identifier) for identifier in SECRET_IDS]
    if any(old == new for old, new in zip(before, after)):
        raise OperationError('A secret did not change during rotation.')
    second = {workload: evaluate(workload) for workload in ('checkout', 'fraud')}
    for workload, result in second.items():
        if result.get('credential_version') != new_version:
            raise OperationError(f'{workload} did not observe live rotation.')
    payload = json.dumps([first, second])
    if any(value.decode() in payload for value in before + after):
        raise OperationError('A workload exposed secret material.')
    print('Both REST workloads observed new secrets without restarts; no secret values were exposed.')


def main():
    action = sys.argv[1] if len(sys.argv) == 2 else ''
    if action not in ('init', 'policies', 'rotate', 'test'):
        raise OperationError('Usage: manage.py {init|policies|rotate|test}')
    if action == 'init':
        bootstrap_key()
    client = AdminClient()
    client.authenticate()
    if action == 'init':
        load_policies(client)
        seed(client)
    elif action == 'policies':
        load_policies(client)
    elif action == 'rotate':
        rotate(client)
    else:
        integration_test(client)


if __name__ == '__main__':
    try:
        main()
    except OperationError as error:
        print(f'ERROR: {error}', file=sys.stderr)
        sys.exit(1)
    except Exception:
        print('ERROR: Management operation failed; check service health and private runtime state.', file=sys.stderr)
        sys.exit(1)
