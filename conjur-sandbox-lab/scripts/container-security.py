"""Inspect the configured boundary and probe harmless operations inside APIs."""

import json
import subprocess
import sys


SERVICES = ('acme-dev', 'acme-prod', 'globex-dev', 'globex-prod')
PROBE = '''
import errno, json, os
from pathlib import Path
status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
assert os.getuid() == 10001, 'unexpected UID'
assert int(status['CapEff'].strip(), 16) == 0, 'effective capabilities present'
assert status['NoNewPrivs'].strip() == '1', 'privilege escalation not blocked'
assert status['Seccomp'].strip() == '2', 'seccomp filtering absent'
assert not Path('/var/run/docker.sock').exists(), 'Docker socket exposed'
assert not Path('/runtime').exists(), 'admin runtime exposed'
assert {path.name for path in Path('/run/secrets').iterdir()} == {'host_api_key', 'tls_cert'}, 'unexpected secret mount'
try:
    descriptor = os.open('/app/.boundary-probe', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
except OSError as error:
    assert error.errno in (errno.EROFS, errno.EACCES, errno.EPERM), 'unexpected write failure'
else:
    os.close(descriptor)
    os.unlink('/app/.boundary-probe')
    raise AssertionError('image directory was writable')
path = Path('/tmp/.boundary-probe')
path.write_text('synthetic probe')
path.unlink()
print('PASS: UID, caps, no-new-privileges, seccomp, secret mounts, read-only image, writable tmpfs')
'''


def configuration_checks(service, inspection):
    host = inspection['HostConfig']
    checks = {
        'non-root identity': inspection['Config']['User'] == '10001:10001',
        'read-only filesystem': host['ReadonlyRootfs'],
        'not privileged': not host['Privileged'],
        'all capabilities dropped': 'ALL' in (host.get('CapDrop') or []),
        'no added capabilities': not host.get('CapAdd'),
        'no-new-privileges': any(value.startswith('no-new-privileges') for value in host.get('SecurityOpt', [])),
        'PID bound': host.get('PidsLimit') == 64,
        'memory bound': host.get('Memory') == 128 * 1024 * 1024,
        'CPU bound': host.get('NanoCpus') == 500000000,
        'no published backend ports': not host.get('PortBindings'),
        'isolated namespace network': set(inspection['NetworkSettings']['Networks']) == {f"{inspection['Config']['Labels']['com.docker.compose.project']}_{service}"},
        'no host PID namespace': host.get('PidMode') != 'host',
        'no host network': host.get('NetworkMode') != 'host',
    }
    failed = [name for name, passed in checks.items() if not passed]
    if failed:
        raise ValueError(f'{service} failed: {", ".join(failed)}')


def main():
    for service in SERVICES:
        container = subprocess.check_output(['docker', 'compose', 'ps', '-q', service], text=True).strip()
        if not container:
            raise ValueError(f'{service} is not running; run make tenants-init.')
        inspection = json.loads(subprocess.check_output(['docker', 'inspect', container], text=True))[0]
        configuration_checks(service, inspection)
        print(f'{service}: PASS configured container boundary', flush=True)
        subprocess.run(['docker', 'compose', 'exec', '-T', service, 'python', '-c', PROBE], check=True)
    print('Container boundary probes passed; this is not a kernel escape, image scan, or compliance certification.')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        if isinstance(error, ValueError):
            print(f'ERROR: {error}', file=sys.stderr)
        else:
            print('ERROR: Container security exercise failed; inspect local configuration and probe results.', file=sys.stderr)
        sys.exit(1)
