# Container security layer: compromised process, bounded blast radius

This exercise asks: **If an API process is compromised, what remains denied by container configuration and Conjur RBAC?** It is a safe control demonstration, not a container escape exploit, penetration test or compliance assessment. Only run against this authorized synthetic lab.

## Preparation

```bash
make up
make init
make tenants-init
make container-security
```

The exercise checks the four tenant APIs independently. It first reads Docker's effective configuration in memory and prints only pass/fail summaries, not full inspect data. It then executes a harmless Python probe as the API's normal user. There is no privileged helper, Docker socket mount, host namespace access, exploit or resource exhaustion.

## What is checked

| Layer | Check | Intended security effect |
| --- | --- | --- |
| Identity | Effective UID 10001 | Avoid root inside workloads |
| Filesystem | Configured read-only root; attempted `/app` write denied | Block persistent modifications to image filesystem |
| Temporary storage | Disposable `/tmp` write succeeds; tmpfs configured | Give a bounded writable location rather than making the image writable |
| Linux capabilities | `cap_drop: ALL`, no added capabilities, `CapEff=0` | Remove capability-based privileges |
| Privilege escalation | `NoNewPrivs=1` | Block acquiring additional privilege via exec paths |
| System calls | `/proc/self/status` reports seccomp filtering (`Seccomp=2`) | Require runtime filtering to be active; does not prove a particular syscall set |
| Host access | No Docker socket or admin runtime directory | Remove obvious host-control/admin-key paths |
| Secret mounts | Only own host API key and public CA cert | Prevent mounting other tenants' credentials |
| Networks | Exactly one tenant/environment network; no published backend port | Remove direct cross-scope peer-network membership |
| Resources | 128 MiB memory, 0.5 CPU, 64 PID limits | Bound container resource allocation; no denial-of-service probe is run |
| Namespaces | No host PID/network modes; nonprivileged | Retain namespace separation |

An unexpected success/failure returns nonzero. Some runtimes may implement CPU limits differently or report no seccomp filtering; treat a failed check as a real limitation and investigate, rather than removing it to declare success. The filesystem probe may return read-only or permission denied; Docker's effective read-only setting is checked separately so ordinary ownership does not masquerade as read-only enforcement.

Limits are backend-specific. Nginx must bind its TLS port/read its private key/drop workers' IDs, so it retains documented minimal capabilities and is not assessed as a capability-free application. Postgres/Conjur have different bootstrap requirements. Do not pretend the same security context applies to every service.

## Manual attacker-perspective checks

From `conjur-sandbox-lab/`, use a shell only in an API container—not the manager or root CLI:

```bash
docker compose exec acme-dev sh
id
grep -E 'CapEff|NoNewPrivs|Seccomp' /proc/self/status
test ! -e /var/run/docker.sock && echo 'No Docker socket'
test ! -d /runtime && echo 'No admin runtime mount'
test ! -e /run/secrets/admin_api_key && echo 'No admin key'
python message.py check
exit
```

Do not `cat` secret files or dump environment/process state into recordings. `message.py check` uses the mounted API identity to verify own ingress-token/signing-key access and denied reads for every other tenant/environment. This is the critical surviving **secret authorization boundary** when an API process is compromised. A compromised process can still read its own keys, bypass its local request checks, and act with its own identity; hardening does not revoke the legitimate privileges of that process.

The backend network permits contacting the shared Conjur TLS proxy and tenant ingress gateway. A compromised API can make requests to those trusted shared components, but another scope's message authorization must still reject its token. Shared gateway compromise or Docker host/kernel compromise is a stronger threat than this exercise handles.

## Tie this to the CISO/ISSO demonstration

1. Run baseline legitimate/attacker actions from [security-exercise.md](security-exercise.md).
2. Run the cross-tenant and dev-to-prod message probes from [zero-trust-multitenancy.md](zero-trust-multitenancy.md).
3. Run `make container-security` and compare the controls to the effective running containers.
4. Show that process compromise and stolen credentials are different assumptions: container hardening constrains host-level actions; Conjur RBAC constrains secret access; per-request bearer checking constrains API use.
5. Discuss residual risk: own-scope exposure, replayable tokens, mutable/unscanned images, plaintext internal hops, shared kernel, shared admin, unauthenticated base payment demo endpoints, and lack of protected external audit collection.

Do not claim "container escape impossible", "zero trust complete", "all syscall exploits blocked", or "production certified" from these probes. They check defined controls and negative paths only. Container image scanning/signing, SBOMs, patching, custom seccomp/AppArmor/SELinux policies, runtime detection, mTLS and orchestrator policy are production workstreams, not implemented claims.

## Verification record

Unit tests verify the inspector rejects missing hardening settings and shared backend networks. Docker runtime probes remain **unverified** in the authoring environment. Run the commands on the authorized local stack and inspect the fresh result before presenting it as evidence.
