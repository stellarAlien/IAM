# Development handoff for subsequent runs

Read the repository `AGENTS.md` and this file before making changes. This repository is a local Conjur OSS **educational sandbox**. Never promote its single-instance deployment, synthetic "prod" environments or client evidence to a claim of HA, enterprise zero trust, compliance, or live verification.

`okta-iam-suite/` is a separate human-IAM companion with its own [development handoff](../../okta-iam-suite/docs/development.md). It does not synchronize Okta groups into Conjur or replace existing scope bearer tokens. Root `okta-*` targets use a separate Python virtual environment and tests. Preserve the separation of human federation, tenant API permissions and Conjur workload secret access.

`conjur-agent-identity/` is a separate application-layer signed-delegation/Cedar prototype with its own [handoff](../../conjur-agent-identity/docs/development.md). Its optional Conjur initialization adds only the `agent-lab` branch and captures per-tool keys through the trusted sandbox manager. Agent grants are not Conjur API keys, agent runtime policy is not translated MAML, and no live tool or full-equivalence claim follows from its synthetic demo.

## Architecture and file ownership

| Surface | Source of truth | What changes together |
| --- | --- | --- |
| Base infrastructure | `docker-compose.yml`, `config/nginx.conf`, `.env.example`, `scripts/up.sh` | Secret mount paths, certificate SANs, healthchecks, lifecycle docs |
| Payment-risk apps | `app/app.py`, policies `01`–`03`, `scripts/manage.py` | Host logins, variable IDs, app tests, integration tests |
| Human attacker exercise | `policy/04-human-exercise.yml`, `policy/exercise/`, `scripts/exercise*` | Actor permissions, PATCH statements, manual walkthrough, expected matrix |
| Tenant messages | `config/tenants.json`, `policy/05-tenants.yml`, `app/message.py`, `config/tenant-nginx.conf`, four Compose services | Tenant/env allowlists, keys, networks, gateway routes, sender choices, docs/tests |
| Tenant administration | `scripts/tenants.py`, `scripts/tenants.sh` | Idempotence, permissions, secret generation, scoped rotation, live matrix |
| Curl sender | `scripts/send-message.py` | Scoped sender identity, private header file, fixed local HTTPS paths, stdin JSON |
| HTTPS acceptance | `scripts/test-gateway.py` | Real curl sender path, exact HTTP statuses and scoped safe response validation |
| Container exercise | `scripts/container-security.py` | Docker inspect expectations, safe probes, hardening documentation |
| Kubernetes handoff | `k8s/` | Existing checkout/fraud workloads only; not a Conjur or tenant deployment |

The root Makefile delegates to the lab directory; root Compose includes the same manifest. For direct root Compose invocation after customizing `.env`, use `--env-file conjur-sandbox-lab/.env` so project names and configuration match. The tenant API ingress is fixed at port 8444, while the Conjur TLS port is configurable in `.env`.

The four scopes are Acme/Globex × dev/prod. There is **no dynamic onboarding API**. Add a scope by reviewed repository changes across every listed surface. Policy YAML anchors reuse an environment body with local role references; they must not turn into shared global tenant grants. Do not infer isolation solely from namespace naming.

## Identity and credential conventions

- Conjur account defaults to `sandbox`. Resource IDs in the repository are relative to this account.
- Base hosts: `host/lab/checkout`, `host/lab/fraud`. Human users: root users `lab-alice`, `lab-bob`, `lab-eve`.
- Tenant API host: `host/tenants/<tenant>/<environment>/api`; sender host: `host/tenants/<tenant>/<environment>/sender`.
- Tenant variables: `tenants/<tenant>/<environment>/secrets/ingress-token` and `.../signing-key`.
- API groups read/retrieve their own two variables. Sender groups read/retrieve only their own ingress token. Scoped reviewers/secret-operators have no members by default.
- Private runtime files use `<tenant>_<environment>_api_key` and `<tenant>_<environment>_sender_key`. Mounted API keys are 0444 beneath a host-private 0700 directory so UID 10001 can read its **individual** mount; sender/admin keys stay 0600. Runtime files are not vault storage; Docker admins are trusted.
- `ConjurClient` in `app.py` enforces HTTPS, URL encoding, no redirects, generic upstream errors and bounded retry. `manage.AdminClient` reuses the administrative REST flow with explicit login/key-file parameters for scoped senders. Its name does not confer admin privileges: Conjur decides the rights of the supplied identity.
- A bearer message token is **not** a Conjur API key. Never mount admin credentials into backends or use the sender identity to retrieve signing keys.

## Lifecycle and mutation contract

| Command | Mutates |
| --- | --- |
| `make up` | Generates missing initial runtime keys/certificate; starts base infrastructure |
| `make init` | Creates base account if necessary, additive policy load, initial seeding, workloads |
| `make policies` | Additive base policies; does not remove old grants |
| `make rotate`, `make test-app` | Payment/fraud secret values and public version marker |
| `make exercise-init` | Human user declarations/keys if new, canary seed, explicit baseline reset |
| `make exercise-expose CONFIRM=lab-only` | Intentional payment-read overgrant for Eve |
| `make exercise-contain` | Explicit PATCH revocation of Eve checkout and contractor group access |
| `make exercise-recover` | Containment followed by payment/fraud secret rotation |
| `make exercise-reset` | Removes intentional overgrant and restores Eve canary-only membership |
| `make tenants-init` | New scoped host keys/policy/initial secrets if absent; starts four APIs/gateway |
| `make tenant-rotate TENANT=... ENVIRONMENT=...` | Only the selected scope's ingress token and signing key |
| `make test-tenants` | Live RBAC/caller checks plus Acme dev secret rotation |
| `make container-security` | Only a bounded disposable probe file in `/tmp`; expected denied write to `/app` |
| `make clean CONFIRM=destroy` | Deletes database volume and **all** runtime identities/keys/evidence |

Ordinary base initialization does not load human exposure or tenant policies. Identity credentials are generated by Conjur and captured privately; never reissue existing keys silently when a capture file is missing. Restore a matching backup or perform an explicitly reviewed rotation/reprovision. Preserve account state, encryption data key and Postgres volume as a consistent set.

Administrative shell commands serialize through `.runtime/operation.lock`. Actor and message requests intentionally remain concurrent so containment can be demonstrated. The lock is not distributed and does not stop external Conjur writers. If the lock remains after interruption, confirm no process is running before removing it. Rotating multiple variables is not atomic; partial rotation can be repaired by rerunning, but external provider lifecycle is out of scope.

POST policy load is additive. `!revoke`, `!deny`, or deletion must use reviewed PATCH policy loading; removing a line from YAML does not revoke permission. Human containment is authorization revocation, not disabling authentication, deleting Eve, API-key rotation or universal token invalidation.

## Development checks

No third-party Python app dependencies are required. From repository root:

```bash
make test
git diff --check
docker compose --profile tools --profile workloads --profile exercise --profile tenants config --quiet
```

`make test` runs Python unittest discovery and Bash syntax checks. If ShellCheck is available, run:

```bash
shellcheck -x -P SCRIPTDIR conjur-sandbox-lab/scripts/*.sh
```

Policy files use Conjur YAML tags; a generic YAML parser can verify syntax using compose/node APIs, not ordinary safe-load without tag constructors. Parsing does not validate Conjur semantics. Unit tests use controlled fake secret clients and local HTTP servers; they establish application behavior, not the real server's authorization, TLS, container or database semantics.

Tests should assert valid/invalid inputs, denial versus outage, secret-free output, fixed scope, authorization freshness, known policy mutation ordering and preservation of existing values. Do not weaken tests to accept outages as a denial, remove tenant checks, or replace live acceptance with mocks.

## Live acceptance

Docker with Compose v2.20+ is required. Do not try to emulate a Docker daemon with mocks or bypass runtime security constraints. When working in a managed sandbox without Docker, use the platform's authorized Docker runtime setup; if unavailable, report the limitation and stop short of claiming live success.

```bash
make up
make init
make test-app
make cli ARGS=whoami
make exercise-init
make test-exercise
make tenants-init
make test-tenants
make container-security
printf '%s\n' 'Synthetic acceptance message' | make send-message TENANT=acme ENVIRONMENT=dev
```

Also perform the manual retained-token containment walkthrough and cross-tenant/dev-to-prod curl probes from the linked runbooks. Record actual statuses and inspect relevant server audit events privately. Run `make test-app`/`test-tenants` with awareness that they rotate lab values. Do not call `make clean` to "fix" an existing database without authorization.

## Security invariants and known limits

- Tenant/environment scope is deployment-bound, never selected by request payload/header. Body is exactly one bounded message field.
- TLS ingress and Conjur clients verify certificates. Never use curl `-k`, insecure contexts, secret query strings, trace flags or debug output.
- The shared gateway-to-message-backend and Conjur-gateway-to-server hops are HTTP on isolated networks. There is no backend mTLS or service mesh; shared gateway/host compromise remains a cross-scope threat.
- Scope bearer tokens are long-lived replayable secrets until rotation, not end-user JWTs, device posture or user attribution. APIs retrieve fresh token/signing values on every request and fail closed on Conjur errors.
- Message acceptance is ephemeral validation/internal signing, not durable delivery. No message or HMAC appears in responses/logs.
- Backend containers must remain UID 10001, read-only, capability-free, no-new-privileges, resource/PID bounded, without Docker socket/host namespace/admin runtime mounts. Harmless probes inspect controls; do not add kernel exploits, fork bombs or privileged variants.
- Kubernetes manifests currently cover only base checkout/fraud workloads against an existing Conjur installation. Tenant Kubernetes network/secret/service manifests are not implemented.
- Client observations in `.runtime/evidence/` are not an immutable or authoritative audit stream, protected SIEM or compliance evidence. Never publish unredacted logs/media.

## Current verification record

The authoring environment has no Docker daemon/CLI; attempts to enable Docker runtime previously returned `not_required`. Offline checks are available, but live Conjur bootstrap, tenant policy interpretation, official CLI, TLS routing, network isolation, retained-token behavior and container runtime probes remain unverified. Fetch fresh evidence for subsequent changing state; do not inherit a passing claim from a previous summary.

Runbooks: [base README](../README.md), [human attacker exercise](security-exercise.md), [zero trust and tenancy](zero-trust-multitenancy.md), [container security](container-security.md), [Kubernetes handoff](../k8s/README.md).
