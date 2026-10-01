# Conjur OSS: payment-risk secret management lab

Two services handle the same order: **checkout** signs a payment authorization using its payment credential; **fraud** derives a coarse synthetic risk score using its own model credential. Neither service may read the other's key, change a secret, or administer policy. Both retrieve fresh secret values for every request, so credential rotation takes effect without application restarts.

This is a fully implemented, security-conscious **local lab**, not a claim of production certification. A single Postgres/Conjur instance, self-signed TLS, bootstrap host API keys, mutable image tags, and Python's demo HTTP server are not an enterprise production deployment. The use case is synthetic: no bank, payment gateway, or real fraud model is contacted.

## Manual multi-user security exercise

[The compromised contractor walkthrough](docs/security-exercise.md) provides a CISO/ISSO-oriented exercise with Alice (metadata-only reviewer), Bob (payment operator), and Eve (simulated compromised contractor). It demonstrates denied lateral access, an explicitly approved read-only overgrant, retained-token containment, recovery, and private client evidence. Actor containers receive only their own key; ordinary initialization never enables the overgrant.

```bash
make exercise-init             # After make up && make init; restores human baseline
make test-exercise             # Assert baseline multi-user access matrix
make act ACTOR=eve ACTION=payment EXPECT=deny
make exercise-report
```

Read the walkthrough before `exercise-expose` or `exercise-reset`: they intentionally change permissions. Evidence summaries are client observations, not a protected server audit trail or an implemented SIEM.

## Zero trust, multi-tenant messages, and container security

[Tenant and environment API runbook](docs/zero-trust-multitenancy.md) adds Acme/Globex × dev/prod scopes, each with distinct API/sender hosts, caller tokens, signing keys, RBAC and backend networks. Every message POST verifies a fresh scoped caller token; a claimed tenant in an unauthenticated payload/header cannot change API scope.

```bash
make tenants-init              # After make up && make init
printf '%s\n' 'Synthetic message' | make send-message TENANT=acme ENVIRONMENT=dev
make test-tenants              # Live RBAC/caller matrix; rotates Acme dev
make container-security       # Effective hardening + safe in-container probes
```

`send-message` runs curl with verified TLS and a private bearer-header file; credentials are not command-line values. Messages are validated and discarded, not durably queued. The [container security exercise](docs/container-security.md) covers UID, capabilities, read-only filesystem, no-new-privileges, seccomp, mount/network boundaries, and resource limits. Internal HTTP hops, shared gateways/admins and scope-shared replayable tokens remain documented limits; this is a zero-trust **foundation**, not a complete enterprise architecture.

Future development runs must read [the durable development handoff](docs/development.md) and repository `AGENTS.md` before changing the lab. It records identity conventions, file dependencies, lifecycle mutations, security invariants, verification commands and unresolved live checks. Kubernetes handoff remains limited to checkout/fraud; tenant Kubernetes deployment is not supplied.

## Prerequisites and quick start

- Linux/macOS or WSL with Bash, GNU Make, OpenSSL supporting `req -addext`, and Docker with Compose **v2.20+** and a running daemon. Docker Desktop is supported.
- Python **3.10+** for offline unit tests. Containers use Python 3.12, with no third-party Python dependencies.
- Internet access to pull the public images and sufficient Docker resources (start with 2 CPUs / 4 GiB).
- Local ports 8443, 8081, and 8082 available, or change the non-secret `.env` settings.

From this directory, or from the repository root:

```bash
make up
make init
make test-app
```

`make up` copies `.env.example` if needed, dynamically generates the database password and Conjur data key, creates a 30-day self-signed certificate, and waits for the infrastructure healthchecks. `make init` creates the account, privately extracts the admin API key, loads the policies in order, captures generated host API keys, seeds random secret values, and starts both workloads. Repeating either command preserves existing keys and secrets. Initialization authenticates before changing policy; it never silently resets an existing account's admin key.

`make test-app` verifies permitted reads and denied cross-workload reads, submits an order to both HTTP services, **rotates both test credentials**, verifies the stored values changed, and checks both services observe the new non-secret version without a restart. It never prints secret values or API tokens.

## Architecture

```text
localhost:8443 ── TLS gateway ── Conjur:80 ── isolated Postgres:5432
                         ▲                      persistent volume
                         │ HTTPS + trusted CA
                  checkout / fraud
                  distinct host identities
                  localhost:8081 / :8082
```

Only the TLS gateway is connected to both the Conjur backend and workload networks. Postgres has no published port and is reachable only on its internal database network. Conjur has no published cleartext port. TLS terminates at Nginx; the gateway-to-Conjur hop is HTTP on a dedicated Docker network. Container-host administrators can inspect that traffic: production requires authenticated/encrypted transport across every trust boundary.

The optional tenant layer adds four dedicated backend networks, a loopback TLS ingress at port 8444, and scoped message services. The Conjur TLS proxy joins those networks to serve Conjur traffic; the ephemeral trusted manager joins them for verification. Tenant APIs do not join the shared workload network or another scope's backend network. See the tenant runbook for the expanded trust diagram.

| Identity | Read/execute | Not allowed |
| --- | --- | --- |
| `host/lab/checkout` | `lab/secrets/payment-api-key`, `lab/secrets/credential-version` | Fraud key, secret writes, policy management |
| `host/lab/fraud` | `lab/secrets/fraud-model-key`, `lab/secrets/credential-version` | Payment key, secret writes, policy management |
| `admin` | Bootstrap, policy and secret management | Never mounted into application containers |

Conjur `read` permits metadata access; `execute` permits retrieval of a variable's value. The account (`sandbox` by default) is separate from these relative resource paths. Policies are loaded additively with `POST`: root creates `lab`; identities are loaded under `lab`; variables and grants are then loaded under `lab`. Removing a grant from a policy file does **not** revoke an already-loaded grant: use an explicitly reviewed policy delete/update procedure for revocation, not this additive loader.

```text
conjur-sandbox-lab/
├── .env.example
├── docker-compose.yml
├── Makefile
├── README.md
├── config/
│   ├── nginx.conf
│   ├── tenant-nginx.conf
│   └── tenants.json
├── docs/
│   ├── development.md
│   ├── security-exercise.md
│   ├── zero-trust-multitenancy.md
│   └── container-security.md
├── policy/
│   ├── 01-root.yml
│   ├── 02-app-identity.yml
│   ├── 03-secrets.yml
│   ├── 04-human-exercise.yml
│   ├── 05-tenants.yml
│   └── exercise/
│       ├── expose.yml
│       ├── contain.yml
│       └── reset.yml
├── scripts/
│   ├── common.sh
│   ├── up.sh
│   ├── init-conjur.sh
│   ├── load-policies.sh
│   ├── rotate-secrets.sh
│   ├── test-app.sh
│   ├── clean.sh
│   ├── conjur-entrypoint.sh
│   ├── client-entrypoint.sh
│   ├── manage.py
│   ├── exercise.py
│   ├── exercise.sh
│   ├── exercise-report.py
│   ├── test-exercise.sh
│   ├── tenants.py
│   ├── tenants.sh
│   ├── send-message.py
│   ├── test-gateway.py
│   └── container-security.py
├── app/
│   ├── Dockerfile
│   ├── app.py
│   ├── message.py
│   └── requirements.txt
├── tests/
│   ├── test_app.py
│   ├── test_manage.py
│   ├── test_exercise.py
│   ├── test_message.py
│   ├── test_sender.py
│   └── test_tenants.py
└── k8s/
    ├── workloads.yml
    └── README.md
```

## Commands and application API

```bash
make help
make policies                 # Additive load; preserves host keys
make rotate                   # Rotate payment/fraud values, not host identities
make cli ARGS=whoami           # Ephemeral, preconfigured CyberArk CLI
make test                     # Offline unit tests + Bash syntax checks
make logs                     # Recent service logs; no management responses
make down                     # Stop/remove containers; retain volume and keys
make up && make init          # Resume persisted state
make clean CONFIRM=destroy    # Irreversibly delete DB volume and runtime keys
```

The administrative CLI has the trusted certificate, appliance URL, account, and admin login injected. Its wrapper reads the admin key from a mounted file into process environment, not a command-line argument. Default `make cli` runs `whoami`; it is intentionally a privileged tool. Do not use CLI debug flags or commands that print credentials in shared terminals or CI logs.

After initialization:

```bash
curl --fail --cacert .runtime/tls.crt https://localhost:8443/health
curl --fail http://localhost:8081/readyz
curl --fail http://localhost:8081/evaluate \
  -H 'Content-Type: application/json' \
  --data '{"order_id":"order-2048","amount":129.95,"currency":"USD"}'
curl --fail http://localhost:8082/evaluate \
  -H 'Content-Type: application/json' \
  --data '{"order_id":"order-2048","amount":129.95,"currency":"USD"}'
make rotate
```

Checkout returns `order_id`, `status: signed`, and `credential_version`. Fraud returns `order_id`, `risk_score`, `risk_level`, and `credential_version`. The UUID is a deliberately public rotation marker, not a key fingerprint. Signatures and secret values are not returned. This is a demonstration of using a secret, not a complete payment processor.

`GET /healthz` is dependency-free liveness. `GET /readyz` checks current permitted secret access. `POST /evaluate` requires exactly `order_id`, numeric `amount` (>0 and ≤1,000,000), and a three-letter `currency`; it rejects invalid input and bodies over 16 KiB. Upstream failures return a generic 503. The bounded server accepts at most 16 active requests with socket timeouts. Application HTTP endpoints are unauthenticated and published **only to localhost**: never expose them to untrusted callers as-is.

### REST authentication

The standard-library client posts its host API key to `/authn/{account}/{url-encoded-login}/authenticate`. The raw short-lived token is Base64 encoded and sent as `Authorization: Token token="..."` to `/secrets/{account}/variable/{url-encoded-id}`. Whole IDs, including slashes, are encoded. Each read obtains a fresh token; a secret-read 401 triggers at most one reauthentication retry, while 403/404 are not retried. TLS verification is always enabled, redirects are rejected, and request/response credentials are not logged. This lab uses direct REST, not Secretless or an SDK, and supports two independently configured instances of the same workload image.

The image accepts `WORKLOAD`, `CONJUR_APPLIANCE_URL`, `CONJUR_ACCOUNT`, `CONJUR_AUTHN_LOGIN`, `CONJUR_AUTHN_API_KEY_FILE`, `CONJUR_CERT_FILE`, optional `CONJUR_TIMEOUT_SECONDS` (default 5), and `APP_HOST`/`APP_PORT`. An API-key environment injection is supported via `CONJUR_AUTHN_API_KEY`; the mounted file takes precedence. Compose uses files to avoid putting application credentials in its rendered configuration.

## Secret lifecycle and recovery

- `.env.example` and `.env` contain **configuration only**, never secrets. `.env` is ignored. Account names should be simple identifiers; choose the account before first initialization. Changing it is not a migration and requires a separate instance or destructive reset.
- `.runtime/` is gitignored, private mode 0700, and contains the data key, database password, TLS key/certificate, and bootstrap identity keys. Secret values are generated in management process memory and stored only in Conjur. Never commit or publish this directory, diagnostics containing credentials, or database dumps.
- Compose file-backed secrets are **not encrypted secret storage**. They are read-only bind mounts. The data key and DB password are injected into Conjur's process environment by its entrypoint; privileged host/container administrators can inspect process memory/environment. Use a managed secret store and an independently protected encryption key for a real deployment.
- Host API-key files are mode 0444 so UID 10001 can read their individual mounts; the host parent directory remains 0700. Other application secrets are not mounted. Administrative files remain 0600. The manager runs as the invoking host UID/GID, and the CLI is an ephemeral root administrative container. Workloads run non-root, read-only, with all capabilities dropped.
- `make rotate` publishes the version marker **after** both secret writes. Conjur does not provide a transaction spanning these writes: a crash or concurrent request can observe a partially rotated set. Repeat rotation to converge after a failed operation. This lab's keys have no external provider; production rotation must coordinate provider-side creation, overlap, cutover, and revocation.
- Shell entrypoints use strict error handling, private output redirection, colorized logs, and a directory lock to serialize lab management operations. If interrupted, first ensure no management process is running, then remove the stale `.runtime/operation.lock` directory. The lock is not a distributed lock or protection against external API writers.
- Back up the Postgres volume/database and runtime keys together under access controls, with the data key protected separately. Losing the data key makes encrypted records unrecoverable. The scripts refuse to regenerate missing infrastructure keys after a successful bootstrap. Never delete only a volume or only `.runtime/`; restore a matching backup or use the guarded full reset.
- If account creation succeeded but credential extraction was interrupted, `bootstrap.out` preserves the output privately for the next `make init`. If a crash occurred before it was renamed, inspect `.runtime/bootstrap.out.tmp` privately and restore it to `bootstrap.out` only after confirming it contains the successful account output. If the account exists but the admin key was lost, restore a backup; the script intentionally does not delete the account or fabricate credentials.
- If policies were loaded but a host key was lost before being captured, restore that key or perform a reviewed host credential rotation/reprovisioning. An additive load does not reissue existing host API keys. Secret-value rotation does not revoke host API keys or already-issued tokens.
- Certificates expire after 30 days. For lab renewal, stop containers, replace `.runtime/tls.key` and `.runtime/tls.crt` using the same OpenSSL command in `scripts/up.sh`, retain SANs for `proxy`/`localhost`/`127.0.0.1`, preserve private permissions, and start again. Recreate containers with mounted trust material; never bypass verification using `-k`.

## Kubernetes and production promotion

[Kubernetes workload handoff](k8s/README.md) includes complete restricted-Pod-Security-compatible Deployments and internal Services. Supply the existing Conjur endpoint, trusted CA, and separately provisioned host keys externally. It is not a second Conjur server deployment or an HA plan.

Before production use: pin tested image digests from a compatible CyberArk OSS suite (the requested server default is `cyberark/conjur:latest`), scan/sign images, use enterprise PKI and end-to-end TLS, configure network allowlists, centralize protected audit logs, add caller authentication and a production application server, replace long-lived bootstrap keys with supported workload authentication, protect Kubernetes Secrets with etcd encryption and RBAC, and implement monitored backups with tested restores. Validate availability, capacity, upgrades, and revocation requirements separately. Do not interpret local healthchecks as an HA or compliance guarantee.

## Verification and troubleshooting

`make test` covers URL encoding, token headers, 401 retry behavior, denied reads, redirect rejection, input validation, generic failures, secret-safe HTTP responses, fresh reads, bootstrap extraction, idempotence, policy credential capture, and rotation ordering. Compose configuration can be checked with `docker compose config --quiet`; it never needs credentials in `.env`.

Live verification is `make up && make init && make test-app && make cli ARGS=whoami`. If startup fails, inspect `docker compose ps` and `make logs` locally. Database startup precedes Conjur, and Conjur health precedes the TLS gateway. For authentication errors, check the account, host paths, runtime key presence, and policy-load completion; do not paste keys into tickets. For TLS failures, check certificate dates, SANs, and mounted CA paths instead of disabling verification. Docker users and administrators are trusted with this lab's secrets.

Implementation checks in the authoring environment include offline tests, Bash syntax, Compose schema validation, and image-tag availability. Docker was unavailable in that environment, so live Conjur bootstrap, official CLI behavior, and container integration are **not yet verified**; the supplied commands are the integration acceptance gate, not a claimed passing result.

### Upstream references

- [CyberArk Conjur quickstart](https://github.com/cyberark/conjur-quickstart): official sample architecture and bootstrap/CLI commands; explicitly demo-only.
- [Conjur authentication](https://docs.cyberark.com/conjur-open-source/Latest/en/Content/Operations/Services/Authentication-new.htm): host credentials, short-lived access tokens, and authorization flow.
- [Server account bootstrap task](https://github.com/cyberark/conjur/blob/master/lib/tasks/account.rake): current `API key for admin:` output parsed privately by this lab.
- [Docker Compose secrets](https://docs.docker.com/compose/how-tos/use-secrets/): service-scoped file-backed injection and its limits.
