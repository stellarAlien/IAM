# Zero-trust foundation and tenant/environment message APIs

This extends the local sandbox with four independent API workloads: **Acme dev**, **Acme prod**, **Globex dev**, and **Globex prod**. "Prod" is an isolated **lab label**, not an actual production deployment. Each accepts a bounded JSON message via a TLS-fronted POST. Tenant identity, caller authorization, Conjur permissions and container boundaries are demonstrated independently.

Zero trust is an architectural practice, not an image tag or a promise that a compromised kernel is safe. This lab demonstrates explicit verification, least privilege, fail-closed authorization and scoped credentials. It does **not** implement enterprise conditional access, device posture, federated user identity, mTLS/service-mesh enforcement, or a complete NIST SP 800-207 deployment.

## Start and send a message with curl

Prerequisites: the base Docker stack, Python 3.10+, and curl **7.76+** (`--fail-with-body`; header files require 7.55+). Use synthetic messages only. `send-message` reads stdin and invokes the installed curl executable; it does not need requests or another HTTP library.

```bash
make up
make init
make tenants-init

printf '%s\n' 'Hello from Acme development' | make send-message TENANT=acme ENVIRONMENT=dev
printf '%s\n' 'Hello from Acme production lab' | make send-message TENANT=acme ENVIRONMENT=prod
printf '%s\n' 'Hello from Globex development' | make send-message TENANT=globex ENVIRONMENT=dev
printf '%s\n' 'Hello from Globex production lab' | make send-message TENANT=globex ENVIRONMENT=prod
```

An authenticated successful POST returns HTTP **202** with a new `message_id`, configured `tenant`, `environment`, and `status: accepted`. The message is validated and internally HMAC-signed, then discarded. There is **no durable queue, message store, subscriber delivery, or externally verified signature**. A 202 here is only an in-process demonstration, not a durability guarantee.

The curl helper authenticates as the selected scope's **sender host**, retrieves only that scope's caller token from Conjur over verified TLS, and places the bearer header in a temporary private 0600 file inside a private temporary directory. curl receives the header-file path, not the secret as an argument. JSON is passed to curl through stdin. The helper reads neither an admin API key nor a signing key. Temporary bearer material is deleted when the helper exits normally; abrupt termination can leave local temporary files, so protect host storage. Never use `set -x`, curl tracing, or `-k` with credentials.

The helper reads simple non-secret `KEY=value` settings in `.env` for `CONJUR_ACCOUNT` and `CONJUR_HTTPS_PORT`, with environment-variable overrides. It does not execute shell expansions in `.env`. Tenant HTTPS ingress is deliberately fixed at local port **8444** in Compose and the helper. The existing Conjur TLS port defaults to 8443. Only localhost endpoints are supported by the helper; it will not send credentials to an arbitrary URL supplied by an attacker.

### Direct unauthenticated curl

```bash
cd conjur-sandbox-lab  # omit if already here
curl --fail-with-body --cacert .runtime/tls.crt \
  -H 'Content-Type: application/json' \
  --data '{"message":"Unauthenticated test"}' \
  https://localhost:8444/tenants/acme/dev/messages
```

Expected result: **401**, curl exit 22. No connection error, TLS failure, or 503 counts as authorization success. The `send-message` helper provides the authenticated version of exactly this curl POST without exposing its bearer token.

## Demonstrate tenant and environment boundaries

Try Acme dev credentials against another tenant or environment:

```bash
printf '%s\n' 'Synthetic cross-tenant probe' | make send-message \
  TENANT=acme ENVIRONMENT=dev TARGET_TENANT=globex TARGET_ENVIRONMENT=dev

printf '%s\n' 'Synthetic dev-to-prod probe' | make send-message \
  TENANT=acme ENVIRONMENT=dev TARGET_TENANT=acme TARGET_ENVIRONMENT=prod
```

Both should return **401** and a nonzero Make status. `TENANT`/`ENVIRONMENT` choose the caller identity; `TARGET_*` changes only the destination path. A valid Acme dev token must not authenticate to Acme prod or Globex. A claimed tenant in a body/header cannot change server scope: the server derives it from immutable startup configuration.

```bash
make test-tenants
make tenant-rotate TENANT=globex ENVIRONMENT=prod
make container-security
```

`test-tenants` asserts Conjur secret RBAC for API and sender identities, all **16 caller source→destination combinations**, missing-token rejection, and rotation of Acme dev. It **changes Acme dev's caller token and signing key**. The old token must immediately fail subsequent API checks; other scopes' old tokens must remain usable. The helper retrieves the current token for each invocation, so normal messages work after rotation without reinitialization or restart.

The same target also runs host-side **real HTTPS/curl** acceptance through port 8444: all four valid scopes, cross-tenant/dev-to-prod rejection and missing credentials. It asserts exact 202/401 statuses and configured response scope; a TLS failure, rate limit or gateway error cannot count as a successful authorization test. The sender prints a safe `HTTP_STATUS` line after each response for manual checks.

No secret values, key fingerprints, messages or bearer headers are printed by the API or management tests. Responses contain only safe operational fields. Use stdin for sensitive content, but remember shell history captures literal example strings typed into commands; this lab is for synthetic data.

## Two distinct authorization layers

```text
scoped sender host ── verified Conjur TLS ── own ingress-token only
       │
       └── curl HTTPS :8444 /tenants/<tenant>/<environment>/messages
                      │
                 shared TLS gateway
                      │ HTTP, isolated backend network
                  fixed-scope API
                      └── verified Conjur TLS ── own token + signing-key only
```

1. **Conjur RBAC** decides which workload identities can retrieve which secrets. A caller/sender cannot retrieve signing keys or another environment's token. An API cannot read any other environment's secrets. Namespaces alone do not enforce this; scoped permits and tests do.
2. **API caller authorization** checks a supplied bearer token against the current scope's token on **every request**, using a constant-time comparison. Secrets are retrieved fresh, without an application credential cache. Missing/invalid credentials return 401; a Conjur dependency failure returns generic 503 and no acceptance. This is a shared secret per scope, not per-user attribution or a signed end-user identity.

Possession of a valid scope token grants message submission to that scope. Its replay is possible until rotation. Production should replace shared bearer tokens with short-lived audienced OIDC/JWT credentials, bind caller identity to authorization, validate issuer/audience/expiry, and add replay/rate protections suited to the workload. API responses and internal HMAC do not fix compromised caller credentials or provider-side exposure.

## RBAC ground for a multi-tenant environment

All four namespaces are rooted at `tenants/<tenant>/<environment>` under the **same Conjur account**. This is logical tenant separation; the account administrator still has cross-tenant authority. A separate account/deployment is required when contractual or threat-model requirements demand an independent administrative boundary.

| Scoped group | Default member | Permission on scoped variables |
| --- | --- | --- |
| `api-readers` | `host/tenants/<tenant>/<environment>/api` | `read, execute` on ingress-token and signing-key |
| `callers` | `host/tenants/<tenant>/<environment>/sender` | `read, execute` on ingress-token only |
| `reviewers` | None | `read` metadata on both variables; no value retrieval |
| `secret-operators` | None | `read, execute, update` on both variables; no policy-management permit |

The last two groups are an **unassigned foundation**, not fabricated users or an enabled permission path. Provision human users through your identity lifecycle, use reviewed group grants for each specific tenant/environment, and verify actual access. Never put every developer into a common group that inherits prod or every tenant. Existing Alice, Bob and Eve exercise users receive **no new tenant permissions**. Human role changes must not reuse their unrelated lab-business groups as implicit tenant authority.

The YAML anchor in `policy/05-tenants.yml` reuses the same environment-local policy body without sharing role identities: relative `api-readers`, `callers`, and `secrets/...` references resolve inside each separate policy branch. Actual Conjur interpretation remains a live acceptance requirement. Default owners are the policy/account administrator; the groups above do not own policy or have create/update policy privileges. Secret update is not policy update.

Suggested promotion rules:

- Define tenant owner, environment approver, secret custodian and security reviewer responsibilities separately. Make access time-bound where supported by your identity workflow.
- Provision dev and prod principals independently; never promote a dev API key or copy a prod secret into dev.
- Give CI identities only the scope/action they need; keep control-plane and runtime credentials separate.
- For offboarding, review all direct/inherited grants and ownership, explicitly revoke membership with PATCH, rotate potentially exposed values, and handle API-key/token lifecycle separately.
- Require policy-as-code review for permission changes. Additive POST retains grants that are absent from a file; it is not a recertification or deletion mechanism.
- Validate metadata access as well as value retrieval if tenant resource names or annotations are confidential.

## Network and container layer

Each API joins **one dedicated internal Docker network** (`acme-dev`, `acme-prod`, `globex-dev`, or `globex-prod`) and exposes no host port. The shared tenant TLS gateway, Conjur TLS proxy, and ephemeral trusted manager connect to the scopes to route/authenticate/test. APIs have no direct peer-network membership. Shared gateways and Docker administrators remain cross-tenant trust boundaries and compromise targets.

The tenant gateway publishes only `127.0.0.1:8444`, uses verified self-signed TLS at ingress, exact route allowlists, 4 KiB body limits and per-IP rate limits. APIs independently verify credentials; the gateway does not supply tenant authorization. HTTP between the gateway and API is isolated **but not encrypted or mutually authenticated**. Therefore this is **not end-to-end zero trust**. For production, enforce backend mTLS/workload identity and network policy; do not equate a Docker bridge with a cryptographic identity boundary.

Each API runs as UID/GID 10001, uses a read-only root filesystem, a bounded `/tmp` tmpfs, no Linux capabilities, no-new-privileges, default runtime seccomp, and explicit 128 MiB memory / 0.5 CPU / 64 PID limits. It mounts only its own Conjur host key and the public TLS certificate. Container details and exercises are in [container-security.md](container-security.md).

The shared bootstrap certificate/key and mutable base image tags are lab conveniences. Protect host-owned file-backed secrets; Docker secrets here are not encrypted storage. A compromised API can retrieve its own ingress token and signing key and accept arbitrary local messages; the intended remaining control is Conjur cross-scope RBAC, not prevention of every action inside the compromised process. A compromised Docker host/kernel or gateway invalidates stronger isolation claims.

## API contract

- `POST /messages` at the backend, or the exact scoped gateway path shown above.
- `Authorization: Bearer <current scope token>` and `Content-Type: application/json`.
- Body exactly `{"message":"..."}`; nonempty UTF-8 string, at most 2048 encoded bytes; maximum HTTP body 4096 bytes. Extra tenant/environment keys are rejected. Transfer encoding and invalid/duplicate framing are handled conservatively by the backend; use normal curl Content-Length requests.
- 202 accepted; 401 unauthorized; 400 invalid input; 404 unknown path; 413 too large; 415 wrong content type; 503 dependency failure. Gateway rate/body limits can return additional rejection statuses.
- `/healthz` is backend liveness; `/readyz` checks both scoped Conjur values without returning them. The public tenant gateway exposes only its own `/healthz` and the four message routes. Gateway liveness does not prove all backends are ready.

## Verification status and references

Offline tests exercise HTTP behavior, fixed scope, credential freshness, input limits, absence of secret/message logs, provisioning idempotence, isolation matrix expectations and container configuration checks. Compose/YAML validation does not establish live Conjur policy semantics, network isolation, TLS routing or kernel hardening. Docker is unavailable in the authoring environment; run the commands above before calling the live outcomes verified.

- [NIST SP 800-207, Zero Trust Architecture](https://csrc.nist.gov/pubs/sp/800/207/final): architecture reference, not a certification claim for this lab.
- [Docker Compose service security/resource controls](https://docs.docker.com/reference/compose-file/services/): container-level configuration semantics.
- [Conjur policy load modes](https://docs.cyberark.com/conjur-open-source/latest/en/content/operations/policy/policy-load.html): POST versus PATCH/PUT authorization and deletion behavior.
