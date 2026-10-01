# Okta suite development handoff

Read root `AGENTS.md`, `conjur-sandbox-lab/docs/development.md`, this file and [setup.md](setup.md) before editing. This is a separate human-IAM lab, not a production Okta integration or a Conjur permission synchronizer.

## Architecture map

| File | Responsibility |
| --- | --- |
| `config/example.json`, `okta_lab/config.py` | Non-secret tenant/client/issuer/audience and loopback configuration validation |
| `okta_lab/login.py` | Public Native OIDC PKCE flow, state/nonce, fixed loopback callback, validated private token storage, logout |
| `okta_lab/api.py` | RS256/JWKS access-token validation, scope/group/tenant checks, per-request local containment/cutoff/JIT |
| `okta_lab/manage.py` | Registered-object-only management APIs, staged users, group moves, local blocks, JIT, reviews and log snapshots |
| `okta_lab/send.py` | Real curl request, stdin message, private header file, fixed configured loopback origin |
| `tests/` | Offline crypto/HTTP/management boundary tests, no live credentials |
| `docs/` | Free-plan setup, mutation/acceptance walkthroughs and future-run instructions |

## Invariants

- No real secrets, raw tokens, private log records, logins or registry IDs in git/output/media. `.runtime/`, config/local.json and the virtual environment are ignored.
- The hosted provider is a real configured Integrator Free Plan org. Offline fakes establish code behavior only, never real MFA, claim issuance, plan entitlement or management mutation.
- Keep OIDC Native public-client PKCE. Never add password grant, implicit flow, client secrets, disabled TLS verification, permissive callbacks or a custom password UI.
- API authorization requires custom-AS access token with expected RS256 signature, issuer, API audience, client (`cid`), user identifier (`uid`), lifetime and `messages.send` scope plus exact scoped groups. ID tokens/org-server tokens are not API credentials.
- Preserve per-request local blocks, minimum issue time and expiring grants. A group membership snapshot is stale after changes; do not claim API revocation simply from Okta logout or group removal.
- The API never consumes management credentials. The management API uses a separate private SSWS token; production service-app OAuth is an unimplemented promotion requirement.
- Management mutations are limited to registry-created `iam-lab-*` groups/users in the matching org. Never adopt an existing user/group by name, expand to Everyone, mutate an admin identity or auto-delete objects.
- `move` blocks first and removes old role groups before adding one new role; `release` sets a token issue-time cutoff before removing the block. A fresh login is required afterward.
- JIT is a local facilitator-authorized grant with a 1–15 minute maximum, not Okta PAM, automated approval or Identity Governance. Scope submitter groups can independently authorize; candidate membership alone cannot.
- `leave` requires `deactivate-lab-user` confirmation. Okta deactivation can destroy downstream data; inspect assignments first and verify asynchronous completion after requests.
- Local mutation CLI uses an operation lock. Atomic private JSON replacement is single-host/single-writer, not a distributed authorization store. After interruption, verify no CLI process is active before removing a stale `.runtime/operation.lock`.

## Checks and environment

```bash
cd okta-iam-suite
make setup
make test
.venv/bin/python -m compileall -q okta_lab
git diff --check
```

Python 3.10+ is required. Top-level dependencies are pinned; install in the suite's `.venv`, not system Python. Run the existing `make test` at repository root too; it tests the Conjur lab. Root `okta-test`/`okta-setup` targets delegate to this suite. Dependencies must be set up before Okta tests; do not weaken tests for missing dependencies.

Use current official Okta docs for plan changes, issuer/claim configuration and lifecycle APIs. The free plan currently limits 10 active users and five Workflows. Keep the three-actor budget and do not assume email automation, Org2Org, paid governance/PAM or production API Access Management licensing. No account signup or management token can be created by offline automation.

## Verification boundaries

Offline tests must check real cryptographic signature validation, issuer/audience/client/uid/scope/group checks, claim types, PKCE/state/nonce, safe callbacks, file permissions, data-independent output, invalid policy fail-closed behavior, retained-token blocks/cutoffs, JIT expiry, and registered mutation guards.

Live acceptance requires user-supplied tenant configuration and authorization: discovery, app assignment, real hosted sign-in/MFA, JWT-protected curl success and cross-scope denial, mover same-token denial, JIT expiry, containment, session revocation/deactivation and private System Log correlation. Never infer these from a mock or historical media. Local API health/no-token HTTP probes can be verified without Okta, but authenticated outcomes cannot.

Implementation verification passed reproducible `make okta-setup`, 46 Okta offline tests, the 66 existing Conjur tests, dependency consistency, Python compilation and diff checks. Fresh running-API checks confirmed `/healthz` 200, missing bearer token 401, and omission of a synthetic query marker from logs. No configured tenant/client/management credential was supplied; live hosted sign-in, MFA, issuance, lifecycle and audit behavior remain unverified.

The API exposes JSON routes only; login's callback has static plain-text responses, no application UI. Preserve callback/body/code secrecy. Browser sign-in happens on the external hosted provider; do not automate enrollment of factors or credential capture without explicit authorization.

## Recovery and mutation ordering

- Staged users carry no locally generated passwords. Manual activation/enrollment must use supported tenant options.
- Registered object verification checks remote IDs/profile names before mutations. A successful create followed by interrupted registry persistence requires deliberate private recovery; do not adopt arbitrary objects.
- Group/user state changes can partially succeed. Retry documented idempotent setup/mover operations after inspecting private state. No automatic retry of Okta mutation requests or rate-limit responses is implemented.
- `contain` can close the local API path without an Okta management token/network call, using an already trusted local registry. It does not globally contain the identity.
- `leave` reads/validates the registered identity, then blocks locally before remote session/token/deactivation operations. A remote failure after blocking must leave the block in place.
- System Log collection deliberately fetches only first pages from the last hour, per registered user. It is not complete pagination, indefinite retention, immutable evidence or a SIEM. Review export privately before sharing.
- Logout must distinguish local token removal, remote access-token revocation and global browser/SSO-session logout. Do not promise one when implementing another.

## Future integrations—not implemented

SCIM/SAML service providers, Okta-to-Conjur group provisioning, JWT authorization inside the existing Conjur-backed API containers, refresh-token rotation, service-app management OAuth, protected production policy store, actual multi-party approval, remote TLS deployment, full System Log pagination/collection, and production WSGI hosting are separate engineering work. Add them only under a scoped task with their own tests and real acceptance evidence.
