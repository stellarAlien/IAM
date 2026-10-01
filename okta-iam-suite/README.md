# Okta IAM learning suite — Integrator Free Plan

A companion to the Conjur sandbox for **human IAM**: browser SSO with Authorization Code + PKCE, MFA configuration, JWT API authorization, scoped RBAC, joiner/mover/leaver lifecycle, local expiring access, containment of retained tokens, access reviews and System Log inspection.

This suite targets Okta's current **Integrator Free Plan**, not the retired Developer Edition or a time-limited sales trial. It runs independently of Docker and Conjur. Okta remains the hosted identity provider; there is no fake local Okta server. You must create/configure your own free org and authorize any management mutations.

## Plan fit

As checked against [Okta's current free-org reference](https://developer.okta.com/docs/reference/org-defaults/), the plan includes SSO, Universal Directory, Adaptive MFA, Lifecycle Management, API Access Management and Workflows. It allows **10 active users** and **five Workflows**, excludes Org2Org and email automation, and may deactivate after 90 consecutive days without a user sign-in unless an app is submitted to the OIN. Sign-up requires an eligible unique business email; entitlement/UI details can change.

The suite creates **three synthetic actors at most** (Alice, Bob, Eve) plus six groups. Account for your existing/admin users within the 10-user cap. Do not connect the lab users or groups to production apps. No paid Identity Governance certification campaign, Okta Privileged Access/PAM, Org2Org federation, device management subscription or paid connector is assumed. Local review/JIT exercises are explicitly **not those Okta products**.

## Quick start

Read [setup.md](docs/setup.md) before using the management CLI.

```bash
cd okta-iam-suite
make setup
make configure
# Configure your free Okta org and edit config/local.json using docs/setup.md.
make doctor
make test
make serve                    # Terminal 1: loopback API
make login                    # Terminal 2: browser redirect to Okta
printf '%s\n' 'Synthetic authenticated message' | make send TENANT=acme ENVIRONMENT=dev
make logout
```

`make login NO_BROWSER=1` supports environments where the browser cannot be launched: it stores a private authorization URL locally. The redirect listener is on `http://127.0.0.1:8765/callback`, so the browser must be on the same machine or have an explicitly secured tunnel to that loopback endpoint. Do not expose the callback publicly, paste private URLs into tickets, or share tokens with another machine.

Starting a new login removes the previous local token before opening the browser, so a failed actor switch cannot silently submit as the last signed-in user. Removing a local token is not revoking its copies or ending the browser's Okta session.

For cloud-hosted coding environments, offline tests/management API operations can run there, but a live browser login requires a correctly reachable loopback listener. A successful unit test is not evidence of real Okta sign-in/MFA. No org URL, client ID, management token or live browser access was supplied during implementation; live Okta acceptance remains unverified.

## Architecture

```text
browser ── hosted Okta sign-in + configured MFA
   │ authorization code + state
   ▼
loopback PKCE listener ── HTTPS code exchange/JWKS validation ── Okta custom AS
   │ validated access token, private local file
   ▼
curl ── loopback JWT API :8090 ── signature/issuer/audience/client/scope/group checks
                                └── fresh local block, token cutoff and expiring grants

facilitator CLI ── separate SSWS management credential ── Okta users/groups/logs
```

There are **two different credentials/trust planes**: public-client OIDC access tokens for the demo API, and an administrative SSWS token for guarded Okta management operations. Neither is a Conjur API key. The API never reads the management token, calls Okta user-management APIs, or receives browser passwords. The login flow does not use password grant, implicit flow, a client secret, or offline refresh tokens.

The API accepts only custom-authorization-server access tokens for `api://iam-lab`, from the configured issuer/client, with `messages.send` and exact `iam-lab-<tenant>-<environment>-submitters` group membership. It rejects ID tokens and org-server access tokens. A `uid` claim identifies the Okta user for local containment/cutoff/JIT, rather than relying on email-valued `sub`. Groups in signed JWTs can remain stale until new issuance; local containment and issue-time cutoffs demonstrate that limitation explicitly.

Message bodies must contain exactly one `message` string, nonempty and at most 2048 UTF-8 bytes. The HTTP body is bounded at 12,416 bytes to permit worst-case JSON escaping without relaxing the decoded message limit. The sender emits UTF-8 JSON directly; no message or token is logged or returned.

API routes use the same four tenant/environment labels as Conjur, but **this is a separate JWT demo at port 8090**. It does not retrofit JWT acceptance into the existing Conjur bearer-token APIs or synchronize Okta groups to Conjur grants. Human SSO and Conjur workload identity remain separated. That separation avoids silently granting human users secret-management authority.

## Learning tracks

| Track | Implemented or configured exercise |
| --- | --- |
| SSO/OIDC | Real hosted redirect, PKCE S256, state/nonce, ID/access JWT validation and local logout/revocation |
| MFA | Okta authenticator enrollment and app sign-in policy configured in your free org; observe real sign-in events |
| API authorization | Four scoped message endpoints; scope/group/client/audience checks and negative tests |
| Joiner–Mover–Leaver | Guarded three-user provisioning, scoped group replacement, retained-token block, session revocation/deactivation |
| Temporary privilege | Facilitator-approved local 1–15 minute JIT grant; no claim of Okta PAM/approval workflow |
| Access governance | Private report of registered users, statuses, memberships and local blocks; human-reviewed decisions |
| Detection | Bounded private System Log snapshots correlated with local safe outcomes |
| Workflows | Two optional free-plan flow recipes in the exercise runbook; configured/tested in Okta UI, not imported automatically |
| SCIM/SAML | Extension guidance and capability boundaries; no SCIM server or SAML service provider implemented |

See [exercises.md](docs/exercises.md) for the full manual walkthrough and expected results. See [development.md](docs/development.md) before changing the suite.

## Commands and mutations

```bash
make groups CONFIRM=lab-only
make join ACTOR=alice LOGIN=iam-lab-alice@YOUR_CONTROLLED_DOMAIN CONFIRM=lab-only
make move ACTOR=alice SCOPE=acme/dev CONFIRM=lab-only
make release ACTOR=alice CONFIRM=lab-only
make contain ACTOR=alice
make jit ACTOR=alice SCOPE=acme/prod MINUTES=5 CONFIRM=lab-only
make review
make audit
make leave ACTOR=eve CONFIRM=deactivate-lab-user
```

Only locally registered suite-created objects are mutated. Existing same-name objects are not automatically adopted. `join` stages users without passwords, preserving existing keys/profiles; activate/enroll manually. `move` blocks the user locally, removes all suite privilege groups, adds exactly one scoped submitter role and leaves the block in place. `release` requires an ACTIVE user and refuses older JWT issue times; wait at least one second then sign in again.

`contain` blocks the API immediately but does not disable Okta login. `leave` blocks first, then requests Okta session/OAuth-token revocation and user deactivation. **Deactivation can destroy downstream application data**; the explicit confirmation is intentional. Async completion and external app provisioning must be verified separately. No user/group deletion or automatic destructive cleanup is supplied.

All private state is in ignored `.runtime/` (0700 directory, 0600 files). Never commit or publish access tokens, administrative tokens, actor logins, registry IDs or raw System Log records. SSWS privileges follow its creating administrator: use the least privileges/network restrictions available for these exercises, restrict the token file, and revoke the token in Okta after testing. Production management integrations should use scoped OAuth service-app credentials instead.

## Verification and limitations

Offline tests cover signature/claim validation, wrong audience/issuer/algorithm, input validation, scope/group isolation, retained-token blocks, token cutoff/JIT expiry, PKCE/state/nonce, private file handling, and guarded management lifecycle behavior. Okta plan availability, policy configuration, real MFA/sign-in, token issuance, API management responses and offboarding completion require live tenant evidence.

The local API is loopback **HTTP** and uses Flask's development server for a single-machine lab. It is not a production server or remote endpoint. For deployment, add TLS, a production WSGI server, centralized protected policy storage, auditable approvals, authorization-policy ownership, rate limits, monitoring and formal revocation design. Local JSON files/CLI locks are not a multi-node governance system. Token revocation does not automatically invalidate offline JWT validation; local blocks/cutoffs are deliberately checked on every API request.
