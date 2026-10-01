# Enterprise and small-team IAM exercises

Run only with your dedicated free org, three synthetic users and a separate administrator. Complete [setup.md](setup.md) first. All messages are synthetic and ephemeral; a 202 is not durable delivery. This is a CLI/API learning suite: sign-in takes place on Okta's hosted page, not a custom password form.

## 1. Joiner: grant identity, then access

Provision Alice, Bob and Eve using `make groups`/`make join` from the setup guide. Activate/enroll each in Okta, check the `iam-lab-users` application assignment, and verify each has required MFA. No scope group is initially assigned. An assigned app is **not** permission to submit messages.

Terminal 1:

```bash
cd okta-iam-suite
make serve
```

Terminal 2, as the facilitator:

```bash
make move ACTOR=alice SCOPE=acme/dev CONFIRM=lab-only
make release ACTOR=alice CONFIRM=lab-only
# Wait at least one second, then use Alice's separate browser profile.
make login
printf '%s\n' 'Alice approved Acme dev message' | make send TENANT=acme ENVIRONMENT=dev
printf '%s\n' 'Alice attempts Acme prod' | make send TENANT=acme ENVIRONMENT=prod
printf '%s\n' 'Alice attempts Globex dev' | make send TENANT=globex ENVIRONMENT=dev
```

Expected: first **202**, others **403**. Login creates a private token file; send invokes curl with a private bearer-header file rather than command-line credentials. Missing/invalid token returns **401**, Okta key-fetch/local-policy failure **503**. A network outage or 429 is not a successful deny result.

Repeat Bob with `globex/dev`; leave Eve assigned to the app but with **no submitter groups**. Eve should sign in with MFA but receive 403 for every message scope. This models a compromised low-privilege user—not an external exploit. Never use the facilitator's administrator session as Eve; inspect the currently selected browser identity before signing in.

**Business lesson:** authentication, application assignment and resource authorization are different controls. MFA protects sign-in; RBAC limits what a signed-in identity can do.

## 2. MFA and SSO policy evidence

1. Sign in using a new/separate browser profile for the actor.
2. Observe the actual authenticator requirement, not just an enrollment checkbox.
3. Attempt sign-in without completing the required factor; it must not yield a usable API token.
4. Sign in again within the allowed SSO session policy; note whether the tenant reuses the session or challenges again.
5. Inspect System Log entries for sign-in/authentication-policy decisions and authenticator events.

Do not claim a particular assurance level based solely on API JWT validity. Okta's policy controls challenge behavior. The suite validates identity/token properties but does not implement device posture or a phishing-resistant-factor claim policy.

## 3. Mover: remove previous access, protect against stale JWTs

While Alice's old Acme dev token remains saved:

```bash
make move ACTOR=alice SCOPE=globex/dev CONFIRM=lab-only
printf '%s\n' 'Old token after move' | make send TENANT=acme ENVIRONMENT=dev
```

Expected **403**: the mover action blocks Alice locally **before** changing groups and removes all suite privilege groups before adding the new one. It deliberately leaves her locally blocked until a facilitator reviews the change.

```bash
make review
make release ACTOR=alice CONFIRM=lab-only
printf '%s\n' 'Stale token after reviewed release' | make send TENANT=acme ENVIRONMENT=dev
```

Still **403**: release records a local minimum issue time, so an earlier JWT carrying old groups cannot regain access. Wait at least one second and perform fresh PKCE sign-in as Alice:

```bash
make login
printf '%s\n' 'Alice new team message' | make send TENANT=globex ENVIRONMENT=dev
printf '%s\n' 'Alice previous team denied' | make send TENANT=acme ENVIRONMENT=dev
```

Expected **202** for Globex dev and **403** for Acme dev. If refreshed groups are absent, inspect assignment, claim filter, policy and eventual directory consistency privately; don't modify expected denials to make a demonstration pass.

**Business lesson:** group removal alone does not rewrite already-issued JWT claims. Token lifetime, issue-time cutoff, online policy evaluation and revocation design must be explicit.

## 4. Controlled temporary privilege (local JIT model)

Keep Alice with her legitimate dev submitter group. In the facilitator terminal:

```bash
make jit ACTOR=alice SCOPE=acme/prod MINUTES=1 CONFIRM=lab-only
make login
printf '%s\n' 'Temporary approved prod lab action' | make send TENANT=acme ENVIRONMENT=prod
```

Expected **202** only when Alice has a signed `iam-lab-jit-candidates` group, a matching **local** grant, no block/cutoff denial, and `messages.send`. The facilitator records a 1–15 minute grant; this is a human-approved terminal action, not a multi-party approval workflow. After the minute expires, retry with the **same** token:

```bash
printf '%s\n' 'Expired temporary privilege' | make send TENANT=acme ENVIRONMENT=prod
```

Expected **403**. A candidate group alone never grants access. A normal prod submitter group would independently authorize prod, so check that Alice does **not** hold it before demonstrating expiry. Expiry is enforced on each API request, not by waiting for a scheduled group cleanup. Candidate membership remains but has no scope privilege without a valid grant.

**Business lesson:** distinguish eligibility, approval, scope, duration and enforcement. This is not Okta Privileged Access/PAM or an Identity Governance entitlement product.

## 5. Compromised credential: contain a retained token

Give Eve only Acme dev for this deliberate exercise, perform real login as Eve and confirm one 202. Then, without deleting or replacing Eve's saved token:

```bash
make contain ACTOR=eve
printf '%s\n' 'Eve token retained after containment' | make send TENANT=acme ENVIRONMENT=dev
```

Expected **403** immediately from the API's per-request block check. Containment uses the locally registered Okta `uid` and does not require an Okta API token/network call, so the local resource can close this path during a provider outage. It does **not** stop Eve from logging in to Okta or other applications and is not global session revocation. A valid JWT with a blocked `uid` still fails.

## 6. Leaver: block resources, revoke sessions, deactivate deliberately

First review app assignments: Okta deactivation deprovisions assigned apps and can permanently destroy downstream data. Use only synthetic users assigned to this lab app.

```bash
make leave ACTOR=eve CONFIRM=deactivate-lab-user
printf '%s\n' 'Retained token after offboarding' | make send TENANT=acme ENVIRONMENT=dev
make review
make audit
```

The CLI verifies the registered user, blocks locally, requests Okta session/OAuth-token revocation, and requests deactivation. API request should stay **403** even if the JWT's signature/lifetime is still valid. Inspect private review/Okta UI until status is **DEPROVISIONED** and try a new actor login to establish denial. Deactivation can be asynchronous; a successful management response alone does not prove all downstream apps are offboarded.

No DELETE-user endpoint, tenant-wide cleanup, production role grant, password export or identity reset is implemented. To repeat a leaver demo, manually review/reactivate the same synthetic user through Okta and complete enrollment/assignment checks; then deliberately release the local block. `join` never recreates or resets an existing identity.

## 7. Access review and detection

```bash
make review
make audit
```

- `.runtime/review.json` contains registered actors' status, current memberships and local block state. Treat group names and user data as private until reviewed.
- `.runtime/system-log.json` contains **first-page, last-hour snapshots** for registered user actor/target IDs. Each query is bounded to 100 records; results can duplicate and omit later pages. This is not a full audit export, log-retention solution or SIEM.
- Correlate actual Okta user IDs, timestamps, group changes, authentication outcomes, deactivation and token/session activity with safe local API outcomes. Local API logs omit subject IDs/messages/tokens; use private context to attribute the exercise.

The logs are neither immutable nor administrator-resistant. Enterprise deployment requires protected central collection, retention, detection rules, documented incident ownership and evidence-quality review. Never upload raw System Log records or full token claims to public tickets.

## Optional free-plan Workflows recipes (manual, no paid connector assumptions)

The current plan permits five Workflows. Use at most two for this lab and test in the Workflows console; the repository does not import/export flows or assume your org has connectors/cards enabled.

### Flow A — lifecycle review trigger

1. Use an available Okta user-created event trigger.
2. Filter the login to `iam-lab-*` and verify the actor belongs to the dedicated exercise.
3. Read the user's group memberships using the Okta connector.
4. Write an access-review task/row to a **lab-only** Workflows table; do not auto-grant privileges.
5. Test one joiner and inspect the execution history privately. No email automation or production SaaS connector is required.

### Flow B — scheduled stale-access review

1. Use a supported scheduled trigger.
2. Inspect only the suite's six registered group IDs (store them as protected configuration, not public media).
3. Produce a review row for out-of-scope or unexpected membership; do not silently remove members from external groups.
4. Have the facilitator review and enact changes through the guarded CLI.
5. Test the bounded user/group set before enabling the schedule.

If the required cards/features are absent, keep the implemented CLI review as the supported path and record that limitation. These recipes are learning exercises, not a deployable approval engine or certification campaign.

## SCIM and SAML extension ground

LCM includes capabilities for provisioning integrations, but a generic users API script is **not SCIM**. This suite does not implement a SCIM service. A separate SCIM exercise would need a conformant `/scim/v2/Users`/`Groups` server, filtering/pagination/PATCH/deactivate semantics, separate scoped authentication, public verified HTTPS reachability, Okta SCIM app configuration, and provisioning test evidence. Never expose this loopback JWT message API as a pretend SCIM connector or use a paid connector as an assumed dependency.

Similarly, OIDC is not SAML. A SAML extension requires a maintained SP implementation, trusted metadata/signature validation, audience/recipient/time/replay controls and tenant binding. The free-plan SSO feature can support testing integrations, but no SAML SP is supplied here. Org2Org is unavailable in the free plan, so federation demos must not depend on it.

## Executive debrief

| Question | Evidence to collect |
| --- | --- |
| Does identity creation grant business access? | Staged user/app assignment succeeds; resource remains forbidden without scoped role |
| Can an employee accumulate permissions after moving? | Old role removed, retained token denied, fresh token limited to new scope |
| Can privileged access expire while a token remains valid? | Same-token JIT allowed→denied transition |
| Does MFA really protect this application? | Real enforced challenge and corresponding tenant policy events |
| Can containment work before JWT expiry? | Same retained token denied by fresh resource policy |
| Does offboarding affect every app? | Tenant status plus independently verified app/session/resource denials; document gaps |
| Can a reviewer reconstruct the decision? | Private membership/status review correlated to authoritative Okta System Log |

Runbook expected results are **acceptance criteria**, not claimed live outcomes. The implementation environment had no configured Okta org/client/token or live user enrollment.
