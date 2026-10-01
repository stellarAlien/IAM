# The compromised contractor: a 15-minute CISO/ISSO exercise

**Business question:** If a contractor's credential is stolen, can that identity read a payment credential, alter it, reach fraud secrets, or grant itself privileges? If a human makes a policy mistake, can we identify the exposure and close the access path without stopping legitimate services?

This is an authorized, synthetic lab exercise. Eve represents an attacker using a compromised contractor credential; she is not a different authentication mechanism. All attack actions are bounded REST requests to this Compose lab. There is no exploit, external target, credential dumping, or real payment data. Use three terminal windows and a fourth facilitator window if participants are available.

## Roles and separation of duties

| Participant | Conjur user | Baseline rights | Demonstration |
| --- | --- | --- | --- |
| Alice, security reviewer | `lab-alice` | Read metadata for payment, fraud, and canary variables; no secret-value retrieval | Review does not require possession of business secrets |
| Bob, payment operator | `lab-bob` | Read/retrieve/update the payment credential; no fraud access or policy administration | Approved business access is distinct from security administration |
| Eve, compromised contractor | `lab-eve` | Read/retrieve one synthetic canary | A valid credential is not authority to access everything |
| Facilitator | `admin` | Provisioning, explicit policy changes, containment and recovery | Changes to access remain a separate privileged responsibility |

Each actor runs in a fresh non-root container with **only that user's API key** and the trusted certificate. It has no admin key, runtime directory, other user's key, Docker socket, or host network. The Python runner suppresses secret values, response bodies, signatures and key fingerprints; an allowed read proves the value was retrieved, but does not print it. Facilitators and anyone with Docker/host access are trusted administrators: do not give participants unrestricted access to the host and then claim this is a hostile multi-tenant isolation boundary.

The same image runs all users to keep the exercise DRY. `ACTOR` is validated against the three allowed names before Compose is called. Login names are explicit root users, avoiding nested-user naming ambiguity.

## 1. Provision and establish the baseline

From the repository root or `conjur-sandbox-lab/`:

```bash
make up
make init
make exercise-init
make test-exercise
```

`exercise-init` loads `policy/04-human-exercise.yml`, privately captures the generated user API keys, seeds a random canary value, and **restores the baseline**. It is intentionally a reset command, not an innocent observation command: it restores Eve's canary membership and removes the intentional payment overgrant. Existing credentials and canary value are preserved. It does not rotate identities or revoke admin keys. Missing keys for existing users cause a recovery error instead of credential fabrication.

Baseline matrix acceptance uses real REST requests and fails on unexpected access, authentication failure, rate limiting, or outage. HTTP 403 or 404 is accepted as denied; servers can hide inaccessible resources as 404. Do not interpret a 401 or 503 as proof of least privilege.

## 2. Have legitimate users perform their jobs

Alice's terminal:

```bash
make act ACTOR=alice ACTION=metadata EXPECT=allow
make act ACTOR=alice ACTION=payment EXPECT=deny
make act ACTOR=alice ACTION=fraud EXPECT=deny
```

Bob's terminal:

```bash
make act ACTOR=bob ACTION=payment EXPECT=allow
make act ACTOR=bob ACTION=fraud EXPECT=deny
make act ACTOR=bob ACTION=escalate EXPECT=deny
```

Optional, approved maintenance demonstration:

```bash
make act ACTOR=bob ACTION=tamper EXPECT=allow
make rotate
make test-app
```

`tamper` posts a newly generated random payment value. For Bob this is an authorized update, not an exploit; for Eve it must be denied. It changes the real **synthetic lab** payment value. `make rotate` rotates both values and refreshes the public version marker afterward. The optional demo must never be run against real provider-backed credentials; this lab does not coordinate an external provider.

**Executive point:** Alice can review a resource without receiving its secret. Bob has task-specific access, not universal access or permission to change the security model.

## 3. Run Eve's bounded attack attempts

Eve's terminal:

```bash
make act ACTOR=eve ACTION=canary EXPECT=allow
make act ACTOR=eve ACTION=payment EXPECT=deny
make act ACTOR=eve ACTION=fraud EXPECT=deny
make act ACTOR=eve ACTION=tamper EXPECT=deny
make act ACTOR=eve ACTION=escalate EXPECT=deny
```

- `canary` reads a synthetic variable with no external validity. Its observation is tagged `canary_signal: true`. Eve is permitted to read it at baseline, so a read alone is **not proof of compromise**. Use context, such as subsequent denied business-secret attempts, to discuss false positives and detection.
- `payment` and `fraud` attempt secret-value retrieval, not a guessed filesystem path.
- `tamper` attempts an unauthorized secret update.
- `escalate` attempts to load a policy granting the current user checkout-readers membership. It must fail because Eve cannot create policy at root. An unexpected success is a real lab policy failure: stop, contain, inspect the grant, and rotate exposed values.

The terminal prints timestamped JSON events with actor, action, outcome and HTTP status. Denied probes are successful **exercise observations**, not shell failures; use `EXPECT=deny` to assert that denial is required. `EXPECT=allow` asserts allowed access. Omit `EXPECT` for exploratory observation.

**Executive point:** Authentication and authorization are separate controls. Credential theft must not imply unlimited lateral movement or administrative access.

## 4. Deliberately demonstrate a human policy mistake

Only the facilitator executes this explicitly approved change:

```bash
make exercise-expose CONFIRM=lab-only
```

This grants Eve membership in `lab/checkout-readers`, a **read-only** group. The resulting exposure is payment secret retrieval and the public version marker, not fraud access, secret updates, or policy administration. The existing checkout host remains a member. The file is isolated at `policy/exercise/expose.yml` and is never loaded by ordinary `make init`, `make policies`, or `make up`.

Eve's terminal:

```bash
make act ACTOR=eve ACTION=payment EXPECT=allow
make act ACTOR=eve ACTION=fraud EXPECT=deny
make act ACTOR=eve ACTION=tamper EXPECT=deny
make act ACTOR=eve ACTION=escalate EXPECT=deny
```

An allowed non-canary Eve read is emitted with `alert: true`. This is a client-side exercise flag, **not a deployed SIEM rule or a Conjur detection feature**.

**Executive point:** A secret manager cannot correct an administrator's intentional overgrant. The remaining boundaries still limit the blast radius; policy review, access recertification, and change approval matter.

## 5. Contain while Eve retains an issued token

In Eve's terminal, start a one-minute observation loop:

```bash
make act ACTOR=eve ACTION=watch-payment
```

This authenticates **once**, then makes 20 payment reads three seconds apart with the same in-memory token. It does not refresh the token mid-session. Wait for at least one `allowed` event.

In the facilitator's terminal, while the loop is still running:

```bash
make exercise-contain
```

Containment uses **PATCH with explicit `!revoke` statements**, removing Eve from checkout-readers and contractors. Observe subsequent reads in Eve's running loop: they should become denied without logging out or restarting Conjur. If they remain allowed, stop and investigate rather than claiming containment. The live server behavior is an acceptance test, not an offline test result.

Then check new requests:

```bash
make act ACTOR=eve ACTION=payment EXPECT=deny
make act ACTOR=eve ACTION=canary EXPECT=deny
make act ACTOR=bob ACTION=payment EXPECT=allow
make act ACTOR=alice ACTION=metadata EXPECT=allow
```

This is **authorization containment**, not deleting Eve, disabling authentication, rotating her API key, or invalidating all issued tokens. Eve can still authenticate; revoked group permissions should deny these resources. The retained-token loop demonstrates that distinction. It does not prove complete identity deprovisioning. Baseline users have no direct grant to Eve or policy ownership that would bypass these group revocations; arbitrary custom grants must be reviewed separately.

Removing a grant from an additive policy file is not enough. [CyberArk's revoke reference](https://docs.cyberark.com/conjur-open-source/latest/en/content/operations/policy/statement-ref-revoke.htm) requires PATCH mode for `!revoke`; the lab implements that explicitly.

## 6. Recover and prove business continuity

```bash
make exercise-recover
make act ACTOR=eve ACTION=payment EXPECT=deny
make act ACTOR=bob ACTION=payment EXPECT=allow
make test-app
make exercise-report
```

`exercise-recover` first reapplies containment and then rotates both workload values with the existing rotation utility. It does not rotate Eve's identity key. Rotating secrets without closing the access path would let an attacker simply read the replacements; that is why order matters. `make test-app` verifies workloads still function and observe another rotation without restarts. Rotation is not atomic across variables, and previously retrieved secrets cannot be "unread"; replace downstream provider credentials and investigate any actual exposure in a real incident.

To replay the exercise:

```bash
make exercise-reset
make test-exercise
```

Reset restores canary-only access for Eve and removes the payment overgrant. It deliberately reopens that limited baseline access; do not reset a real compromised user to access merely to make a test pass. Historical client observations are preserved until `make clean CONFIRM=destroy` or deliberate private archival/removal.

## Evidence and executive debrief

Host-side wrappers append secret-free observations to `.runtime/evidence/events.jsonl`. Actor containers cannot edit that file, but a trusted host operator can; compromised code could also emit false stdout. The summary tolerates interleaved/malformed lines and reports counts, observed exposures, and the latest observed exposure-to-containment-command interval. That interval is **not verified end-to-end MTTR**, an SLA, or proof that every token/resource was contained. Repeated runs accumulate observations, so keep your exercise start/end times.

These are **client observations, not authoritative server audit records**. Keep the files private until reviewed. Corroborate timestamps, actual Conjur principals (`lab-alice`, `lab-bob`, `lab-eve`), resources, results, policy changes and versions with your running server's audit output. For local inspection:

```bash
cd conjur-sandbox-lab   # omit if already here
docker compose logs --since 20m conjur
```

Inspect locally; do not publish raw logs or assume every service log is an audit event. Audit format/destination depends on the Conjur image/configuration. This lab does not provision a protected external audit collector or SIEM. Configure and validate that before using the demo as evidence of enterprise detection or compliance.

### Suggested one-page presentation

| Control | Observable evidence | Business interpretation |
| --- | --- | --- |
| Least privilege | Alice metadata succeeds; her secret retrieval fails | Review without secret custody |
| Segregation of duties | Bob payment access succeeds; policy escalation fails | Operators cannot authorize themselves |
| Credential compromise boundary | Eve authenticates, but business-secret probes fail | Stolen credential has limited initial impact |
| Misconfiguration risk | Explicit overgrant enables only payment read | Human policy errors remain a material risk |
| Containment | Retained-token reads transition to denied; Bob remains allowed | Close the access path while preserving approved work |
| Recovery | Rotate after containment; workload checks pass | Reduce exposure without service restarts |
| Evidence quality | Client records correlated with server audit records | Distinguish a convincing demonstration from defensible incident evidence |

Ask: Who approves access changes? Who owns the secret? Which downstream system must rotate after exposure? How do we revoke every access path? How do we protect audit records from an administrator? What is the detection latency, and who is paged? These questions are more useful to a CISO/ISSO than claiming the attacker is "blocked" solely because one request returned 403.

## Verification status

Offline unit tests cover scoped requests, secret-free output, expected outcomes, outage handling, explicit exposure confirmation, containment-before-rotation, preserved user keys, evidence summaries and token reuse. Docker/Conjur integration is still unverified in the authoring environment. Run the walkthrough against the local stack and inspect the retained-token behavior before presenting its outcomes as confirmed.
