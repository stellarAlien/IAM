# Manual agent identity and delegation exercises

Use synthetic data only. The agent authority/gateway CLI is a **trusted local operator interface**, not a hostile multi-tenant shell. Anyone with full access to `.runtime/` can read issuer and holder private keys. Do not present the single-host folder as hardware-backed identity isolation.

## Offline, reproducible demonstration

```bash
cd conjur-agent-identity
make setup
make validate
make test
make demo
make test-translation
```

The demo uses real Cedar and real cryptographic signatures with synthetic connector credentials; no Conjur server or LLM is involved. Tests also start a loopback HTTP PEP and submit proof-bound valid/invalid requests. Keep the output distinction visible in presentations.

## Live Conjur acceptance

Follow the README's base setup and additive `make conjur-init CONFIRM=lab-only`, then run `make test-conjur`. That test authenticates separately as each tool host, reads its own credential, and asserts denial for the other tool's credential and the declared prod-admin credential. A 401, TLS failure, timeout or 503 is not counted as successful RBAC denial; only a 403/404 is.

Terminal 1:

```bash
make serve
```

Terminal 2:

```bash
make grant
make delegate
make discover TOOL=payment-db RECORDS=2
make invoke TOOL=payment-db RECORDS=2
make invoke TOOL=stripe-reconcile RECORDS=1
make invoke TOOL=production-admin RECORDS=1
make invoke TOOL=payment-db RECORDS=3
make invoke TOOL=payment-db RECORDS=1
make invoke TOOL=payment-db RECORDS=1
make revoke
make invoke TOOL=payment-db RECORDS=1
make audit
```

Expected:

| Step | Outcome |
| --- | --- |
| Root/child issuance | Private files; no tokens in output |
| Discovery | Eligible now; advisory; no Conjur credential read or counter increment |
| First payment call | Completed synthetic effect; no credential/HMAC/records returned |
| Stripe via payment-only child | Denied: outside delegated tools |
| Admin proposal | Denied; no host/secret mapping exists for admin |
| Three records via max-two child | Denied |
| Second payment call | Completed |
| Third admitted child call | Denied by child call budget |
| Revoked root's retained child | Denied by ancestor revocation |
| Audit check | Local hash linkage verifies, subject to documented anchoring limitations |

The child expires at most 60 seconds after issuance, and cannot outlive its root. Perform the steps promptly. An expiration denial is not proof of budget/revocation behavior; inspect the specific safe error code. Issue a fresh human-approved root only deliberately; it represents new authority and resets that root's call budget, not the old grant's state.

`make discover` is not a reservation or reusable permit. Invoke reevaluates current signatures, constraints, revocation, Cedar policy and counters. The tests cover revocation between discovery and execution, so stale discovery cannot grant authority.

## Prompt injection exercise

Read `fixtures/prompt-injection.txt`: an untrusted tool output claims blanket human approval and asks for prod-admin access. It is never loaded into policy, identity attributes or grant claims. The deterministic demo converts the proposal into an admin-tool request and observes rejection.

In a future LLM integration, parse a proposed tool call into the same narrow schema and route it through the PEP. Never place authority keys/Conjur credentials in model context; never let a model supply public-key registries, policy files, issuer claims, arbitrary tool URLs or secret IDs. A prompt saying "ignore the guard" cannot mint a signature. A compromised holder can still misuse its legitimately authorized payment read operations; use finer action/task/approval constraints for consequential real tools.

## Identity theft and chain integrity

The automated tests demonstrate stolen-token-without-holder-key rejection, wrong-holder-key rejection, body/path/chain substitution, expired grants/proofs, and replay. Public API requests without signed proof are denied. The request proof is bound to `/tools/invoke` versus `/authorization/discover`; discovery proof reuse cannot invoke a tool.

Holder keys are distinct from Conjur host keys. Stealing a broker's Conjur host key bypasses this application PEP and permits that host's legitimate secret reads directly at Conjur. Protect the broker runtime as a separate trust boundary and keep its per-tool grants narrow. The lab does not provide attestation, hardware-backed keys or service-mesh authentication.

## Audit and containment

Audit records distinguish issuance, advisory authorization, budget reservation, completion and failure. Correlation/grant IDs link the chain without persisting bearer material. Unknown/unverified callers get safe unattributed failures rather than falsely asserted verified identities.

Revoke ancestors to close **future admission** for all descendants. The gateway rereads revocation state on every call and rechecks after asynchronous secret retrieval. Revocation cannot erase secrets already fetched by a trusted broker or undo a side effect already sent to an external provider. The synthetic connectors have no external effects; production connectors need transactional/idempotent behavior and provider-side revocation design.

The local audit hash chain detects edits relative to a trusted tail/anchor but cannot stop an administrator from replacing/truncating the entire file. There is no independently stored checkpoint, signature by the human or external collector. Do not claim non-repudiation or incident-proof evidence from `make audit` alone.

## CISO/ISSO debrief

- **Who acts?** Distinct registered agent identity, bound holder key and tool identity—not a shared environment secret.
- **Who approved?** Trusted issuer records the lab human; real human SSO/signature integration is a promotion requirement.
- **What was delegated?** Tool/action/tenant/environment, lifetime, per-call record limit and aggregate call count.
- **Can a sub-agent amplify authority?** Verified attenuation and shared ancestor counters constrain it.
- **Can an injected instruction bypass control?** It may propose a call but cannot alter issuer, policy or proof.
- **What happens during outage?** Missing/corrupt state, issuer/holder failure, Cedar diagnostics, unavailable Conjur or audit failure deny/fail the call.
- **What survives compromise?** A compromised authorized agent retains its in-scope capabilities; a compromised broker or issuer is a stronger trust failure.
- **What is proven?** Tests establish declared invariants and fixture-model equivalence—not complete prompt safety, full MAML semantics or production readiness.
