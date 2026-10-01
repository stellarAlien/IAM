# Conjur Agent Identity & Delegation + Cedar research lab

A separate, runnable **agent-to-tool authorization** lab: signed identity-bound delegation, typed attenuation, short-lived proof-of-possession, a policy enforcement point (PEP), real Cedar authorization, Conjur-managed tool secrets and auditable provenance.

This is an **application-layer extension prototype**, not a Conjur server fork, a native Conjur plugin, a production security boundary or a standardized portable-authorization implementation. Conjur remains the independent secret/RBAC system; the gateway enforces delegated tool authority **before** retrieving a credential. Neither Conjur nor Cedar automatically interprets an agent's prompts.

## Run the complete offline demo

Requires Node **22+**, npm, GNU Make. No API key, LLM provider, Rust toolchain, AWS account, Stripe account or Docker is needed for this path.

```bash
cd conjur-agent-identity
make setup
make validate
make test
make demo
make test-translation
```

`setup` installs pinned dependencies with `npm ci --ignore-scripts`. Cedar is the **official 4.13.0 Rust engine compiled to WebAssembly**, not a handwritten imitation. JWT/JWS signing uses the maintained `jose` library with Ed25519 keys. All actual keys are runtime-generated; declarations/IDs are not secrets.

The deterministic demo creates an isolated private temporary runtime, uses fresh **synthetic in-memory credentials**, invokes the real Cedar engine and removes the temporary runtime afterward. It shows:

1. Human approval → primary agent → narrower sub-agent → payment tool.
2. Advisory pre-flight discovery with no secret retrieval or budget consumption.
3. An untrusted tool-output fixture proposing production-admin access is denied.
4. Undelegated tools and record-bound amplification are denied.
5. Proof replay and aggregate-call-budget excess are denied.
6. Revoking the ancestor grant denies an already-issued descendant grant.
7. Linked audit records verify and only authorized synthetic credentials are retrieved.

This demonstrates the authorization result of an injected **plan proposal**; it does not run an LLM, simulate every prompt-injection vector, evaluate model robustness, or contact real external tools. The model may propose any action: the PEP, rather than natural-language obedience, decides whether it can run.

## Architecture

```text
lab human approval (trusted facilitator/issuer CLI)
       │ root grant: agent + tool/action/scope/time/record/call bounds
       ▼
primary agent (own Ed25519 holder key; no Conjur key)
       │ signed request to issuer; only attenuation accepted
       ▼
sub-agent (separate holder key + full linked grant chain)
       │ 30-second signed proof bound to method/path/body/chain
       ▼
tool gateway PEP ── verify issuer, full chain, holder, constraints, revocation
       │           └── Cedar PDP: team/tenant/environment/tool policy
       │           └── reserve nonce + every ancestor's aggregate call budget
       ▼
tool-specific Conjur host ── HTTPS authenticate/retrieve own credential
       │ recheck expiry/revocation after retrieval
       ▼
synthetic connector effect ── safe result only, never credential value
```

Registry-defined tools are `payment-db`, `stripe-reconcile` and a **blocked** `production-admin` resource. The latter has no usable Conjur host/secret mapping. The two usable tool hosts can read only their individual **dev** credential. No agent host, agent key or grant can directly authenticate to Conjur in this design. The gateway is a trusted secret broker containing multiple **distinct** tool identities, not an agent with a global secret-reader key.

The trusted registry pins agent attributes and holder public keys; request text cannot supply a team, tenant, environment, issuer, audience, custom tool URL, SQL query, target secret ID or replacement key. The tool request body is exactly `{ "tool": "payment-db", "records": 1 }`. Agents receive constrained invocation authority, not `AWS_SECRET_ACCESS_KEY` or a Stripe key.

## Delegation contract

Each signed grant includes a fixed issuer/audience/type/version, approved human, agent subject, unique grant ID, issue/not-before/expiry times, depth, parent-token SHA-256 link and typed constraints. Root TTL is at most **300 seconds**; the CLI demo uses 120 seconds. Child expiry cannot exceed the parent, and its issuer-generated time cannot precede the parent.

Constraints are explicit, exact fields:

```json
{
  "tools": ["payment-db", "stripe-reconcile"],
  "action": "read",
  "tenant": "acme",
  "environment": "dev",
  "maxRecords": 5,
  "maxCalls": 4
}
```

Unknown fields/types/actions/scopes fail closed. Delegation can remove tools and lower record/call limits; it cannot increase privilege, switch tenant/environment, create cycles or exceed two delegation hops. Every ancestor signature, parent link, issuer, audience, expiry and attenuation relation is verified on each invocation.

Holder proofs bind the entire chain hash, body hash, method and endpoint. A stolen grant alone is insufficient without the leaf holder's private key. Proofs expire within **30 seconds**. Invocation proof nonces and counters are stored privately and survive gateway restarts. Each admitted invocation consumes **one call in every ancestor grant**; creating several children cannot multiply the root budget. `maxRecords` is per invocation, not an aggregate record/billing limit. Downstream failures do not refund reserved budgets.

Child issuance requires a proof verified with the parent holder's **pinned** public key. The in-process issuer rejects reused delegation proofs; CLI-issued proof usage is privately persisted under an issuer-operation lock. This lab has one issuer and no public delegation endpoint. Its root human identity is **represented by the authorized facilitator**, not cryptographically authenticated with Okta or a human hardware key. Treat the issuer CLI/operator as the trust boundary; the `human` string is provenance recorded by that trusted issuer, not independent proof of human consent.

See [security-exercises.md](docs/security-exercises.md) for the acceptance walkthrough and [development.md](docs/development.md) for future runs.

## Live Conjur path (separate acceptance)

First bring up the existing sandbox. These commands add only the separate `agent-lab` branch, preserve existing accounts/keys/values/grants, and do not enable the human exercise's intentional overgrant:

```bash
# Repository root:
make up
make init

cd conjur-agent-identity
make setup
make init
make conjur-init CONFIRM=lab-only
cp config/conjur.example.json config/local.json
# Check account, TLS origin/port and CA path in ignored config/local.json.
make test-conjur
```

The additive policy declares two distinct tool hosts, their two dev credentials, and a synthetic prod-admin variable with **no tool permit**. The admin manager captures new host keys into `.runtime/tool-keys/` without printing them. Existing missing keys cause a restore error; they are not rotated silently. It uses the existing sandbox's private admin runtime only in its trusted ephemeral manager, not in the agent or gateway.

Run two terminals **inside this folder**:

```bash
# Terminal 1: real Conjur-backed gateway, loopback only
make serve

# Terminal 2: trusted facilitator/agent CLI
make grant
make delegate
make discover
make invoke TOOL=payment-db RECORDS=2
make invoke TOOL=production-admin RECORDS=1    # Expected denial, nonzero
make revoke
make invoke TOOL=payment-db RECORDS=1          # Retained child chain must now fail
make audit
```

The CLI signs requests and sends the envelope to `http://127.0.0.1:8092`; it never prints grant tokens or holder proofs. The server reads only public authority/holder keys, enforcement/audit state and per-tool Conjur keys. It does not load the authority signing key or agent private keys. On a single host the **filesystem administrator can access all private files**; real deployments must separate issuer, agent and gateway runtimes with independent secret/key isolation. Loopback HTTP is a lab transport, not remote TLS/mTLS.

Live connectors remain **synthetic**: they retrieve and internally consume Conjur credentials, process a bounded record count and return only safe status/correlation fields. They do not execute SQL, call Stripe, modify GitHub, access AWS or implement MCP protocol transport. Adding a real connector requires fixed target allowlists, downstream authorization, idempotency/transaction semantics, tool-specific action constraints and live acceptance. Never accept arbitrary URLs/queries/shell commands from a model.

## Cedar authorization and translation experiment

`policies/agents.cedar` + `policies/schema.json` validate at startup. Cedar permits in-scope read actions for registered matching-team agents with valid delegated context, and explicitly forbids blocked/prod/cross-scope resources. Any engine parse/validation/decision diagnostic error is treated as a denial, even if Cedar could otherwise return allow from another policy.

The **separate translator** compiles a restricted flat Conjur-tagged YAML fixture into Cedar entities/policies and compares actual Cedar decisions to an independent finite role-closure reference evaluator:

```bash
make translate
make test-translation
```

Supported: user/host/group/layer/variable declarations, acyclic role grants, and variable `read`/`execute` permits. Unsupported: nested policy namespaces, account/implicit owner semantics, mutation/deletion/deny statements, authenticator/network constraints, arbitrary metadata and other privileges. Unsupported input is rejected rather than approximated.

This is **not a proof of full Conjur/MAML equivalence** and not yet a differential comparison against a live Conjur server. The fixture's finite-model equivalence is evidence for a precisely bounded subset. See [translation.md](docs/translation.md) for the exact model and [research.md](docs/research.md) for the research questions and limitations. The human/agent grant format is a lab profile, not compliance with an arXiv proposal or an interoperability standard.

## Audit and failure semantics

Local JSONL records link previous-record and current-record hashes, correlation IDs, verified human/agent/grant chain, Cedar policy reasons and safe outcomes. Tokens, proofs, credentials, prompt contents, messages and key fingerprints are never written to them. Admission, reserved-budget, connector completion and failures are distinct events. Requests that cannot establish a trusted chain/holder are not attributed as a verified agent action.

The chain detects edits against a retained trusted anchor, but **does not prove non-repudiation, independent human approval or immunity to rewriting/truncating the entire file**. No external collector or checkpoint is implemented. A trusted administrator can rewrite both log and local state. Export/checkpoint events into independently protected storage for production evidence.

State and audit locking/atomic replacement are local single-host mechanisms. Stale locks after a crash fail closed; inspect active processes before removing them. Missing existing enforcement state is not silently reset by initialization. Budget reservation happens before credential retrieval; revocation/expiry is rechecked after asynchronous retrieval before the connector effect. Revocation cannot recall a credential already fetched or cancel an external side effect already underway.

## Verification record

The real Cedar engine, signed delegation, proof/chain binding, attenuation, replay, shared-budget concurrency, stale-token revocation, secret-output absence, policy validation and translation matrix are tested offline. The synthetic CLI demo and HTTP gateway are also exercised locally. Live Conjur policy/TLS/host behavior remains unverified without Docker. No model robustness benchmark, live MCP/SQL/Stripe/GitHub/cloud operation, formal proof or full MAML translation is claimed.

All actual runtime secrets, grants, private state and local config are ignored. `npm audit` reported no known dependency vulnerabilities when installed; that is a point-in-time registry result, not a guarantee of vulnerability freedom.
