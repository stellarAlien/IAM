# Research ground: agent authorization and Conjur → Cedar

## Verified references

- Surapani et al., [Authorization Architectures for Tool-Using AI Agents](https://arxiv.org/abs/2609.15906), arXiv:2609.15906, submitted **14 September 2026**. A review/preprint addressing identity, delegation, multi-hop scope propagation, runtime enforcement, prompt injection, and provenance. It is not a Conjur integration specification.
- Madhira, [Digital Identity for Agentic Systems: Toward a Portable Authorization Standard for Autonomous Agents](https://arxiv.org/abs/2605.11487), arXiv:2605.11487, **May 2026**. Describes issuer-authored authorization payloads, typed constraints, attenuation, fail-closed processing and pre-flight discovery. The lab borrows these design concerns; it does not claim to implement a finalized standard or satisfy every proposed semantic rule.
- [Cedar source and official WASM bindings](https://github.com/cedar-policy/cedar/tree/main/cedar-wasm), pinned SDK **4.13.0**, with schema validation and actual Rust-engine evaluation.
- [Cedar policy validation](https://docs.cedarpolicy.com/policies/validation.html): schema validation catches policy/type errors; validation is not proof that application-provided identity/context is trustworthy.
- [Conjur policy load modes](https://docs.cyberark.com/conjur-open-source/latest/en/content/operations/policy/policy-load.html): additive and deletion/replacement semantics matter when comparing languages.

Preprints are a research starting point, not peer-reviewed assurance or production standards. Exact implementation choices and deviations are documented below.

## What the runnable lab investigates

### RQ1: Can delegation stay attenuated over multiple hops?

The authority signs explicit constraints; child grants may only take a subset of tools, preserve action/tenant/environment, reduce per-call record and call-count bounds, and shorten lifetime. The PEP verifies **every** signed ancestor and child relation, not just the last JWT. Holder proofs prevent a stolen grant from acting without the subject's pinned private key.

Evidence: signed-parent substitution/reordering/tampering tests, typed-bound amplification tests, holder-key mismatch, expiry, proof binding/replay, cycle rejection and ancestor revocation. Limitation: one local issuer, fixed identity registry, no federation/trust-resolution protocol. Human approval is represented by the trusted facilitator CLI, not an independently verifiable human signature. A compromised issuer can sign arbitrary roots; Cedar and Conjur supply further independent bounds but do not repair issuer trust.

### RQ2: Can aggregate constraints survive branching delegation?

Each admitted call consumes one counter in **all grant IDs in the chain**. Different children share the root counter. Reservations are persisted under a local lock before credential retrieval. Failed downstream attempts do not refund budget. Parallel-call tests demonstrate the root count cannot be raced inside this gateway.

This bounds **call counts**, not aggregate payment amount, total rows across independent root grants, billing, data disclosure, tokens issued by another authority, or external action volume. `maxRecords` is per call. A human can intentionally approve another root grant; global principal-level quotas and distributed reservations are separate research work.

### RQ3: Can prompt injection bypass the tool PEP?

Untrusted text is a plan proposal only. The gateway accepts a tiny typed body and does not treat a statement such as "the human approved admin" as a principal, signed grant, trusted group, URL, secret ID or policy. Synthetic admin/undelegated-tool proposals are denied before secret retrieval.

This establishes specified authorization invariants, **not prompt-injection immunity**. A compromised agent may misuse actions that are legitimately within its delegation. A tool result may contain attacker-controlled data; connector-specific constraints, output handling, task intent/approval and human review remain necessary. No LLM evaluation or MCP protocol exploit is implemented.

### RQ4: Can Conjur RBAC be translated while preserving decisions?

The compiler deliberately models a **closed flat role graph**: declared user/host subjects, group/layer ancestor roles, declared variables, and `read`/`execute` permits. It outputs Cedar membership entities and permit policies, validates the schema and compares the real engine with a separate reference evaluator across the fixture decision matrix.

The claim is finite **reference-model equivalence**, not full Conjur equivalence. In particular:

- Conjur account administrators and implicit ownership can authorize actions absent from explicit permits; the model excludes owner/admin principals and cannot infer those semantics from a flat fixture.
- Nested policy namespaces/relative paths and inherited ownership must be resolved using the real Conjur model, not string heuristics.
- Conjur `!deny` removes a permission in a mutation context; it must not automatically become a globally overriding Cedar `forbid`. Similarly, PATCH `!revoke` changes graph state, not a static runtime deny rule.
- Authentication/network restrictions, role ownership, host factories, authenticators, templates and lifecycle are not merely Cedar permit predicates.
- Conjur `read` metadata access and `execute` value retrieval remain separate actions. Mapping both to an abstract `read` would destroy semantics.
- Cedar runtime diagnostics normally affect the policies they occur in; this gateway adds an **any-diagnostic-error → fail-closed** rule. That is a deliberate enforcement profile, not a universal statement about Cedar's native decision semantics.

## A defensible next research milestone

1. Specify the source decision relation and supported principal domain formally, including account and implicit owner cases.
2. Build generated fixtures for the restricted source language, keeping unsupported syntax rejection explicit.
3. Load each fixture into an isolated **real Conjur** account and collect `read` metadata and `execute` value-access outcomes with independent identities.
4. Compare those outcomes with compiled Cedar decisions and minimize counterexamples. Do not test using the account admin for every request.
5. Expand one semantic feature at a time (namespaces, owner permissions, stateful PATCH changes) with new proof obligations and counterexamples.
6. Use Cedar's analysis tooling/formal methods for specified translations where available, but do not mistake schema validation or exhaustive testing of a finite fixture for a universal proof.

These steps are research ground, not an implemented generator, proof assistant, SMT proof or live differential harness. Add them under a separate scoped task with actual Conjur evidence.
