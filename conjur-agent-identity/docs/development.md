# Agent identity and Cedar development handoff

Read root `AGENTS.md`, the Conjur development handoff and this document before editing. This is a **separate application-layer agent authorization/research prototype**, not a Conjur/Cedar plugin, production connector, portable-authorization standard or formally proven MAML translator.

## Source map

| Surface | Files | Invariants |
| --- | --- | --- |
| Trusted identity/tool registry | `config/registry.json` | Agent team/tenant/environment and fixed tool IDs/host/secret mappings are trusted deployment data |
| Grant/proof cryptography | `src/delegation.mjs` | Ed25519/JWS, issuer/audience/type/version, all ancestor signatures/links, exact typed attenuation, holder-key pinning |
| PEP | `src/gateway.mjs` | Narrow tool request, current revocation, Cedar decision, before-fetch reservation, post-fetch expiry/revocation check, no secret output |
| Cedar PDP | `src/cedar.mjs`, `policies/` | Real official engine, strict schema validation, any diagnostic error fails closed, attributes from trusted registry |
| Local state/evidence | `src/storage.mjs` | Private atomic writes, locks, persistent replay/ancestor counters/revocation, linked but not externally anchored audit |
| Conjur retrieval | `src/conjur.mjs`, `policy/conjur-tools.yml`, `scripts/` | Distinct per-tool hosts, TLS verified, own credential only, no admin tool mapping, no returned secret |
| Runtime/CLI | `src/runtime.mjs`, `src/cli.mjs` | Issuer and holder private keys loaded only by trusted CLI; gateway reads public keys/tool keys; demo uses isolated temporary synthetic runtime |
| Translation research | `src/translation.mjs`, `fixtures/conjur-subset.yml`, `tests/translation.test.mjs` | Reject unsupported constructs; finite reference model versus actual Cedar, not full Conjur equivalence |

## Commands and mutations

- `make setup`: pinned `npm ci --ignore-scripts`; official Cedar WASM 4.13.0 + jose + patched YAML dependency. Commit package-lock when dependencies change. No Rust compiler is needed.
- `make test`, `make validate`, `make test-translation`: offline actual-engine/security tests; no live Conjur behavior implied.
- `make demo`: isolated private temporary keys, state/audit and synthetic random credentials, no LLM or external side effects; removes its temporary directory afterward.
- `make init`: creates missing initial authority/holder keys and state. Existing keys are preserved; partial key pairs or missing existing enforcement state require restore, not reset.
- `make grant`: trusted operator approves a root for the registered human/primary agent, saves private chain, 120-second CLI TTL and four-call budget. It is not a real human SSO/signature event.
- `make delegate`: signs parent-holder proof and creates a narrower payment-only child, up to 60 seconds/two calls/two records. Parent expiry bounds child. CLI issuer proof usage is persisted privately.
- `make discover`: signed advisory authorization request; no reservation/secret read, no permission promise for a future call.
- `make invoke`: signed invocation through loopback HTTP; gateway rechecks every authorization layer and returns safe synthetic outcome.
- `make revoke`: explicitly revokes the root grant so future descendant admissions fail. Does not rotate holder or Conjur keys, cancel completed effects or disable human identity.
- `make audit`: validates local hash linkage only, not non-repudiation/independent anchoring/complete history.
- `make translate`: compiles restricted fixture, saves private `.runtime/translated.json`; never loads translated policy into Conjur.
- `make conjur-init CONFIRM=lab-only`: additive `agent-lab` branch/new tool host keys/initial credential seeding through existing trusted sandbox manager. Preserves existing values; missing existing keys fail.
- `make test-conjur`: actual own-read and cross-tool/admin-denial checks with distinct host identities. Needs configured TLS/local Conjur.

Root `agent-setup`, `agent-test`, `agent-demo` targets delegate here. Always execute direct folder CLI commands with this folder as CWD so policy/config/runtime paths resolve correctly.

## Security constraints for future changes

1. Keep authority, holder and Conjur tool keys distinct. Never send any secret to model context, a token response, audit output or a prompt. The gateway loads no issuer/holder private keys.
2. Root human provenance currently comes from a trusted facilitator/issuer operator. Do not call it human-authenticated consent without adding and verifying an actual human authentication/signature mechanism.
3. Verify every signed chain node, parent hash, lifetime, typed relation and holder proof. A chain embedded in JSON is not trusted just because the leaf looks valid.
4. Proofs bind method/path/body/entire chain, use pinned holder public keys, and have ≤30-second lifetimes. Never accept a caller-supplied replacement JWK or skip proof checks for "internal" requests.
5. Children cannot increase tools/action/tenant/environment/time/records/calls. Reject unknown/malformed constraint fields and unsupported semantics rather than treating them as advice.
6. Call budgets are shared through **all ancestors**; reserve atomically before secret retrieval. Downstream failure does not refund. Per-call records are not an aggregate row, payment or billing limit.
7. Runtime state/counters persist across restart. Do not delete/reset them to fix a denial or generate new keys over existing accounts without reviewed authorization. File locks are local only; stale lock removal requires checking processes first.
8. Audit records contain only safe correlation/identity/grant IDs, policy IDs and outcomes. Unverified caller data must not appear as verified actor provenance. Fail on audit corruption/unavailability rather than run without evidence.
9. Preflight discovery is advisory; invocation must reauthorize. Recheck lifetime/revocation after async credential retrieval and before the connector effect. In-flight external effects need their own cancellation/idempotency design.
10. Fixed tool mappings are trusted code/config. Do not accept SQL, shell commands, target URLs, secret IDs or environment/team fields from model output. Currently both connectors are synthetic; real tools are a new scoped task.
11. Keep production-admin blocked in Cedar, undelegatable in grant types and unmapped in broker config. Conjur tool hosts have no prod-admin permit. Layered denial is intentional.
12. Translation code is separate from runtime agent policy. Do not reuse a subset compiler as a general Conjur loader or silently map source constructs to permissive approximations.

## Verification

```bash
make setup
make validate
make test
make demo
make test-translation
npm audit
node --check src/cli.mjs
git diff --check
```

Root Conjur and Okta regression checks remain `make test` and `make okta-test` respectively. ShellCheck can lint `scripts/conjur-init.sh` with the existing Conjur common include. Policy YAML uses Conjur tags; generic parsing only checks syntax, not live server authorization semantics.

The security tests must cover chain tampering, amplification, holder mismatch, expired grants/proofs, replay, root budget shared by children, parallel reservations, preflight revocation, secret-output absence, state/audit failure, scope/admin denial, and actual Cedar validation/decisions. Translation tests compare the supported fixture matrix with a reference role-closure evaluator; reject alias/deep/duplicate/unsupported/mutation/owner/nested policy inputs.

Implementation verification passed pinned `npm ci`, strict Cedar validation, 37 agent/research tests, the synthetic end-to-end demo, ShellCheck, Python provisioning compilation and diff checks. The finite translator fixture covers 18 declared principal/action/resource combinations against the real Cedar engine. The existing 66 Conjur and 46 Okta tests also passed. Dependency audit reported no known advisories at that point. These are offline/local results; no live Conjur or LLM was involved.

## Remaining limitations

- Live Conjur bootstrap/RBAC/TLS remains unverified in the current environment without Docker. Do not convert synthetic demo output into a live Conjur claim.
- No real MCP transport, SQL, Stripe/GitHub/cloud API, LLM, Okta-to-agent consent integration, human signature, attestation, distributed issuer or interoperable portable grant profile is supplied.
- All private files coexist on the trusted development host. Host/Docker administrators can read them. Production needs separate runtimes, key stores and authenticated TLS channels.
- Loopback HTTP/Node demo server is not remote mTLS or a hardened production service. Request concurrency/body/time are bounded, but protected egress/remote deployment is not provisioned.
- Local counters/revocations/proof history and audit grow for the small lab workload; no multi-host coordination, TTL compaction, high-volume log collection or quota service is implemented.
- Local hash linking detects changes relative to a retained anchor, not full-history rewriting/truncation by an administrator. No externally protected checkpoint or human non-repudiation claim.
- The compiler excludes account/implicit owner semantics and many MAML features. Finite reference equivalence is not real-server equivalence or a universal formal proof; see research/translation docs.

Runbooks: [README](../README.md), [security exercises](security-exercises.md), [research ground](research.md), [restricted translation](translation.md).
