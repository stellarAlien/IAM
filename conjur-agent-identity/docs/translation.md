# Conjur tagged-YAML to Cedar translation

This module is a research prototype for a **restricted flat subset** of Conjur policy YAML. It is not a Conjur policy loader, MAML interpreter, or a claim that full Conjur authorization semantics are preserved. Conjur's account, policy namespaces, implicit ownership, annotations, policy nesting, and lifecycle mutations are outside this model.

## Supported source form

Input is one YAML document containing at most 100 flat statements (64 KiB, maximum AST depth 16, no aliases):

- Declarations: `!user`, `!host`, `!group`, `!layer`, and `!variable`, each with only a string `id` field.
- `!grant` has `role` (a group or layer reference) and exactly one of `member` or non-empty `members` (user, host, group, or layer references).
- `!permit` has `role` (user, host, group, or layer), a non-empty `privileges` list containing only `read` and/or `execute`, and exactly one of `resource` or non-empty `resources` (variable references).
- IDs are safe slash-separated paths made from ASCII letters, digits, `_`, and `-`. A leading slash on a reference is normalized away. Declaration IDs are relative to their resource kind; for example, `!host` with `id: payments-agent` is addressed by the API as `host/payments-agent`.

Unknown fields, duplicate IDs/keys, missing references, cross-account syntax, cycles, aliases, multiple documents, nested policy, owners/annotations, denies/revokes, other privilege names, and all other tags or shapes are rejected with the same generic error. Empty or undeclared permissions do not create access.

## API and model

`compile(text)` returns `{ policies, entities, schema, model }`. The first three fields are Cedar JSON consumed by the official `@cedar-policy/cedar-wasm` 4.13.0 Node API: `policies.staticPolicies`, Cedar `entities`, and the Cedar `schema`. All Conjur user/host/group/layer identities map to Cedar `Role`; variables map to `Variable`; actions are `Action::read` and `Action::execute`. Grants become entity parent relationships (including transitive group/layer membership). Each permit becomes a typed static Cedar permit policy. The translator validates the schema, entity set, and policies with Cedar WASM and rejects validation errors.

The `model` field is the finite reference evaluator's input: canonical actor IDs, variable IDs, direct parent links, and permit tuples. `referenceDecision(compiled, principal, action, resource)` evaluates those tuples with transitive membership. `authorizeCompiled(...)` makes a separate call to Cedar WASM; it returns `true` only for an allow decision with no Cedar diagnostics errors, and returns `false` for unknown inputs or evaluator failures. Both decision functions take canonical IDs such as `host/payments-agent` and `variable/payments/db/credentials`, and action names `read` or `execute`.

## Verification and limits

`npm test` runs the finite declared-principal × supported-action × declared-variable differential matrix against real Cedar WASM, plus expected allow/deny examples and malformed-input rejection cases. This demonstrates parity only for the modeled fixture and the supported subset. It does not prove behavior against a running Conjur server or cover full MAML, account scoping, owner permissions, policy updates/deletes, or other Conjur privileges.
