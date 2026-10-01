# Development handoff

Read `conjur-sandbox-lab/docs/development.md` before changing the lab. The project is an educational Conjur OSS sandbox, not an HA production or compliance-certified deployment.

For `okta-iam-suite/`, also read `okta-iam-suite/docs/development.md` and its setup guide. Use a dedicated Integrator Free Plan org and only registered synthetic actors; never mutate external identities or assume paid features. Run `make okta-setup && make okta-test` for its separate dependency/test environment. Live sign-in, MFA and lifecycle claims require an authorized configured Okta tenant. Local containment/JIT are lab mechanisms, not Okta PAM/Identity Governance.

For `conjur-agent-identity/`, read its `docs/development.md` and research/translation boundaries. Use the real pinned Cedar engine; never treat untrusted prompts as identity, policy or delegated authority. Preserve signature/holder/chain attenuation, ancestor budgets, replay and revocation checks. Agents must never receive Conjur tool secrets. Synthetic demos and finite reference-model equivalence are not live Conjur, model robustness, full MAML equivalence, human-authenticated consent or production claims.

- Keep all actual credentials and private evidence out of source control. `.runtime/` and `.env` are ignored; policies contain declarations only. Never print keys, tokens, message bodies, private runtime state, or unredacted server logs.
- Root Make targets delegate to `conjur-sandbox-lab/`. Run `make test` for offline unit tests and Bash syntax. Docker is required for live acceptance; offline mocks never establish real Conjur policy or container behavior.
- Preserve existing accounts, API keys, secret values, policy grants, and database volume unless a command explicitly documents its mutation. Additive POST does not revoke grants: use reviewed explicit PATCH deletion statements.
- Message API scope is fixed by deployment configuration. Never accept a tenant/environment selected by an unauthenticated body/header. Each API and sender has a distinct host identity; do not share tenant keys or inherit business permissions broadly.
- Ordinary initialization must not enable the human exercise's intentional overgrant. Keep actor containers isolated from admin runtime and other keys.
- For tenant changes update policies, config, Compose scopes/secrets/networks, gateway routes, message validation, sender choices, tests, and documentation together. The four scopes are intentionally explicit, not dynamically provisioned untrusted input.
- Preserve non-root/read-only/capability-drop/no-new-privileges/resource limits on message backends. No privileged containers or Docker socket mounts for exercises. Use harmless probes; do not add kernel exploits or resource exhaustion.
- Document verified checks and remaining limitations accurately. Container runtime, TLS, real RBAC, retained-token containment, and curl acceptance require fresh live evidence before claiming success. Never bypass certificate validation.
