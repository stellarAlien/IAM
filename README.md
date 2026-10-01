# Conjur Sandbox Lab

A modular CyberArk Conjur OSS lab demonstrating a payment checkout and a fraud-scoring service with separate identities, TLS, runtime-generated credentials, least-privilege policies, and live secret rotation.

```bash
make up
make init
make test-app
```

See [the complete lab guide](conjur-sandbox-lab/README.md) for prerequisites, architecture, recovery, security boundaries, and all commands. The self-contained project is in `conjur-sandbox-lab/`; root Make targets delegate there. The root Compose file includes the same stack, not a second installation.

Use Make for lifecycle operations. If invoking Compose directly from the root after customizing the lab's `.env`, pass `--env-file conjur-sandbox-lab/.env` so the project name and configuration stay consistent.

This is a hardened **sandbox**, not an HA production Conjur deployment. No credentials are checked in. `make test` runs offline unit tests without Docker.

For a hands-on security presentation, follow [the compromised-contractor exercise](conjur-sandbox-lab/docs/security-exercise.md): three human roles, a constrained attacker, intentional policy overgrant, containment with a retained token, and an executive evidence debrief.

The [zero-trust/multi-tenant runbook](conjur-sandbox-lab/docs/zero-trust-multitenancy.md) adds four tenant/environment message APIs with scoped RBAC and curl POST examples. The [container exercise](conjur-sandbox-lab/docs/container-security.md) verifies effective hardening with harmless probes. Subsequent development runs should start with [the development handoff](conjur-sandbox-lab/docs/development.md) and `AGENTS.md`.

The independent [Okta IAM suite](okta-iam-suite/README.md) targets the current **Integrator Free Plan**: PKCE SSO, MFA setup, JWT tenant APIs, guarded joiner/mover/leaver operations, retained-token containment, local expiring access, access reviews and System Log exercises. Start with [the Okta setup guide](okta-iam-suite/docs/setup.md); a real authorized free org is required for live testing. `make okta-setup && make okta-test` runs its separate offline checks without changing Conjur.

The separate [Conjur Agent Identity & Delegation lab](conjur-agent-identity/README.md) implements signed attenuated human→agent→sub-agent grants, holder-bound tool proofs, shared ancestor budgets, revocation, real Cedar authorization and brokered Conjur tool identities. `make agent-setup && make agent-test && make agent-demo` runs the synthetic end-to-end path without an LLM or credentials. A restricted Conjur→Cedar compiler includes finite reference-model differential tests; it does not claim full MAML equivalence. See its [development handoff](conjur-agent-identity/docs/development.md) and [research boundaries](conjur-agent-identity/docs/research.md).