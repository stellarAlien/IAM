SHELL := /bin/bash
.DEFAULT_GOAL := help
.PHONY: help setup test demo validate init serve grant discover invoke delegate revoke audit translate test-translation conjur-init test-conjur
help:
	@printf '%s\n' 'setup            Install pinned Cedar/JWT/YAML dependencies' 'test             Offline security and real Cedar engine tests' 'demo             Synthetic end-to-end human→agent→subagent→tool exercise' 'init             Generate private lab authority/holder keys, preserve existing keys' 'serve            Run loopback PEP gateway (requires configured Conjur)' 'validate         Validate Cedar policies against schema' 'translate        Compile restricted Conjur fixture into Cedar' 'test-translation Differential subset equivalence tests' 'conjur-init      Add agent tool identities/policies to existing sandbox (CONFIRM=lab-only)' 'test-conjur      Live tool-host positive/negative Conjur RBAC checks'
	@printf '%s\n' 'grant            Trusted facilitator issues 120s root grant' 'delegate         Parent holder proof; payment-only attenuated child' 'discover         Signed advisory pre-flight; TOOL=payment-db RECORDS=1' 'invoke           Signed tool call via gateway; TOOL=payment-db RECORDS=1' 'revoke           Revoke root; future descendant admissions denied' 'audit            Verify local hash linkage, not non-repudiation'
setup:
	@npm ci --ignore-scripts
test:
	@npm test
demo:
	@npm run demo
init:
	@node src/cli.mjs init
serve:
	@node src/cli.mjs serve
grant:
	@node src/cli.mjs grant
delegate:
	@node src/cli.mjs delegate
discover:
	@node src/cli.mjs discover '$(or $(TOOL),payment-db)' '$(or $(RECORDS),1)'
invoke:
	@node src/cli.mjs invoke '$(or $(TOOL),payment-db)' '$(or $(RECORDS),1)'
revoke:
	@node src/cli.mjs revoke
audit:
	@node src/cli.mjs audit
validate:
	@npm run validate
translate:
	@node src/cli.mjs translate
test-translation:
	@node --test tests/translation.test.mjs
conjur-init:
	@CONFIRM='$(CONFIRM)' bash scripts/conjur-init.sh
test-conjur:
	@node src/cli.mjs test-conjur
