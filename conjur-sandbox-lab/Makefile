SHELL := /bin/bash
.DEFAULT_GOAL := help
.PHONY: tenants-init test-tenants tenant-rotate send-message container-security
.PHONY: help up init policies rotate test-app test down clean cli logs exercise-init act exercise-expose exercise-contain exercise-reset exercise-recover exercise-report test-exercise
help:
	@printf '%s\n' 'up        Generate runtime material and start infrastructure' 'init      Create account, load policies, seed secrets, start apps' 'test-app  Verify RBAC and live secret rotation (changes test secrets)' 'rotate    Rotate both workload secrets' 'policies  Apply additive policies' 'cli       Run CLI, e.g. make cli ARGS=whoami' 'test      Run offline unit tests and shell syntax checks' 'down      Stop containers, preserving database and credentials' 'clean     Destroy state (requires CONFIRM=destroy)'
	@printf '%s\n' 'exercise-init     Provision Alice, Bob, Eve and reset baseline' 'act               Actor action; ACTOR=eve ACTION=payment EXPECT=deny' 'exercise-expose   Intentional read overgrant; CONFIRM=lab-only required' 'exercise-contain  Revoke Eve group permissions (not her identity)' 'exercise-recover  Contain then rotate exposed workload secrets' 'exercise-reset    Restore Eve canary-only baseline' 'exercise-report   Summarize private client observations' 'test-exercise     Check baseline human RBAC matrix'
	@printf '%s\n' 'tenants-init      Provision four tenant/environment APIs and caller identities' 'test-tenants      Assert RBAC and 16 caller pairs; rotates acme/dev' 'tenant-rotate     Rotate one scope; TENANT=acme ENVIRONMENT=dev' 'send-message      Read message from stdin; scoped curl POST' 'container-security Inspect hardening and run harmless in-container probes'
up:
	@bash scripts/up.sh
init:
	@bash scripts/init-conjur.sh
policies:
	@bash scripts/load-policies.sh
rotate:
	@bash scripts/rotate-secrets.sh
test-app:
	@bash scripts/test-app.sh
test:
	@python3 -m unittest discover -s tests -v
	@for script in scripts/*.sh; do bash -n "$$script" || exit; done
down:
	@docker compose --profile workloads --profile tools --profile exercise --profile tenants down
clean:
	@CONFIRM='$(CONFIRM)' bash scripts/clean.sh
cli:
	@docker compose run --rm --no-deps client $(ARGS)
logs:
	@docker compose logs --tail=100 database conjur proxy checkout fraud
exercise-init:
	@bash scripts/exercise.sh setup
act:
	@bash scripts/exercise.sh act '$(or $(ACTOR),eve)' '$(or $(ACTION),canary)' '$(or $(EXPECT),observe)'
exercise-expose:
	@CONFIRM='$(CONFIRM)' bash scripts/exercise.sh expose
exercise-contain:
	@bash scripts/exercise.sh contain
exercise-reset:
	@bash scripts/exercise.sh reset
exercise-recover:
	@bash scripts/exercise.sh recover
exercise-report:
	@python3 scripts/exercise-report.py
test-exercise:
	@bash scripts/test-exercise.sh
tenants-init:
	@bash scripts/tenants.sh init
test-tenants:
	@bash scripts/tenants.sh test
tenant-rotate:
	@bash scripts/tenants.sh rotate '$(or $(TENANT),acme)' '$(or $(ENVIRONMENT),dev)'
send-message:
	@python3 scripts/send-message.py --tenant '$(or $(TENANT),acme)' --environment '$(or $(ENVIRONMENT),dev)' $(if $(TARGET_TENANT),--target-tenant '$(TARGET_TENANT)') $(if $(TARGET_ENVIRONMENT),--target-environment '$(TARGET_ENVIRONMENT)')
container-security:
	@python3 scripts/container-security.py
