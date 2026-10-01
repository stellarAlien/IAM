SHELL := /bin/bash
PYTHON ?= .venv/bin/python
.DEFAULT_GOAL := help
.PHONY: help setup configure doctor serve login logout test groups join move leave review audit jit contain release send
help:
	@printf '%s\n' 'setup      Install pinned Python dependencies' 'configure  Copy non-secret config example; edit config/local.json' 'doctor     Check tenant discovery and configuration (no mutation)' 'serve      Run local JWT API on 127.0.0.1:8090' 'login      Browser PKCE sign-in; private token file' 'logout     Revoke stored token and remove local artifacts' 'groups     Provision suite-scoped Okta groups (CONFIRM=lab-only)' 'join       Stage synthetic user (ACTOR=alice LOGIN=... CONFIRM=lab-only)' 'move       Replace scoped user access (ACTOR=alice SCOPE=globex/dev CONFIRM=lab-only)' 'leave      Block locally, revoke Okta sessions, deactivate (CONFIRM=deactivate-lab-user)' 'contain    Block registered actor locally immediately' 'jit        Local expiring grant (ACTOR=alice SCOPE=acme/prod MINUTES=5 CONFIRM=lab-only)' 'review     Private access-review report for registered lab objects' 'audit      Private System Log export; safe count only' 'send       JWT message via curl, stdin; TENANT=acme ENVIRONMENT=dev' 'test       Offline tests (no Okta credentials)'
	@printf '%s\n' 'release    Reviewed local unblock; cutoff rejects old JWTs (CONFIRM=lab-only)'
setup:
	@python3 -m venv .venv
	@$(PYTHON) -m pip install --disable-pip-version-check -r requirements.txt
configure:
	@mkdir -p config
	@test -e config/local.json || cp config/example.json config/local.json
	@printf '%s\n' 'Edit config/local.json using the Okta setup guide; no credentials go in this file.'
doctor groups review audit:
	@$(PYTHON) -m okta_lab.manage $@ --confirm '$(CONFIRM)'
join:
	@$(PYTHON) -m okta_lab.manage join --actor '$(ACTOR)' --login '$(LOGIN)' --confirm '$(CONFIRM)'
move:
	@$(PYTHON) -m okta_lab.manage move --actor '$(ACTOR)' --scope '$(SCOPE)' --confirm '$(CONFIRM)'
leave:
	@$(PYTHON) -m okta_lab.manage leave --actor '$(ACTOR)' --confirm '$(CONFIRM)'
contain:
	@$(PYTHON) -m okta_lab.manage contain --actor '$(ACTOR)'
release:
	@$(PYTHON) -m okta_lab.manage release --actor '$(ACTOR)' --confirm '$(CONFIRM)'
jit:
	@$(PYTHON) -m okta_lab.manage jit --actor '$(ACTOR)' --scope '$(SCOPE)' --minutes '$(or $(MINUTES),5)' --confirm '$(CONFIRM)'
serve:
	@$(PYTHON) -m okta_lab.api
login:
	@$(PYTHON) -m okta_lab.login $(if $(NO_BROWSER),--no-browser)
logout:
	@$(PYTHON) -m okta_lab.login --logout --revoke
send:
	@$(PYTHON) -m okta_lab.send --tenant '$(or $(TENANT),acme)' --environment '$(or $(ENVIRONMENT),dev)'
test:
	@$(PYTHON) -m unittest discover -s tests -v
