import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { createPdp } from '../src/cedar.mjs';

const here = new URL('../', import.meta.url);
const registry = JSON.parse(readFileSync(new URL('config/registry.json', here), 'utf8'));
const policyText = readFileSync(new URL('policies/agents.cedar', here), 'utf8');
const schema = JSON.parse(readFileSync(new URL('policies/schema.json', here), 'utf8'));
const require = createRequire(fileURLToPath(new URL('../package.json', import.meta.url)));
const cedar = require('@cedar-policy/cedar-wasm/nodejs');
const pdp = createPdp({ registry });

const base = {
  agentId: 'agent/payment-reconciliation',
  tool: 'payment-db',
  action: 'read',
  records: 2,
  tenant: 'acme',
  environment: 'dev',
  delegationValid: true,
};

test('policies validate with the pinned Cedar 4.13 engine', () => {
  assert.equal(cedar.getCedarVersion(), '4.13.0');
  const result = cedar.validate({
    validationSettings: { mode: 'strict' },
    schema,
    policies: { staticPolicies: policyText },
  });
  assert.equal(result.type, 'success');
  assert.deepEqual(result.validationErrors, []);
});

test('registered payments agent can read an in-scope payment tool', () => {
  assert.deepEqual(pdp.authorize(base), { allowed: true, reasons: ['agent_read_team_scope'] });
});

test('production admin remains explicitly forbidden', () => {
  const result = pdp.authorize({ ...base, tool: 'production-admin', action: 'admin', environment: 'prod' });
  assert.equal(result.allowed, false);
  assert.ok(result.reasons.includes('deny_blocked_tool'));
  assert.ok(result.reasons.includes('deny_production_resource'));
});

test('cross-team agents cannot read a payment tool', () => {
  const scopedRegistry = {
    ...registry,
    agents: [...registry.agents, { id: 'audit-acme', team: 'audit', tenant: 'acme', environment: 'dev' }],
  };
  const scopedPdp = createPdp({ registry: scopedRegistry });
  assert.equal(scopedPdp.authorize({ ...base, agentId: 'audit-acme' }).allowed, false);
});

test('cross-tenant and cross-environment requests are denied with a policy reason', () => {
  const result = pdp.authorize({ ...base, agentId: 'agent/observer' });
  assert.equal(result.allowed, false);
  assert.ok(result.reasons.includes('deny_cross_scope'));
});

test('delegation, record limit, and caller context are enforced', () => {
  assert.equal(pdp.authorize({ ...base, delegationValid: false }).allowed, false);
  assert.equal(pdp.authorize({ ...base, records: 11 }).allowed, false);
  assert.equal(pdp.authorize({ ...base, tenant: 'globex' }).allowed, false);
  assert.equal(pdp.authorize({ ...base, environment: 'prod' }).allowed, false);
});

test('missing principals, unknown tools, and malformed contexts fail closed', () => {
  assert.equal(pdp.authorize({ ...base, agentId: 'missing-agent' }).allowed, false);
  assert.equal(pdp.authorize({ ...base, agentId: undefined }).allowed, false);
  assert.equal(pdp.authorize({ ...base, tool: 'unknown-tool' }).allowed, false);
  assert.equal(pdp.authorize({ ...base, records: -1 }).allowed, false);
  assert.equal(pdp.authorize({ ...base, records: '2' }).allowed, false);
  assert.equal(pdp.authorize({ ...base, delegationValid: 'true' }).allowed, false);
  assert.equal(pdp.authorize({ ...base, tenant: null }).allowed, false);
  assert.equal(pdp.authorize(null).allowed, false);
});

test('construction rejects policies that reference undeclared attributes', () => {
  const injected = policyText.replace('principal.team == resource.team', 'principal.unregistered == resource.team');
  assert.throws(() => createPdp({ registry, policies: injected, schema }), /Cedar policy validation failed/);
});

test('construction rejects invalid Cedar policy syntax', () => {
  assert.throws(() => createPdp({ registry, policies: 'permit ???', schema }), /Cedar schema or policy syntax is invalid/);
});
