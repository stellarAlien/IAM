import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { authorizeCompiled, compile, referenceDecision } from '../src/translation.mjs';

const fixturePath = fileURLToPath(new URL('../fixtures/conjur-subset.yml', import.meta.url));
const fixture = await readFile(fixturePath, 'utf8');

test('Cedar WASM decisions match the finite reference semantics', () => {
  const compiled = compile(fixture);
  for (const principal of compiled.model.principals) {
    for (const action of ['read', 'execute']) {
      for (const resource of compiled.model.variables) {
        assert.equal(
          authorizeCompiled(compiled, principal, action, resource),
          referenceDecision(compiled, principal, action, resource),
          `${principal} ${action} ${resource}`,
        );
      }
    }
  }
});

test('transitive roles grant only the declared read and execute permissions', () => {
  const compiled = compile(fixture);
  assert.equal(referenceDecision(compiled, 'host/payments-agent', 'read', 'variable/payments/db/credentials'), true);
  assert.equal(referenceDecision(compiled, 'user/auditor', 'read', 'variable/payments/stripe/credential'), true);
  assert.equal(referenceDecision(compiled, 'host/payments-agent', 'execute', 'variable/payments/db/credentials'), true);
  assert.equal(referenceDecision(compiled, 'user/auditor', 'execute', 'variable/payments/db/credentials'), false);
  assert.equal(referenceDecision(compiled, 'host/settlement-agent', 'read', 'variable/payments/db/credentials'), false);
  assert.equal(referenceDecision(compiled, 'host/payments-agent', 'read', 'variable/production/admin/credential'), false);
});

test('unknown principals, actions, and resources fail closed', () => {
  const compiled = compile(fixture);
  for (const decision of [
    referenceDecision(compiled, 'host/unknown', 'read', 'variable/payments/db/credentials'),
    authorizeCompiled(compiled, 'host/unknown', 'read', 'variable/payments/db/credentials'),
    referenceDecision(compiled, 'host/payments-agent', 'update', 'variable/payments/db/credentials'),
    authorizeCompiled(compiled, 'host/payments-agent', 'update', 'variable/payments/db/credentials'),
    referenceDecision(compiled, 'host/payments-agent', 'read', 'variable/unknown'),
    authorizeCompiled(compiled, 'host/payments-agent', 'read', 'variable/unknown'),
  ]) assert.equal(decision, false);
});

test('unsupported constructs and malformed declarations are rejected generically', () => {
  const invalidPolicies = [
    '- !host\n  id: /absolute-agent\n',
    '- !variable\n  id: /absolute-secret\n',
    '- !host\n  id: x\n  owner: !user alice\n',
    '- !host\n  id: x\n  annotations: {description: unsupported}\n',
    '- !policy\n  id: nested\n  body: []\n',
    '- !deny\n  role: !host x\n',
    '- !revoke\n  role: !group readers\n',
    '- !host\n  id: x\n- !host\n  id: x\n',
    '- !host\n  id: x\n- !grant\n  role: !group missing\n  member: !host x\n',
    '- !group\n  id: a\n- !group\n  id: b\n- !grant\n  role: !group a\n  member: !group b\n- !grant\n  role: !group b\n  member: !group a\n',
    '- !host\n  id: x\n- !permit\n  role: !host x\n  privileges: [read, update]\n  resource: !variable secret\n',
    '- !host\n  id: x\n- !permit\n  role: !host x\n  privileges: [read]\n  resource: !variable missing\n',
    '- !host\n  id: x\n  id: y\n',
    '- !host\n  id: x\n---\n- !host\n  id: y\n',
    '- !host\n  id: x\n- !grant\n  role: !group readers\n  member: !host x\n  members: [!host x]\n',
    '- !host\n  id: x\n- !permit\n  role: !host x\n  privileges: []\n  resource: !variable y\n',
    '- !host\n  id: x\n- !permit\n  role: !host x\n  privileges: [read]\n  resources: [!variable y]\n  resource: !variable y\n',
    '- !host\n  id: x\n- !grant\n  role: !group /other-account:readers\n  member: !host x\n',
    '- !host\n  id: x\n- !permit\n  role: !host x\n  privileges: [read]\n  resource: !variable secret\n  nested: {a: {b: {c: {d: {e: {f: {g: {h: {i: {j: {k: {l: {m: {n: {o: {p: {q: too-deep}}}}}}}}}}}}}}}}\n',
    '- !host\n  id: &reused x\n- !host\n  id: *reused\n',
  ];
  for (const policy of invalidPolicies) {
    assert.throws(() => compile(policy), error => error.message === 'Invalid or unsupported Conjur policy subset');
  }
});

test('input size and statement count are bounded', () => {
  assert.throws(() => compile(`- !host\n  id: ${'x'.repeat(64 * 1024)}\n`));
  assert.throws(() => compile(Array.from({ length: 101 }, (_, index) => `- !host\n  id: h${index}\n`).join('')));
});
