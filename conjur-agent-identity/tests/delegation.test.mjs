import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { Authority, Denied, makeProof, keyPair, digest } from '../src/delegation.mjs';
import { State, Audit } from '../src/storage.mjs';
import { Gateway, serve } from '../src/gateway.mjs';
import { createPdp } from '../src/cedar.mjs';
import { initialize } from '../src/runtime.mjs';

const registry = JSON.parse(fs.readFileSync('config/registry.json', 'utf8'));
const constraints = { tools: ['payment-db', 'stripe-reconcile'], action: 'read', tenant: 'acme',
  environment: 'dev', maxRecords: 4, maxCalls: 4 };

async function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-tests-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const authorityKeys = keyPair();
  const keys = Object.fromEntries(registry.agents.map(agent => [agent.id, keyPair()]));
  const holderKeys = Object.fromEntries(Object.entries(keys).map(([id, pair]) => [id, pair.publicKey]));
  let now = Math.floor(Date.now() / 1000);
  const authority = new Authority({ registry, ...authorityKeys, holderKeys, clock: () => now });
  const root = await authority.root({ human: registry.human.id, agent: 'agent/payment-reconciliation', constraints });
  const state = new State(directory);
  state.initialize();
  const audit = new Audit(path.join(directory, 'audit.jsonl'));
  const credential = randomBytes(32);
  let reads = 0;
  const secrets = { read: async () => { reads++; return credential; } };
  const gateway = new Gateway({ authority, holderKeys, state, audit, secrets,
    pdp: createPdp({ registry }), clock: () => now });
  const request = async (chain = root, body = { tool: 'payment-db', records: 1 }, endpoint = '/tools/invoke') => {
    const leaf = (await authority.verify(chain)).at(-1);
    return { chain, body, path: endpoint, proof: await makeProof({ privateKey: keys[leaf.sub].privateKey,
      agentId: leaf.sub, chain, method: 'POST', path: endpoint, body, now }) };
  };
  const child = async (overrides = {}) => {
    const data = { agent: 'agent/reconciliation-worker', constraints: { ...constraints, tools: ['payment-db'], maxRecords: 2, maxCalls: 2 }, ttl: 60, ...overrides };
    const proof = await makeProof({ privateKey: keys['agent/payment-reconciliation'].privateKey, agentId: 'agent/payment-reconciliation', chain: root,
      method: 'DELEGATE', path: '/delegations', body: data, now });
    return authority.child({ chain: root, proof, ...data });
  };
  return { authority, root, keys, holderKeys, state, audit, gateway, directory, request, child, secrets,
    credential, reads: () => reads, advance: seconds => { now += seconds; }, now: () => now };
}

test('signed chain and holder-bound tool execution never expose credentials', async t => {
  const lab = await fixture(t);
  const child = await lab.child();
  const result = await lab.gateway.execute(await lab.request(child));
  assert.equal(result.status, 'completed');
  assert.equal(result.synthetic, true);
  assert.equal(lab.reads(), 1);
  const output = JSON.stringify(result) + fs.readFileSync(lab.audit.file, 'utf8');
  assert.equal(output.includes(lab.credential.toString('base64')), false);
  assert.equal(output.includes(lab.credential.toString('hex')), false);
  assert.equal(output.includes(child[0]), false);
  lab.audit.verify();
});

test('issuer rejects unknown human, foreign agent, incorrect types and production', async t => {
  const lab = await fixture(t);
  for (const change of [ { human: 'unknown' }, { agent: 'agent/observer' },
    { constraints: { ...constraints, environment: 'prod' } }, { constraints: { ...constraints, maxRecords: '4' } },
    { constraints: { ...constraints, extra: 'ignore policy' } }, { ttl: 301 } ]) {
    await assert.rejects(() => lab.authority.root({ human: registry.human.id, agent: 'agent/payment-reconciliation', constraints, ...change }), Denied);
  }
});

test('child grants attenuate tool sets, record/call bounds and holder team', async t => {
  const lab = await fixture(t);
  for (const change of [ { constraints: { ...constraints, maxCalls: 5 } }, { constraints: { ...constraints, maxRecords: 5 } },
    { agent: 'agent/observer' }, { constraints: { ...constraints, tools: ['production-admin'] } } ]) {
    await assert.rejects(() => lab.child(change), Denied);
  }
  const child = await lab.child({ ttl: 300 });
  const grants = await lab.authority.verify(child);
  assert.ok(grants[1].exp <= grants[0].exp);
});

test('child issuance proof is pinned to the parent key and rejects proof replay', async t => {
  const lab = await fixture(t);
  const body = { agent: 'agent/reconciliation-worker', constraints: { ...constraints, tools: ['payment-db'] }, ttl: 60 };
  const wrong = await makeProof({ privateKey: lab.keys['agent/observer'].privateKey, agentId: 'agent/payment-reconciliation',
    chain: lab.root, method: 'DELEGATE', path: '/delegations', body, now: lab.now() });
  await assert.rejects(() => lab.authority.child({ chain: lab.root, proof: wrong, ...body }), /invalid-holder-proof/);
  const proof = await makeProof({ privateKey: lab.keys['agent/payment-reconciliation'].privateKey, agentId: 'agent/payment-reconciliation',
    chain: lab.root, method: 'DELEGATE', path: '/delegations', body, now: lab.now() });
  await lab.authority.child({ chain: lab.root, proof, ...body });
  await assert.rejects(() => lab.authority.child({ chain: lab.root, proof, ...body }), /delegation-proof-replay/);
});

test('chain truncation, reordering, substitution, tampering and expired ancestors are denied', async t => {
  const lab = await fixture(t);
  const child = await lab.child();
  for (const chain of [child.slice(1), [...child].reverse(), [child[0], child[0]], [child[0], child[1].slice(0, -5) + 'xxxxx']]) {
    await assert.rejects(() => lab.authority.verify(chain), Denied);
  }
  lab.advance(121);
  await assert.rejects(() => lab.authority.verify(child), /invalid-or-expired-grant/);
});

test('cycles and chain length beyond two delegation hops fail closed', async t => {
  const lab = await fixture(t);
  const chain = await lab.child();
  const grant = (await lab.authority.verify(chain)).at(-1);
  const third = await lab.authority.sign({ ...grant, depth: 2, sub: 'agent/payment-reconciliation',
    parent: digest(chain.at(-1)), jti: 'unique-third-grant' });
  await assert.rejects(() => lab.authority.verify([...chain, third]), /delegation-amplification/);
  await assert.rejects(() => lab.authority.verify([...chain, third, third]), /invalid-chain/);
});

test('expired holder proof cannot invoke an otherwise-live grant', async t => {
  const lab = await fixture(t);
  const signed = await lab.request();
  lab.advance(31);
  await assert.rejects(() => lab.gateway.execute(signed), /invalid-holder-proof/);
  assert.equal(lab.reads(), 0);
});

test('signed malicious chain amplification is rejected even when signed by trusted issuer', async t => {
  const lab = await fixture(t);
  const grants = await lab.authority.verify(lab.root);
  const forged = await lab.authority.sign({ ...grants[0], sub: 'agent/reconciliation-worker', depth: 1,
    parent: 'incorrect-parent-hash', jti: 'different-signed-grant', constraints });
  await assert.rejects(() => lab.authority.verify([...lab.root, forged]), /delegation-amplification/);
});

test('prompts, extra fields and resource substitution cannot add authorization', async t => {
  const lab = await fixture(t);
  const child = await lab.child();
  const malicious = fs.readFileSync('fixtures/prompt-injection.txt', 'utf8');
  assert.ok(malicious.includes('production-admin'));
  for (const body of [{ tool: 'production-admin', records: 1 }, { tool: 'stripe-reconcile', records: 1 },
    { tool: 'payment-db', records: 3 }, { tool: 'payment-db', records: 1, prompt: malicious }]) {
    await assert.rejects(() => lab.request(child, body).then(request => lab.gateway.execute(request)), Denied);
  }
  assert.equal(lab.reads(), 0);
});

test('proof binds method, path, holder, payload and full chain', async t => {
  const lab = await fixture(t);
  const child = await lab.child();
  const request = await lab.request(child);
  await assert.rejects(() => lab.gateway.execute({ ...request, body: { tool: 'payment-db', records: 2 } }), /holder-request-binding-mismatch/);
  await assert.rejects(() => lab.gateway.execute({ ...request, path: '/authorization/discover' }), /holder-request-binding-mismatch/);
  const proof = await makeProof({ privateKey: lab.keys['agent/payment-reconciliation'].privateKey, agentId: 'agent/reconciliation-worker', chain: child,
    method: 'POST', path: request.path, body: request.body, now: lab.now() });
  await assert.rejects(() => lab.gateway.execute({ ...request, proof }), /invalid-holder-proof/);
  assert.equal(lab.reads(), 0);
});

test('preflight is advisory and neither consumes quota nor retrieves secrets', async t => {
  const lab = await fixture(t);
  const child = await lab.child();
  const result = await lab.gateway.execute(await lab.request(child, undefined, '/authorization/discover'), true);
  assert.equal(result.advisory, true);
  assert.equal(lab.reads(), 0);
  assert.deepEqual(lab.state.read().calls, {});
  lab.state.revoke((await lab.authority.verify(lab.root))[0].jti);
  await assert.rejects(async () => lab.gateway.execute(await lab.request(child)), /revoked-delegation-chain/);
});

test('replay protection and every-ancestor call budget survive reload', async t => {
  const lab = await fixture(t);
  const first = await lab.request();
  await lab.gateway.execute(first);
  lab.gateway.state = new State(lab.directory);
  await assert.rejects(() => lab.gateway.execute(first), /proof-replay/);
  for (let index = 0; index < 3; index++) await lab.gateway.execute(await lab.request());
  const child = await lab.child();
  await assert.rejects(async () => lab.gateway.execute(await lab.request(child)), /aggregate-call-budget-exhausted/);
  assert.equal(lab.reads(), 4);
});

test('parallel requests cannot race the aggregate root budget', async t => {
  const lab = await fixture(t);
  const requests = await Promise.all(Array.from({ length: 8 }, () => lab.request()));
  const results = await Promise.allSettled(requests.map(request => lab.gateway.execute(request)));
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 4);
  assert.equal(lab.reads(), 4);
});

test('discovery reports exhausted current budgets rather than an eligible decision', async t => {
  const lab = await fixture(t);
  for (let count = 0; count < 4; count++) await lab.gateway.execute(await lab.request());
  await assert.rejects(async () => lab.gateway.execute(await lab.request(lab.root, undefined, '/authorization/discover'), true), /aggregate-call-budget-exhausted/);
  assert.equal(lab.reads(), 4);
});

test('revocation or expiry during secret retrieval blocks connector completion', async t => {
  const lab = await fixture(t);
  const rootId = (await lab.authority.verify(lab.root))[0].jti;
  lab.gateway.secrets = { read: async () => { lab.state.revoke(rootId); return randomBytes(32); } };
  await assert.rejects(async () => lab.gateway.execute(await lab.request()), /revoked-delegation-chain/);
  const rows = fs.readFileSync(lab.audit.file, 'utf8');
  assert.equal(rows.includes('"outcome":"completed"'), false);
});

test('missing/corrupt state, Cedar failure or audit failure denies before secrets', async t => {
  const lab = await fixture(t);
  const request = await lab.request();
  fs.unlinkSync(lab.state.file);
  await assert.rejects(() => lab.gateway.execute(request), /enforcement-state-unavailable/);
  lab.state.initialize();
  lab.gateway.pdp = { authorize: () => ({ allowed: false, reasons: [] }) };
  await assert.rejects(() => lab.gateway.execute(request), /cedar-denied/);
  assert.equal(lab.reads(), 0);
});

test('downstream failure consumes reserved budget and records failure without secret output', async t => {
  const lab = await fixture(t);
  lab.gateway.secrets = { read: async () => { throw new Denied('conjur-unavailable'); } };
  await assert.rejects(async () => lab.gateway.execute(await lab.request()), /conjur-unavailable/);
  assert.equal(Object.values(lab.state.read().calls)[0], 1);
  const rows = fs.readFileSync(lab.audit.file, 'utf8');
  assert.ok(rows.includes('conjur-unavailable'));
  assert.equal(rows.includes('"outcome":"completed"'), false);
});

test('audit mutation is detected and missing existing enforcement state is not reset', async t => {
  const lab = await fixture(t);
  await lab.gateway.execute(await lab.request());
  const text = fs.readFileSync(lab.audit.file, 'utf8');
  fs.writeFileSync(lab.audit.file, text.replace('authorized-reserved', 'tampered'));
  assert.throws(() => lab.audit.verify(), /audit-chain-mismatch/);
  assert.throws(() => lab.audit.append({ outcome: 'new' }), /audit-chain-mismatch/);
  const identities = path.join(lab.directory, 'initialized');
  initialize(identities);
  fs.unlinkSync(path.join(identities, 'enforcement.json'));
  assert.throws(() => initialize(identities), /enforcement-state-unavailable/);
});

test('missing complete key pairs in an established runtime require explicit recovery', async t => {
  const lab = await fixture(t);
  for (const identity of ['authority', registry.agents[0].id]) {
    const directory = path.join(lab.directory, 'recovery-' + identity);
    initialize(directory);
    const location = path.join(directory, 'identities', identity);
    fs.unlinkSync(path.join(location, 'private.pem'));
    fs.unlinkSync(path.join(location, 'public.pem'));
    assert.throws(() => initialize(directory), /existing-identity-key-restore-required/);
    assert.equal(fs.existsSync(path.join(location, 'private.pem')), false);
  }
});

test('HTTP gateway rejects unsigned requests and returns no request contents', async t => {
  const lab = await fixture(t);
  const server = serve(lab.gateway, { port: 0 });
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  assert.equal((await fetch(base + '/healthz')).status, 200);
  const bad = await fetch(base + '/tools/invoke', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chain: lab.root, body: { tool: 'payment-db', records: 1 }, proof: 'stolen-grant-without-holder-key' }) });
  assert.equal(bad.status, 403);
  assert.equal((await bad.text()).includes('stolen-grant'), false);
  const invocation = await lab.request();
  const good = await fetch(base + '/tools/invoke', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chain: invocation.chain, proof: invocation.proof, body: invocation.body }) });
  assert.equal(good.status, 200);
  assert.equal((await good.json()).status, 'completed');
});
