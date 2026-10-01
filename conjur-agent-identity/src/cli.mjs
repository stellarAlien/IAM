import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { randomBytes } from 'node:crypto';
import { Denied, makeProof } from './delegation.mjs';
import { privateWrite } from './storage.mjs';
import { initialize, runtime, registry, identityKey } from './runtime.mjs';
import { Conjur } from './conjur.mjs';
import { serve } from './gateway.mjs';
import { createPdp } from './cedar.mjs';
import { compile } from './translation.mjs';

const constraints = { tools: ['payment-db', 'stripe-reconcile'], action: 'read', tenant: 'acme',
  environment: 'dev', maxRecords: 5, maxCalls: 4 };

function liveSecrets() {
  const config = JSON.parse(fs.readFileSync('config/local.json', 'utf8'));
  return new Conjur({ config, registry: registry(), keyDirectory: '.runtime/tool-keys' });
}

async function request(runtimeData, directory, chain, body, requestPath = '/tools/invoke') {
  const grants = await runtimeData.authority.verify(chain);
  const agentId = grants.at(-1).sub;
  const proof = await makeProof({ privateKey: identityKey(directory, agentId), agentId, chain,
    method: 'POST', path: requestPath, body });
  return { chain, proof, body, path: requestPath };
}

async function demo() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-identity-demo-'));
  let retrieved = 0;
  try {
    initialize(directory);
    const lab = runtime(directory, { read: async () => { retrieved++; return randomBytes(32); } }, { issuer: true });
    const root = await lab.authority.root({ human: lab.registry.human.id, agent: 'agent/payment-reconciliation', constraints });
    const childRequest = { agent: 'agent/reconciliation-worker', constraints: { ...constraints, tools: ['payment-db'], maxRecords: 2, maxCalls: 2 }, ttl: 60 };
    const proof = await makeProof({ privateKey: identityKey(directory, 'agent/payment-reconciliation'), agentId: 'agent/payment-reconciliation',
      chain: root, method: 'DELEGATE', path: '/delegations', body: childRequest });
    const child = await lab.authority.child({ chain: root, proof, ...childRequest });
    console.log('REAL Cedar engine + synthetic connector demo; no live Conjur, LLM or external side effects.');
    const discovery = await request(lab, directory, child, { tool: 'payment-db', records: 2 }, '/authorization/discover');
    const eligible = await lab.gateway.execute(discovery, true);
    console.log(`PASS pre-flight: ${eligible.status} (advisory, no credential read)`);
    const invocation = await request(lab, directory, child, { tool: 'payment-db', records: 2 });
    const result = await lab.gateway.execute(invocation);
    console.log(`PASS human → agent → sub-agent → tool: ${result.status}, records=${result.records_processed}`);
    const expectDenied = async (name, operation) => {
      try { await operation(); } catch (error) {
        if (!(error instanceof Denied)) throw error;
        console.log(`PASS ${name}: ${error.code}`);
        return;
      }
      throw new Error('Expected denial');
    };
    const maliciousPlan = fs.readFileSync('fixtures/prompt-injection.txt', 'utf8');
    if (!maliciousPlan.includes('production-admin')) throw new Error('Missing injection fixture');
    await expectDenied('prompt-injection proposed admin call', async () => lab.gateway.execute(
      await request(lab, directory, child, { tool: 'production-admin', records: 1 })));
    await expectDenied('sub-agent attempts undelegated Stripe tool', async () => lab.gateway.execute(
      await request(lab, directory, child, { tool: 'stripe-reconcile', records: 1 })));
    await expectDenied('typed record-bound excess', async () => lab.gateway.execute(
      await request(lab, directory, child, { tool: 'payment-db', records: 3 })));
    await expectDenied('proof replay', () => lab.gateway.execute(invocation));
    await lab.gateway.execute(await request(lab, directory, child, { tool: 'payment-db', records: 1 }));
    await expectDenied('sub-agent aggregate budget', async () => lab.gateway.execute(
      await request(lab, directory, child, { tool: 'payment-db', records: 1 })));
    lab.state.revoke((await lab.authority.verify(root))[0].jti);
    await expectDenied('ancestor revocation with retained child token', async () => lab.gateway.execute(
      await request(lab, directory, child, { tool: 'payment-db', records: 1 })));
    lab.audit.verify();
    if (retrieved !== 2) throw new Error('Unauthorized credential retrieval');
    console.log('PASS audit linkage and credential isolation: exactly two authorized synthetic credential reads.');
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

async function rootGrant() {
  initialize();
  const lab = runtime('.runtime', { read: async () => { throw new Denied('no-tool-execution-during-issuance'); } }, { issuer: true });
  const chain = await lab.authority.root({ human: lab.registry.human.id, agent: 'agent/payment-reconciliation', constraints });
  privateWrite('.runtime/root-grant.json', chain);
  lab.audit.append({ outcome: 'root-grant-issued', human: lab.registry.human.id, agent: 'agent/payment-reconciliation',
    chain: (await lab.authority.verify(chain)).map(grant => grant.jti) });
  console.log('Human-approved root grant saved privately (120s). Authority operator represents the lab human.');
}

async function delegateGrant() {
  const lab = runtime('.runtime', {}, { issuer: true });
  const chain = JSON.parse(fs.readFileSync('.runtime/root-grant.json', 'utf8'));
  lab.state.checkRevocation(await lab.authority.verify(chain));
  const prior = fs.existsSync('.runtime/issuer-proofs.json') ? JSON.parse(fs.readFileSync('.runtime/issuer-proofs.json', 'utf8')) : [];
  lab.authority.usedDelegations = new Set(prior);
  const child = { agent: 'agent/reconciliation-worker', constraints: { ...constraints, tools: ['payment-db'], maxRecords: 2, maxCalls: 2 }, ttl: 60 };
  const proof = await makeProof({ privateKey: identityKey('.runtime', 'agent/payment-reconciliation'), agentId: 'agent/payment-reconciliation',
    chain, method: 'DELEGATE', path: '/delegations', body: child });
  const issued = await lab.authority.child({ chain, proof, ...child });
  privateWrite('.runtime/issuer-proofs.json', [...lab.authority.usedDelegations]);
  privateWrite('.runtime/child-grant.json', issued);
  lab.audit.append({ outcome: 'attenuated-child-issued', human: lab.registry.human.id, agent: child.agent,
    chain: (await lab.authority.verify(issued)).map(grant => grant.jti) });
  console.log('Child grant saved privately: payment-db only, ≤2 records/call, ≤2 calls, ≤60s.');
}

async function invoke(preflight) {
  const lab = runtime('.runtime', {});
  const chain = JSON.parse(fs.readFileSync('.runtime/child-grant.json', 'utf8'));
  const tool = process.argv[3] ?? 'payment-db';
  const records = Number(process.argv[4] ?? 1);
  const requestPath = preflight ? '/authorization/discover' : '/tools/invoke';
  const signed = await request(lab, '.runtime', chain, { tool, records }, requestPath);
  const envelope = { chain: signed.chain, proof: signed.proof, body: signed.body };
  const response = await fetch('http://127.0.0.1:8092' + requestPath, { method: 'POST', redirect: 'error',
    signal: AbortSignal.timeout(10000), headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(envelope) });
  const result = await response.json();
  console.log(JSON.stringify(result));
  if (!response.ok) process.exitCode = 1;
}

async function main() {
  const command = process.argv[2];
  if (command === 'demo') return demo();
  if (command === 'init') { initialize(); console.log('Authority and separate agent holder keys initialized privately; existing keys preserved.'); return; }
  if (command === 'validate') { createPdp({ registry: registry() }); console.log('Real Cedar schema and policies validated.'); return; }
  if (command === 'translate') {
    const compiled = compile(fs.readFileSync('fixtures/conjur-subset.yml', 'utf8'));
    privateWrite('.runtime/translated.json', { policies: compiled.policies, entities: compiled.entities, schema: compiled.schema });
    console.log('Restricted subset compiled and validated with Cedar; private output .runtime/translated.json. Not full MAML equivalence.');
    return;
  }
  if (command === 'grant') return rootGrant();
  if (command === 'delegate') return delegateGrant();
  if (command === 'invoke' || command === 'discover') return invoke(command === 'discover');
  if (command === 'revoke') {
    const lab = runtime('.runtime', {});
    const chain = JSON.parse(fs.readFileSync('.runtime/root-grant.json', 'utf8'));
    const grants = await lab.authority.verify(chain);
    lab.state.revoke(grants[0].jti);
    lab.audit.append({ outcome: 'root-revoked', human: grants[0].human, agent: grants[0].sub, chain: [grants[0].jti] });
    console.log('Root revoked locally; all descendants will fail future tool admission.');
    return;
  }
  if (command === 'audit') {
    const lab = runtime('.runtime', {});
    lab.audit.verify();
    console.log('Local audit hash links verified; not tamper-proof, independently anchored or non-repudiable evidence.');
    return;
  }
  if (command === 'serve') {
    const lab = runtime('.runtime', liveSecrets());
    const server = serve(lab.gateway);
    server.on('listening', () => console.log('Live Conjur tool gateway on http://127.0.0.1:8092. No agent receives secret values.'));
    return;
  }
  if (command === 'test-conjur') {
    const secrets = liveSecrets();
    const data = registry();
    for (const tool of ['payment-db', 'stripe-reconcile']) {
      await secrets.read(tool);
      for (const forbidden of [tool === 'payment-db' ? data.tools['stripe-reconcile'].secret : data.tools['payment-db'].secret,
        'agent-lab/acme/prod/admin/credential']) {
        try { await secrets.read(tool, forbidden); } catch (error) {
          if (error instanceof Denied && error.code === 'conjur-rbac-denied') continue;
          throw error;
        }
        throw new Denied('unexpected-conjur-overgrant');
      }
    }
    console.log('Live Conjur tool identity RBAC passed: own credential allowed, other tool and admin denied.');
    return;
  }
  throw new Denied('usage-init-grant-delegate-discover-invoke-revoke-audit-serve-demo-validate-translate-test-conjur');
}

let lock;
let acquired = false;
try {
  if (['init', 'grant', 'delegate', 'revoke'].includes(process.argv[2])) {
    fs.mkdirSync('.runtime', { recursive: true, mode: 0o700 });
    lock = '.runtime/issuer-operation.lock';
    fs.mkdirSync(lock, { mode: 0o700 });
    acquired = true;
  }
  await main();
} catch (error) {
  console.error('ERROR:', error instanceof Denied ? error.code : 'operation-failed-check-private-config-and-service-health');
  process.exitCode = 1;
} finally { if (acquired) fs.rmdirSync(lock); }
