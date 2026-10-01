import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { Conjur } from '../src/conjur.mjs';
import { Denied } from '../src/delegation.mjs';

const registry = JSON.parse(fs.readFileSync('config/registry.json', 'utf8'));

function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'conjur-adapter-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const ca = path.join(directory, 'ca.crt');
  fs.writeFileSync(ca, 'synthetic-only-CA-fixture');
  const config = { url: 'https://localhost:8443', account: 'sandbox', ca_file: ca };
  for (const tool of ['payment-db', 'stripe-reconcile']) fs.writeFileSync(path.join(directory, `${tool}.key`), randomBytes(32));
  return { client: new Conjur({ config, registry, keyDirectory: directory }), config, directory };
}

test('Conjur adapter never accepts plaintext, credential-bearing, query or path endpoints', t => {
  const { config, directory } = fixture(t);
  for (const url of ['http://localhost:8443', 'https://user:password@localhost', 'https://localhost/?tenant=other',
    'https://localhost/prefix', 'https://localhost/#insecure']) {
    assert.throws(() => new Conjur({ config: { ...config, url }, registry, keyDirectory: directory }), Denied);
  }
});

test('tool lookup uses distinct pinned host and variable paths with binary token encoding', async t => {
  const { client, directory } = fixture(t);
  const calls = [];
  const token = randomBytes(32);
  const secret = randomBytes(32);
  client.request = async (...args) => {
    calls.push(args);
    return args[0] === 'POST' ? token : secret;
  };
  assert.deepEqual(await client.read('payment-db'), secret);
  assert.equal(calls[0][1], '/authn/sandbox/host%2Fagent-lab%2Fpayment-db/authenticate');
  assert.deepEqual(calls[0][2], fs.readFileSync(path.join(directory, 'payment-db.key')));
  assert.equal(calls[1][1], '/secrets/sandbox/variable/agent-lab%2Facme%2Fdev%2Fpayment-db%2Fcredential');
  assert.equal(calls[1][3], `Token token="${token.toString('base64')}"`);
  await client.read('stripe-reconcile');
  assert.notDeepEqual(calls[2][2], calls[0][2]);
  await assert.rejects(() => client.read('production-admin'), /unknown-secret-tool/);
  assert.equal(calls.length, 4);
});

test('dependency failure and empty secret fail closed without fallback credentials', async t => {
  const { client } = fixture(t);
  client.request = async () => { throw new Denied('conjur-unavailable'); };
  await assert.rejects(() => client.read('payment-db'), /conjur-unavailable/);
  client.request = async () => Buffer.alloc(0);
  await assert.rejects(() => client.read('payment-db'), /empty-tool-secret/);
});
