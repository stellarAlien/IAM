import fs from 'node:fs';
import path from 'node:path';
import { Authority, Denied, keyPair } from './delegation.mjs';
import { privateWrite, State, Audit } from './storage.mjs';
import { createPdp } from './cedar.mjs';
import { Gateway } from './gateway.mjs';

export function registry() {
  return JSON.parse(fs.readFileSync('config/registry.json', 'utf8'));
}

export function initialize(directory = '.runtime') {
  const data = registry();
  const identities = ['authority', ...data.agents.map(agent => agent.id)];
  const state = new State(directory);
  const established = fs.existsSync(state.file) || identities.some(identity =>
    ['private', 'public'].some(kind => fs.existsSync(path.join(directory, 'identities', identity, `${kind}.pem`))));
  if (established) {
    state.read();
    for (const identity of identities) {
      if (!['private', 'public'].every(kind => fs.existsSync(path.join(directory, 'identities', identity, `${kind}.pem`)))) {
        throw new Denied('existing-identity-key-restore-required');
      }
    }
    return data;
  }
  for (const identity of identities) {
    const location = path.join(directory, 'identities', identity);
    const privateFile = path.join(location, 'private.pem');
    const publicFile = path.join(location, 'public.pem');
    if (fs.existsSync(privateFile) !== fs.existsSync(publicFile)) throw new Denied('partial-identity-key-pair-restore-required');
    if (!fs.existsSync(privateFile)) {
      const keys = keyPair();
      privateWrite(privateFile, keys.privateKey);
      privateWrite(publicFile, keys.publicKey);
    }
  }
  state.initialize();
  return data;
}

export function identityKey(directory, id, kind = 'private') {
  if (!['authority', ...registry().agents.map(agent => agent.id)].includes(id)) throw new Denied('unknown-identity');
  return fs.readFileSync(path.join(directory, 'identities', id, `${kind}.pem`), 'utf8');
}

export function runtime(directory, secrets, { issuer = false } = {}) {
  const data = registry();
  const holderKeys = Object.fromEntries(data.agents.map(agent => [agent.id, identityKey(directory, agent.id, 'public')]));
  const authority = new Authority({ registry: data, publicKey: identityKey(directory, 'authority', 'public'),
    privateKey: issuer ? identityKey(directory, 'authority') : null, holderKeys });
  const state = new State(directory);
  state.read();
  const audit = new Audit(path.join(directory, 'audit.jsonl'));
  const pdp = createPdp({ registry: data });
  const gateway = new Gateway({ authority, holderKeys, pdp, state, audit, secrets });
  return { authority, state, audit, pdp, gateway, registry: data };
}
