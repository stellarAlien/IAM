import { createHash, randomUUID, generateKeyPairSync } from 'node:crypto';
import { SignJWT, jwtVerify, importPKCS8, importSPKI } from 'jose';

export const ISSUER = 'urn:conjur-agent-lab:authority';
export const AUDIENCE = 'urn:conjur-agent-lab:tool-gateway';
export const MAX_DEPTH = 2;
const TOOL_NAMES = ['payment-db', 'stripe-reconcile'];

export class Denied extends Error {
  constructor(code = 'authorization-denied') { super(code); this.code = code; }
}

export function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
}

export function digest(value) {
  return createHash('sha256').update(typeof value === 'string' ? value : canonical(value)).digest('hex');
}

export function keyPair() {
  const keys = generateKeyPairSync('ed25519');
  return {
    privateKey: keys.privateKey.export({ type: 'pkcs8', format: 'pem' }),
    publicKey: keys.publicKey.export({ type: 'spki', format: 'pem' }),
  };
}

function keysExact(value, fields) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === [...fields].sort().join(',');
}

export function validateConstraints(value) {
  if (!keysExact(value, ['tools', 'action', 'tenant', 'environment', 'maxRecords', 'maxCalls'])
    || !Array.isArray(value.tools) || !value.tools.length || value.tools.length > 2
    || new Set(value.tools).size !== value.tools.length || value.tools.some(tool => !TOOL_NAMES.includes(tool))
    || value.action !== 'read' || value.tenant !== 'acme' || value.environment !== 'dev'
    || !Number.isInteger(value.maxRecords) || value.maxRecords < 1 || value.maxRecords > 10
    || !Number.isInteger(value.maxCalls) || value.maxCalls < 1 || value.maxCalls > 10) {
    throw new Denied('invalid-typed-constraints');
  }
  return value;
}

function attenuates(child, parent) {
  return child.tools.every(tool => parent.tools.includes(tool)) && child.action === parent.action
    && child.tenant === parent.tenant && child.environment === parent.environment
    && child.maxRecords <= parent.maxRecords && child.maxCalls <= parent.maxCalls;
}

export class Authority {
  constructor({ registry, publicKey, privateKey = null, holderKeys = {}, usedDelegations = new Set(), clock = () => Math.floor(Date.now() / 1000) }) {
    this.registry = registry;
    this.publicKey = publicKey;
    this.privateKey = privateKey;
    this.holderKeys = holderKeys;
    this.usedDelegations = usedDelegations;
    this.clock = clock;
  }

  agent(id) {
    const agent = this.registry.agents.find(item => item.id === id);
    if (!agent) throw new Denied('unknown-agent');
    return agent;
  }

  async sign(payload) {
    if (!this.privateKey) throw new Denied('issuer-private-key-unavailable');
    return new SignJWT(payload).setProtectedHeader({ alg: 'EdDSA', typ: 'agent-grant+jwt' })
      .setIssuer(ISSUER).setAudience(AUDIENCE).sign(await importPKCS8(this.privateKey, 'EdDSA'));
  }

  async root({ human, agent, constraints, ttl = 120 }) {
    const principal = this.registry.human;
    const target = this.agent(agent);
    validateConstraints(constraints);
    if (human !== principal.id || target.team !== principal.team || target.tenant !== principal.tenant
      || target.environment !== principal.environment || !Number.isInteger(ttl) || ttl < 1 || ttl > 300) {
      throw new Denied('human-delegation-out-of-bounds');
    }
    const now = this.clock();
    const token = await this.sign({ version: 1, sub: agent, human, constraints, depth: 0,
      parent: null, jti: randomUUID(), iat: now, nbf: now, exp: now + ttl });
    return [token];
  }

  async verify(chain) {
    if (!Array.isArray(chain) || !chain.length || chain.length > MAX_DEPTH + 1
      || chain.some(token => typeof token !== 'string' || token.length > 8192)) throw new Denied('invalid-chain');
    const verified = [];
    const seen = new Set();
    const key = await importSPKI(this.publicKey, 'EdDSA');
    for (let index = 0; index < chain.length; index++) {
      let result;
      try {
        result = await jwtVerify(chain[index], key, { algorithms: ['EdDSA'], issuer: ISSUER, audience: AUDIENCE,
          typ: 'agent-grant+jwt', currentDate: new Date(this.clock() * 1000),
          requiredClaims: ['sub', 'human', 'constraints', 'depth', 'parent', 'jti', 'iat', 'nbf', 'exp', 'version'] });
      } catch { throw new Denied('invalid-or-expired-grant'); }
      const grant = result.payload;
      validateConstraints(grant.constraints);
      this.agent(grant.sub);
      if (grant.version !== 1 || grant.human !== this.registry.human.id || grant.depth !== index
        || typeof grant.jti !== 'string' || !grant.jti || seen.has(grant.jti)
        || ![grant.iat, grant.nbf, grant.exp].every(Number.isInteger)
        || grant.iat > this.clock() || grant.nbf !== grant.iat || grant.exp <= grant.iat || grant.exp - grant.iat > 300) {
        throw new Denied('invalid-chain-claims');
      }
      seen.add(grant.jti);
      const agent = this.agent(grant.sub);
      if (agent.team !== this.registry.human.team || agent.tenant !== grant.constraints.tenant
        || agent.environment !== grant.constraints.environment) throw new Denied('agent-boundary-mismatch');
      if (index === 0) {
        if (grant.parent !== null) throw new Denied('root-parent-mismatch');
      } else {
        const parent = verified[index - 1];
        if (grant.parent !== digest(chain[index - 1]) || grant.exp > parent.exp || grant.iat < parent.iat
          || !attenuates(grant.constraints, parent.constraints)
          || verified.some(previous => previous.sub === grant.sub)) throw new Denied('delegation-amplification');
      }
      verified.push(grant);
    }
    return verified;
  }

  async child({ chain, agent, constraints, ttl = 60, proof }) {
    const grants = await this.verify(chain);
    const parent = grants.at(-1);
    validateConstraints(constraints);
    const target = this.agent(agent);
    const request = { agent, constraints, ttl };
    const holderPublicKey = this.holderKeys[parent.sub];
    if (!holderPublicKey) throw new Denied('unknown-holder-key');
    const holderProof = await verifyProof({ proof, publicKey: holderPublicKey, agentId: parent.sub, chain,
      method: 'DELEGATE', path: '/delegations', body: request, now: this.clock() });
    if (grants.length > MAX_DEPTH || !Number.isInteger(ttl) || ttl < 1 || ttl > 300
      || !attenuates(constraints, parent.constraints) || target.team !== this.registry.human.team
      || target.tenant !== constraints.tenant || target.environment !== constraints.environment
      || grants.some(grant => grant.sub === agent)) throw new Denied('delegation-amplification');
    const now = this.clock();
    const exp = Math.min(now + ttl, parent.exp);
    if (exp <= now) throw new Denied('expired-parent');
    const proofId = digest(parent.sub + ':' + holderProof.jti);
    if (this.usedDelegations.has(proofId)) throw new Denied('delegation-proof-replay');
    this.usedDelegations.add(proofId);
    const token = await this.sign({ version: 1, sub: agent, human: parent.human, constraints,
      depth: grants.length, parent: digest(chain.at(-1)), jti: randomUUID(), iat: now, nbf: now, exp });
    return [...chain, token];
  }
}

export async function makeProof({ privateKey, agentId, chain, method, path, body, now = Math.floor(Date.now() / 1000), jti = randomUUID() }) {
  return new SignJWT({ agent: agentId, chainHash: digest(chain), requestHash: digest(body), method, path })
    .setProtectedHeader({ alg: 'EdDSA', typ: 'agent-proof+jwt' }).setIssuer(agentId).setAudience(AUDIENCE)
    .setJti(jti).setIssuedAt(now).setExpirationTime(now + 30)
    .sign(await importPKCS8(privateKey, 'EdDSA'));
}

export async function verifyProof({ proof, publicKey, agentId, chain, method, path, body, now = Math.floor(Date.now() / 1000) }) {
  let payload;
  try {
    ({ payload } = await jwtVerify(proof, await importSPKI(publicKey, 'EdDSA'), {
      algorithms: ['EdDSA'], issuer: agentId, audience: AUDIENCE, typ: 'agent-proof+jwt',
      currentDate: new Date(now * 1000), requiredClaims: ['jti', 'iat', 'exp', 'agent', 'chainHash', 'requestHash', 'method', 'path'],
    }));
  } catch { throw new Denied('invalid-holder-proof'); }
  if (payload.agent !== agentId || payload.chainHash !== digest(chain) || payload.requestHash !== digest(body)
    || payload.method !== method || payload.path !== path || !Number.isInteger(payload.iat)
    || !Number.isInteger(payload.exp) || payload.exp <= payload.iat || payload.exp - payload.iat > 30
    || payload.iat > now || now - payload.iat > 30 || typeof payload.jti !== 'string' || !payload.jti) {
    throw new Denied('holder-request-binding-mismatch');
  }
  return payload;
}
