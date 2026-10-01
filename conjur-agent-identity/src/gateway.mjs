import http from 'node:http';
import { createHmac, randomUUID } from 'node:crypto';
import { Denied, verifyProof } from './delegation.mjs';

export class Gateway {
  constructor({ authority, holderKeys, pdp, state, audit, secrets, clock = () => Math.floor(Date.now() / 1000) }) {
    Object.assign(this, { authority, holderKeys, pdp, state, audit, secrets, clock });
  }

  async authorize({ chain, proof, body, path }) {
    if (!body || Object.keys(body).sort().join(',') !== 'records,tool' || typeof body.tool !== 'string'
      || !Number.isInteger(body.records) || body.records < 1 || body.records > 10) throw new Denied('invalid-tool-request');
    const grants = await this.authority.verify(chain);
    const leaf = grants.at(-1);
    const publicKey = this.holderKeys[leaf.sub];
    if (!publicKey) throw new Denied('unknown-holder-key');
    const holderProof = await verifyProof({ proof, publicKey, agentId: leaf.sub, chain, method: 'POST', path, body, now: this.clock() });
    this.state.checkRevocation(grants);
    const constraints = leaf.constraints;
    if (!constraints.tools.includes(body.tool) || body.records > constraints.maxRecords) throw new Denied('outside-delegated-constraints');
    const result = this.pdp.authorize({ agentId: leaf.sub, tool: body.tool, action: constraints.action,
      records: body.records, tenant: constraints.tenant, environment: constraints.environment, delegationValid: true });
    if (!result.allowed) throw new Denied('cedar-denied');
    return { grants, leaf, holderProof, result };
  }

  async execute(request, preflight = false) {
    const correlation = randomUUID();
    let identity;
    try {
      identity = await this.authorize(request);
      const { grants, leaf, holderProof, result } = identity;
      if (preflight) {
        this.state.checkAvailability(grants, holderProof);
        this.audit.append({ correlation, outcome: 'preflight-allow', human: leaf.human, agent: leaf.sub,
          tool: request.body.tool, chain: grants.map(grant => grant.jti), policy: result.reasons });
        return { status: 'eligible-now', tool: request.body.tool, constraints: leaf.constraints,
          expires_at: leaf.exp, advisory: true, correlation };
      }
      this.state.reserve(grants, holderProof, this.clock());
      this.audit.append({ correlation, outcome: 'authorized-reserved', human: leaf.human, agent: leaf.sub,
        tool: request.body.tool, chain: grants.map(grant => grant.jti), policy: result.reasons });
      const credential = await this.secrets.read(request.body.tool);
      // Recheck after the asynchronous secret fetch, before the connector effect.
      await this.authority.verify(request.chain);
      this.state.checkRevocation(grants);
      // Synthetic connector consumes the secret internally; no external side effect.
      createHmac('sha256', credential).update('synthetic-tool-operation').digest();
      this.audit.append({ correlation, outcome: 'completed', human: leaf.human, agent: leaf.sub,
        tool: request.body.tool, chain: grants.map(grant => grant.jti), records: request.body.records });
      return { status: 'completed', tool: request.body.tool, records_processed: request.body.records, synthetic: true, correlation };
    } catch (error) {
      const reason = error instanceof Denied ? error.code : 'internal-enforcement-error';
      this.audit.append({ correlation, outcome: 'denied-or-failed', reason,
        ...(identity ? { human: identity.leaf.human, agent: identity.leaf.sub,
          chain: identity.grants.map(grant => grant.jti) } : {}) });
      throw new Denied(reason);
    }
  }
}

export function serve(gateway, { port = 8092 } = {}) {
  let active = 0;
  const server = http.createServer(async (request, response) => {
    const reply = (status, body) => {
      response.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
      response.end(JSON.stringify(body));
    };
    if (request.method === 'GET' && request.url === '/healthz') return reply(200, { status: 'live' });
    if (request.method !== 'POST' || !['/tools/invoke', '/authorization/discover'].includes(request.url)) return reply(404, { error: 'not-found' });
    if (active >= 16) return reply(503, { error: 'busy' });
    active++;
    let enteredGateway = false;
    try {
      if (request.headers['content-type']?.split(';')[0] !== 'application/json') throw new Denied('invalid-content-type');
      let size = 0;
      const parts = [];
      for await (const part of request) {
        size += part.length;
        if (size > 32768) throw new Denied('request-too-large');
        parts.push(part);
      }
      const envelope = JSON.parse(Buffer.concat(parts).toString('utf8'));
      if (!envelope || Object.keys(envelope).sort().join(',') !== 'body,chain,proof') throw new Denied('invalid-envelope');
      enteredGateway = true;
      const result = await gateway.execute({ ...envelope, path: request.url }, request.url === '/authorization/discover');
      reply(200, result);
    } catch (error) {
      let code = error instanceof Denied ? error.code : 'invalid-request';
      if (!enteredGateway) {
        try { gateway.audit.append({ outcome: 'transport-denied', reason: code }); }
        catch { code = 'audit-state-unavailable'; }
      }
      reply(code.includes('unavailable') || code.includes('busy') || code.includes('internal') ? 503 : 403, { error: code });
    } finally { active--; }
  });
  server.requestTimeout = 10000;
  server.headersTimeout = 5000;
  server.timeout = 10000;
  server.listen(port, '127.0.0.1');
  return server;
}
