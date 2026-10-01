import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { Denied, digest } from './delegation.mjs';

export function privateWrite(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  fs.chmodSync(path.dirname(file), 0o700);
  const temporary = file + '.' + randomUUID() + '.tmp';
  fs.writeFileSync(temporary, typeof value === 'string' ? value : JSON.stringify(value, null, 2), { mode: 0o600, flag: 'wx' });
  fs.renameSync(temporary, file);
}

export class State {
  constructor(directory) { this.directory = directory; this.file = path.join(directory, 'enforcement.json'); }

  initialize() {
    if (!fs.existsSync(this.file)) privateWrite(this.file, { revoked: [], usedProofs: {}, calls: {} });
    this.read();
  }

  read() {
    let data;
    try { data = JSON.parse(fs.readFileSync(this.file, 'utf8')); } catch { throw new Denied('enforcement-state-unavailable'); }
    if (!Array.isArray(data.revoked) || data.revoked.some(id => typeof id !== 'string')
      || !data.usedProofs || !data.calls || typeof data.usedProofs !== 'object' || typeof data.calls !== 'object'
      || Array.isArray(data.usedProofs) || Array.isArray(data.calls)
      || Object.values(data.usedProofs).some(value => !Number.isInteger(value))
      || Object.values(data.calls).some(value => !Number.isInteger(value) || value < 0)) throw new Denied('invalid-enforcement-state');
    return data;
  }

  checkRevocation(grants) {
    const data = this.read();
    if (grants.some(grant => data.revoked.includes(grant.jti))) throw new Denied('revoked-delegation-chain');
  }

  checkAvailability(grants, proof) {
    const data = this.read();
    if (grants.some(grant => data.revoked.includes(grant.jti))) throw new Denied('revoked-delegation-chain');
    if (Object.hasOwn(data.usedProofs, digest(proof.iss + ':' + proof.jti))) throw new Denied('proof-replay');
    if (grants.some(grant => (data.calls[grant.jti] ?? 0) >= grant.constraints.maxCalls)) throw new Denied('aggregate-call-budget-exhausted');
  }

  reserve(grants, proof, now) {
    return this.transaction(() => this.reserveLocked(grants, proof, now));
  }

  transaction(operation) {
    const lock = this.file + '.lock';
    try { fs.mkdirSync(lock, { mode: 0o700 }); } catch { throw new Denied('enforcement-state-busy'); }
    try { return operation(); } finally { fs.rmdirSync(lock); }
  }

  reserveLocked(grants, proof, now) {
    const data = this.read();
    if (grants.some(grant => data.revoked.includes(grant.jti))) throw new Denied('revoked-delegation-chain');
    const id = digest(proof.iss + ':' + proof.jti);
    if (Object.hasOwn(data.usedProofs, id)) throw new Denied('proof-replay');
    if (grants.some(grant => (data.calls[grant.jti] ?? 0) >= grant.constraints.maxCalls)) throw new Denied('aggregate-call-budget-exhausted');
    data.usedProofs = Object.fromEntries(Object.entries(data.usedProofs).filter(([, expiration]) => expiration > now));
    data.usedProofs[id] = proof.exp;
    for (const grant of grants) data.calls[grant.jti] = (data.calls[grant.jti] ?? 0) + 1;
    // Reserve before secret retrieval. Downstream failures do not refund a budget.
    privateWrite(this.file, data);
  }

  revoke(jti) {
    this.transaction(() => {
      const data = this.read();
      data.revoked = [...new Set([...data.revoked, jti])];
      privateWrite(this.file, data);
    });
  }
}

export class Audit {
  constructor(file) { this.file = file; }

  append(record) {
    fs.mkdirSync(path.dirname(this.file), { recursive: true, mode: 0o700 });
    const lock = this.file + '.lock';
    try { fs.mkdirSync(lock, { mode: 0o700 }); } catch { throw new Denied('audit-state-busy'); }
    try { return this.appendLocked(record); } finally { fs.rmdirSync(lock); }
  }

  appendLocked(record) {
    let previous = '0'.repeat(64);
    if (fs.existsSync(this.file)) {
      previous = this.verify();
    }
    const safe = { event: randomUUID(), timestamp: new Date().toISOString(), ...record, previous };
    const entry = { ...safe, hash: digest(safe) };
    fs.appendFileSync(this.file, JSON.stringify(entry) + '\n', { mode: 0o600 });
    return entry.event;
  }

  verify() {
    let previous = '0'.repeat(64);
    for (const row of fs.readFileSync(this.file, 'utf8').trim().split('\n')) {
      const { hash, ...record } = JSON.parse(row);
      if (record.previous !== previous || digest(record) !== hash) throw new Denied('audit-chain-mismatch');
      previous = hash;
    }
    return previous;
  }
}
