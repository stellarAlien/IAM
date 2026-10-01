import fs from 'node:fs';
import https from 'node:https';
import { Denied } from './delegation.mjs';

export class Conjur {
  constructor({ config, registry, keyDirectory }) {
    const url = new URL(config.url);
    if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash
      || url.pathname !== '/' || !/^[A-Za-z0-9_-]+$/.test(config.account)) throw new Denied('invalid-conjur-config');
    this.base = url.origin;
    this.account = encodeURIComponent(config.account);
    this.ca = fs.readFileSync(config.ca_file);
    this.registry = registry;
    this.keyDirectory = keyDirectory;
  }

  request(method, path, body, authorization) {
    return new Promise((resolve, reject) => {
      const request = https.request(this.base + path, {
        method, ca: this.ca, rejectUnauthorized: true, timeout: 5000,
        headers: { 'Content-Type': 'application/octet-stream', ...(authorization ? { Authorization: authorization } : {}) },
      }, response => {
        const parts = [];
        let size = 0;
        response.on('data', part => {
          size += part.length;
          if (size > 65536) { response.destroy(); reject(new Denied('conjur-response-too-large')); }
          else parts.push(part);
        });
        response.on('error', () => reject(new Denied('conjur-unavailable')));
        response.on('end', () => {
          if (response.statusCode !== 200) reject(new Denied(response.statusCode === 403 || response.statusCode === 404 ? 'conjur-rbac-denied' : 'conjur-unavailable'));
          else resolve(Buffer.concat(parts));
        });
      });
      request.on('timeout', () => request.destroy());
      request.on('error', () => reject(new Denied('conjur-unavailable')));
      request.end(body);
    });
  }

  async read(tool, secretOverride = null) {
    const definition = this.registry.tools[tool];
    if (!definition?.host || !definition?.secret) throw new Denied('unknown-secret-tool');
    const key = fs.readFileSync(`${this.keyDirectory}/${tool}.key`);
    const token = await this.request('POST', `/authn/${this.account}/${encodeURIComponent(definition.host)}/authenticate`, key);
    const secret = await this.request('GET', `/secrets/${this.account}/variable/${encodeURIComponent(secretOverride ?? definition.secret)}`,
      undefined, `Token token="${token.toString('base64')}"`);
    if (!secret.length) throw new Denied('empty-tool-secret');
    return secret;
  }
}
