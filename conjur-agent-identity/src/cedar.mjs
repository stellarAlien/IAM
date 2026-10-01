import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';

const require = createRequire(import.meta.url);
const cedar = require('@cedar-policy/cedar-wasm/nodejs');
const here = dirname(fileURLToPath(import.meta.url));
const defaultPolicy = readFileSync(resolve(here, '../policies/agents.cedar'), 'utf8');
const defaultSchema = JSON.parse(readFileSync(resolve(here, '../policies/schema.json'), 'utf8'));

function assertRegistry(registry) {
  if (!registry || !Array.isArray(registry.agents) || !registry.tools || typeof registry.tools !== 'object') {
    throw new TypeError('registry must contain agents and tools');
  }

  const agents = new Map();
  for (const agent of registry.agents) {
    if (!agent || ['id', 'team', 'tenant', 'environment'].some((key) => typeof agent[key] !== 'string' || !agent[key])) {
      throw new TypeError('registry contains an invalid agent');
    }
    if (agents.has(agent.id)) throw new TypeError('registry contains duplicate agent ids');
    agents.set(agent.id, agent);
  }

  for (const [id, tool] of Object.entries(registry.tools)) {
    if (!id || !tool || ['team', 'tenant', 'environment'].some((key) => typeof tool[key] !== 'string' || !tool[key])) {
      throw new TypeError('registry contains an invalid tool');
    }
    if (!['read', 'admin'].includes(tool.action)) throw new TypeError('registry contains an unsupported tool action');
  }
  return { agents, tools: registry.tools };
}

function cedarEntities(agents, tools) {
  return [
    ...[...agents.values()].map((agent) => ({
      uid: { type: 'Agent', id: agent.id },
      attrs: { team: agent.team, tenant: agent.tenant, environment: agent.environment },
      parents: [],
    })),
    ...Object.entries(tools).map(([id, tool]) => ({
      uid: { type: 'Tool', id },
      attrs: {
        team: tool.team,
        tenant: tool.tenant,
        environment: tool.environment,
        sensitive: true,
        blocked: id === 'production-admin',
      },
      parents: [],
    })),
  ];
}

function validateConfiguration(policies, schema) {
  const parts = cedar.policySetTextToParts(policies);
  if (parts.type !== 'success') throw new Error('Cedar schema or policy syntax is invalid');
  const staticPolicies = Object.fromEntries(parts.policies.map((policy, index) => {
    const parsed = cedar.policyToJson(policy);
    if (parsed.type !== 'success') throw new Error('Cedar schema or policy syntax is invalid');
    return [parsed.json.annotations?.id ?? `policy${index}`, policy];
  }));
  if (Object.keys(staticPolicies).length !== parts.policies.length) throw new Error('Cedar policy ids must be unique');
  const policySet = { staticPolicies };
  const parsedSchema = cedar.checkParseSchema(schema);
  const parsedPolicies = cedar.checkParsePolicySet(policySet);
  if (parsedSchema.type !== 'success' || parsedPolicies.type !== 'success') {
    throw new Error('Cedar schema or policy syntax is invalid');
  }

  const result = cedar.validate({
    validationSettings: { mode: 'strict' },
    schema,
    policies: policySet,
  });
  if (result.type === 'failure' || (result.type === 'success' && result.validationErrors.length > 0)) {
    const ids = result.type === 'success'
      ? [...new Set(result.validationErrors.map(({ policyId }) => policyId))]
      : [];
    throw new Error(`Cedar policy validation failed${ids.length ? `: ${ids.join(', ')}` : ''}`);
  }
  return { policySet, schema };
}

export function createPdp({ registry, policies = defaultPolicy, schema = defaultSchema } = {}) {
  if (typeof policies !== 'string') throw new TypeError('policies must be Cedar policy text');
  const { agents, tools } = assertRegistry(registry);
  const { policySet, schema: validatedSchema } = validateConfiguration(policies, schema);
  const entities = cedarEntities(agents, tools);

  function authorize(request = {}) {
    if (!request || typeof request !== 'object' || Array.isArray(request)) return { allowed: false, reasons: [] };
    // The gateway must populate delegation and scope from trusted configuration, not tool input.
    const { agentId, tool, action, records, tenant, environment, delegationValid } = request;
    if (!agents.has(agentId) || !Object.hasOwn(tools, tool) || !['read', 'admin'].includes(action)
      || !Number.isSafeInteger(records) || records < 0
      || typeof tenant !== 'string' || typeof environment !== 'string'
      || typeof delegationValid !== 'boolean') {
      return { allowed: false, reasons: [] };
    }

    try {
      const answer = cedar.isAuthorized({
        principal: { type: 'Agent', id: agentId },
        action: { type: 'Action', id: action },
        resource: { type: 'Tool', id: tool },
        context: { delegationValid, records, tenant, environment },
        schema: validatedSchema,
        validateRequest: true,
        policies: policySet,
        entities,
      });
      if (answer.type !== 'success') return { allowed: false, reasons: [] };
      const { response } = answer;
      const reasons = [...new Set([
        ...response.diagnostics.reason,
        ...response.diagnostics.errors.map(({ policyId }) => policyId),
      ])];
      return {
        allowed: response.decision === 'allow' && response.diagnostics.errors.length === 0,
        reasons,
      };
    } catch {
      return { allowed: false, reasons: [] };
    }
  }

  return { authorize };
}
