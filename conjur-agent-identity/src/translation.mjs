import { createRequire } from 'node:module';
import { isAlias, isMap, isScalar, isSeq, parseAllDocuments } from 'yaml';

const require = createRequire(import.meta.url);
const cedar = require('@cedar-policy/cedar-wasm/nodejs');

const MAX_INPUT_BYTES = 64 * 1024;
const MAX_DEPTH = 16;
const MAX_STATEMENTS = 100;
const DECLARATIONS = new Set(['!user', '!host', '!group', '!layer', '!variable']);
const ROLE_KINDS = new Set(['!user', '!host', '!group', '!layer']);
const ACTOR_KINDS = new Set(['!user', '!host']);
const ALLOWED_TAGS = new Set([...DECLARATIONS, '!grant', '!permit']);
const VALID_PRIVILEGES = new Set(['read', 'execute']);
const ID_PATH = /^[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/;
const IDENTIFIER = /^[A-Za-z0-9_-]+$/;
const ACTIONS = ['read', 'execute'];

const fail = () => {
  throw new Error('Invalid or unsupported Conjur policy subset');
};

function canonicalId(kind, value) {
  if (typeof value !== 'string') fail();
  const id = value.startsWith('/') ? value.slice(1) : value;
  if (!ID_PATH.test(id) || id.includes(':')) fail();
  return `${kind.slice(1)}/${id}`;
}

function scalarString(node) {
  if (!isScalar(node) || typeof node.value !== 'string') fail();
  return node.value;
}

function plainString(node) {
  if (!isScalar(node) || typeof node.value !== 'string' || node.tag?.startsWith('!')) fail();
  return node.value;
}

function taggedRef(node, allowedKinds) {
  if (!isScalar(node) || !allowedKinds.has(node.tag)) fail();
  return { kind: node.tag, id: canonicalId(node.tag, scalarString(node)) };
}

function mapEntries(node) {
  if (!isMap(node)) fail();
  const entries = new Map();
  for (const pair of node.items) {
    if (!isScalar(pair.key) || typeof pair.key.value !== 'string' || pair.key.tag?.startsWith('!')) fail();
    const key = pair.key.value;
    if (entries.has(key)) fail();
    entries.set(key, pair.value);
  }
  return entries;
}

function exactFields(entries, required, optional = []) {
  const allowed = new Set([...required, ...optional]);
  if (required.some(key => !entries.has(key)) || [...entries.keys()].some(key => !allowed.has(key))) fail();
}

function requiredEntry(entries, key) {
  if (!entries.has(key)) fail();
  return entries.get(key);
}

function refList(node, allowedKinds) {
  if (!isSeq(node) || node.items.length === 0) fail();
  return node.items.map(item => taggedRef(item, allowedKinds));
}

function checkAstSafety(documents) {
  if (documents.length !== 1) fail();
  const document = documents[0];
  if (document.errors.length || document.warnings.some(warning => warning.code !== 'TAG_RESOLVE_FAILED')) fail();
  const pending = [[document.contents, 0]];
  while (pending.length) {
    const [node, depth] = pending.pop();
    if (!node) continue;
    if (depth > MAX_DEPTH || isAlias(node)) fail();
    if (node.tag && node.tag.startsWith('!') && !ALLOWED_TAGS.has(node.tag)) fail();
    if (isMap(node)) {
      for (const pair of node.items) pending.push([pair.key, depth + 1], [pair.value, depth + 1]);
    } else if (isSeq(node)) {
      for (const item of node.items) pending.push([item, depth + 1]);
    }
  }
  return document.contents;
}

function parseStatements(text) {
  if (typeof text !== 'string' || Buffer.byteLength(text, 'utf8') > MAX_INPUT_BYTES) fail();
  let documents;
  try {
    documents = parseAllDocuments(text, {
      version: '1.2',
      uniqueKeys: true,
      strict: true,
      logLevel: 'silent',
    });
  } catch {
    fail();
  }
  const root = checkAstSafety(documents);
  if (!isSeq(root) || root.items.length > MAX_STATEMENTS) fail();

  const declarations = new Map();
  const grants = [];
  const permits = [];
  for (const statement of root.items) {
    if (!isMap(statement) || !ALLOWED_TAGS.has(statement.tag)) fail();
    const fields = mapEntries(statement);
    if (DECLARATIONS.has(statement.tag)) {
      exactFields(fields, ['id']);
      const declaredId = plainString(requiredEntry(fields, 'id'));
      if (declaredId.startsWith('/')) fail();
      const id = canonicalId(statement.tag, declaredId);
      if (declarations.has(id)) fail();
      declarations.set(id, { id, kind: statement.tag });
      continue;
    }
    if (statement.tag === '!grant') {
      exactFields(fields, ['role'], ['member', 'members']);
      const hasMember = fields.has('member');
      const hasMembers = fields.has('members');
      if (hasMember === hasMembers) fail();
      const role = taggedRef(requiredEntry(fields, 'role'), new Set(['!group', '!layer']));
      const members = hasMember
        ? [taggedRef(requiredEntry(fields, 'member'), ROLE_KINDS)]
        : refList(requiredEntry(fields, 'members'), ROLE_KINDS);
      grants.push({ role: role.id, members: members.map(member => member.id) });
      continue;
    }
    if (statement.tag === '!permit') {
      exactFields(fields, ['role', 'privileges'], ['resource', 'resources']);
      const hasResource = fields.has('resource');
      const hasResources = fields.has('resources');
      if (hasResource === hasResources) fail();
      const role = taggedRef(requiredEntry(fields, 'role'), ROLE_KINDS);
      const privilegeNode = requiredEntry(fields, 'privileges');
      if (!isSeq(privilegeNode) || privilegeNode.items.length === 0) fail();
      const actions = privilegeNode.items.map(item => plainString(item));
      if (actions.some(action => !VALID_PRIVILEGES.has(action))) fail();
      const resources = hasResource
        ? [taggedRef(requiredEntry(fields, 'resource'), new Set(['!variable']))]
        : refList(requiredEntry(fields, 'resources'), new Set(['!variable']));
      permits.push({ role: role.id, actions: [...new Set(actions)], resources: resources.map(resource => resource.id) });
      continue;
    }
    fail();
  }
  return { declarations, grants, permits };
}

function entityUid(type, id) {
  return { type, id };
}

function cedarSchema() {
  return {
    '': {
      entityTypes: {
        Role: { memberOfTypes: ['Role'] },
        Variable: {},
      },
      actions: Object.fromEntries(ACTIONS.map(action => [action, {
        appliesTo: { principalTypes: ['Role'], resourceTypes: ['Variable'] },
      }])),
    },
  };
}

function makePolicy(role, action, resource, principalKinds, id) {
  const policyPrincipal = principalKinds.has(role)
    ? { op: '==', entity: entityUid('Role', role) }
    : { op: 'in', entity: entityUid('Role', role) };
  return {
    effect: 'permit',
    principal: policyPrincipal,
    action: { op: '==', entity: entityUid('Action', action) },
    resource: { op: '==', entity: entityUid('Variable', resource) },
    conditions: [],
  };
}

function assertValidCedar(policies, entities, schema) {
  const schemaCheck = cedar.checkParseSchema(schema);
  const entityCheck = cedar.checkParseEntities({ entities, schema });
  const policyCheck = cedar.checkParsePolicySet(policies);
  if (schemaCheck.type !== 'success' || entityCheck.type !== 'success' || policyCheck.type !== 'success') fail();
  const result = cedar.validate({ schema, policies, validationSettings: { mode: 'strict' } });
  if (result.type !== 'success' || result.validationErrors.length) fail();
}

/** Compile only the explicitly documented flat Conjur tagged-YAML subset. */
export function compile(text) {
  const { declarations, grants, permits } = parseStatements(text);
  const roleDeclarations = [...declarations.values()].filter(item => item.kind !== '!variable');
  const variableDeclarations = [...declarations.values()].filter(item => item.kind === '!variable');
  const byId = declarations;
  const parentSets = new Map(roleDeclarations.map(role => [role.id, new Set()]));
  for (const grant of grants) {
    const grantedRole = byId.get(grant.role);
    if (!grantedRole || !['!group', '!layer'].includes(grantedRole.kind)) fail();
    for (const memberId of grant.members) {
      const member = byId.get(memberId);
      if (!member || !ROLE_KINDS.has(member.kind)) fail();
      parentSets.get(memberId).add(grant.role);
    }
  }

  const visiting = new Set();
  const visited = new Set();
  function visitRole(roleId) {
    if (visiting.has(roleId)) fail();
    if (visited.has(roleId)) return;
    visiting.add(roleId);
    for (const parent of parentSets.get(roleId) ?? []) visitRole(parent);
    visiting.delete(roleId);
    visited.add(roleId);
  }
  for (const role of roleDeclarations) visitRole(role.id);

  const principalIds = new Set(roleDeclarations.filter(item => ACTOR_KINDS.has(item.kind)).map(item => item.id));
  const variableIds = new Set(variableDeclarations.map(item => item.id));
  const roleKinds = new Map(roleDeclarations.map(item => [item.id, item.kind]));
  const policiesById = {};
  const policyPrincipalKinds = new Set([...principalIds]);
  let policyIndex = 0;
  for (const permit of permits) {
    if (!roleKinds.has(permit.role)) fail();
    for (const resource of permit.resources) if (!variableIds.has(resource)) fail();
    for (const action of permit.actions) {
      for (const resource of permit.resources) {
        const policyId = `p${String(++policyIndex).padStart(4, '0')}`;
        policiesById[policyId] = makePolicy(permit.role, action, resource, policyPrincipalKinds, policyId);
      }
    }
  }

  const entities = [
    ...roleDeclarations.map(role => ({
      uid: entityUid('Role', role.id),
      attrs: {},
      parents: [...parentSets.get(role.id)].sort().map(parent => entityUid('Role', parent)),
    })),
    ...variableDeclarations.map(variable => ({ uid: entityUid('Variable', variable.id), attrs: {}, parents: [] })),
  ];
  const schema = cedarSchema();
  const policies = { staticPolicies: policiesById };
  assertValidCedar(policies, entities, schema);

  return {
    policies,
    entities,
    schema,
    model: {
      principals: [...principalIds].sort(),
      variables: [...variableIds].sort(),
      parents: Object.fromEntries([...parentSets].map(([id, parents]) => [id, [...parents].sort()])),
      permits: permits.map(permit => ({
        role: permit.role,
        actions: permit.actions,
        resources: permit.resources,
      })),
    },
  };
}

function isKnownRequest(compiled, principal, action, resource) {
  return typeof principal === 'string'
    && compiled.model.principals.includes(principal)
    && ACTIONS.includes(action)
    && compiled.model.variables.includes(resource);
}

/** Evaluate the finite Conjur subset directly, with transitive role membership. */
export function referenceDecision(compiled, principal, action, resource) {
  if (!compiled?.model || !isKnownRequest(compiled, principal, action, resource)) return false;
  const membership = new Set([principal]);
  const pending = [principal];
  while (pending.length) {
    for (const parent of compiled.model.parents[pending.pop()] ?? []) {
      if (membership.has(parent)) continue;
      membership.add(parent);
      pending.push(parent);
    }
  }
  return compiled.model.permits.some(permit => membership.has(permit.role)
    && permit.actions.includes(action)
    && permit.resources.includes(resource));
}

/** Authorize through the installed Cedar WASM engine; all evaluator errors deny. */
export function authorizeCompiled(compiled, principal, action, resource) {
  if (!compiled?.model || !isKnownRequest(compiled, principal, action, resource)) return false;
  try {
    const answer = cedar.isAuthorized({
      principal: entityUid('Role', principal),
      action: entityUid('Action', action),
      resource: entityUid('Variable', resource),
      context: {},
      schema: compiled.schema,
      validateRequest: true,
      policies: compiled.policies,
      entities: compiled.entities,
    });
    return answer.type === 'success'
      && answer.response.diagnostics.errors.length === 0
      && answer.response.decision === 'allow';
  } catch {
    return false;
  }
}
