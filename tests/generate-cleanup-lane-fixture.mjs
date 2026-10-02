import { create, createFileRegistry, fromBinary, toBinary } from '@bufbuild/protobuf';
import { FileDescriptorSetSchema } from '@bufbuild/protobuf/wkt';
import { readFileSync, writeFileSync } from 'node:fs';
import * as api from '../packages/typescript/dist/v1alpha2/index.js';
import { CallFailureSchema } from '../packages/typescript/dist/common/index.js';

// Frozen reachable alpha.15 descriptors were extracted from origin/main at
// 54f3e3fd16ddf319c06d990f6fa691fdd12c8182, retaining every old field and type.
// Regenerating vectors never refreshes this historical reader.
const old = createFileRegistry(fromBinary(FileDescriptorSetSchema,
  readFileSync(new URL('./fixtures/cleanup-lane-alpha15.binpb', import.meta.url))));
const vectors = [];
const add = (type, name, value, schema = api[`${type}Schema`]) => {
  const wire = toBinary(schema, create(schema, value));
  const legacy = old.getMessage(schema.typeName);
  vectors.push({ type, name, wire_hex: Buffer.from(wire).toString('hex'),
    ...(legacy ? { legacy_wire_hex: Buffer.from(toBinary(legacy,
      fromBinary(legacy, wire, { readUnknownFields: false }), { writeUnknownFields: false })).toString('hex') } : {}) });
};
const spool = { id: 'spool-a' };
const parent = { id: 'parent' };
const thread = { spool, id: { value: new Uint8Array(32).fill(3) } };
const revision = { spool, revision: { case: 'gitCommitOid', value: 'a'.repeat(40) } };
const record = id => ({ spool, id });
const page = { size: 4096, afterPage: new Uint8Array([7, 8]) };
const budget = { maxItems: 4097, maxFrameBytes: 8192, maxSnapshotBytes: 16777216n };
add('ListPathsRequest', 'prefix-page', { revision, thread, prefix: 'src/', page, budget });
add('ListPathsRequest', 'root-defaults', { revision: { spool, revision: { case: 'state', value: { value: new Uint8Array(32).fill(9) } } }, thread });
add('ListPathsEvent', 'deep-leaf', { revision, payload: { case: 'path', value: 'nested/'.repeat(65) + 'file.ts' } });
add('ListPathsEvent', 'more', { revision, payload: { case: 'complete', value: { section: 'paths', coverage: 1, computedFor: revision, page: { nextPage: new Uint8Array([8]), exhausted: false } } } });
add('ListPathsEvent', 'exhausted', { revision, payload: { case: 'complete', value: { section: 'paths', coverage: 1, computedFor: revision, page: { exhausted: true, matchingCount: 0n } } } });
add('ListPathsEvent', 'unavailable', { revision, payload: { case: 'complete', value: { section: 'paths', coverage: 3 } } });
add('SpoolOverview', 'nested', { ref: spool, parent, name: 'API', version: new Uint8Array([1]), pathSegments: ['team', 'project', 'api'], ancestors: [
  { ref: { id: 'root' }, pathSegments: ['team'] }, { ref: parent, pathSegments: ['team', 'project'] },
] });
add('SpoolOverview', 'visible-subsequence', { ref: spool, parent, name: 'API', ancestors: [{ ref: parent, pathSegments: ['project'] }] });
add('SpoolOverview', 'root', { ref: spool, name: 'Root', pathSegments: ['root'] });
add('ContextRecord', 'live-author', { ref: record('context'), principalId: 'principal-a', agentId: 'agent-a', causalId: new Uint8Array([11]), content: 'Context', authorDisplayName: 'Renamed Author' });
add('ContextRecord', 'unresolved-import', { ref: record('import'), principalId: 'gh:luke', content: 'Imported context' });
add('DiscussionTurn', 'live-author', { ref: record('turn'), discussion: record('discussion'), principalId: 'principal-a', agentId: 'agent-a', body: 'Discussion', causalId: new Uint8Array([12]), authorDisplayName: 'Renamed Author' });
add('DiscussionTurn', 'unresolved', { ref: record('turn-old'), principalId: 'principal-missing', body: 'Historical turn' });
add('CaptureSummary', 'snapshot-author', { revision, thread, principalName: 'Original claimed name', principalEmail: 'original@example.com', attributionAssurance: 1 });
const connection = { id: 'connection' };
const repository = { connection, providerRepositoryId: 'repo-42', name: 'api', private: true, installationId: 'install-7', linkedSpools: [spool] };
const refs = [
  { name: 'refs/heads/main', headOid: 'b'.repeat(40), kind: 1 },
  { name: 'refs/tags/v1', headOid: 'c'.repeat(40), kind: 2 },
];
add('ProviderRepository', 'refs-page', { ...repository, defaultBranch: 'main', refs,
  refsStatus: { section: 'provider_refs', coverage: 1, page: { nextPage: new Uint8Array([9]), exhausted: false } } });
add('ProviderRepository', 'known-empty', { ...repository, refsStatus: { section: 'provider_refs', coverage: 1, page: { exhausted: true, matchingCount: 0n } } });
add('ProviderRepository', 'unavailable', { ...repository, refsStatus: { section: 'provider_refs', coverage: 3 } });
add('ProviderRepository', 'unrequested', repository);
for (const kind of [0, 99]) add('ProviderRef', `kind-${kind}`, { name: 'refs/heads/future', headOid: 'd'.repeat(40), kind });
add('ObserveIntegrationsRequest', 'refs-selectors-at-cap', { includeRepositories: true,
  connections: [connection], includeRefsFor: Array.from({ length: 8 }, (_, i) => ({ connection, providerRepositoryId: `repo-${i}`, page: { size: 512 } })) });
add('ObserveIntegrationsRequest', 'older-inventory', { includeRepositories: true, connections: [connection] });
const routes = ['', 'ThreadService/RecordReview', 'ThreadService/Land', 'SpoolService/PutGrant', 'IdentityService/CreateInvitation', 'SpoolService/ReviseSpool'];
for (const capability of [0, 1, 2, 3, 4, 5, 99]) add('ActionAvailability', `capability-${capability}`, {
  method: routes[capability] ?? 'FutureService/FutureAction', implemented: true, authorized: true, capability,
});
for (const reason of [0, 202, 203, 601, 9999]) {
  const error = { reason, ...(reason === 202 ? { field: 'settings' } : {}) };
  const blocked = { requirements: [{ kind: 1, explanation: 'Action unavailable' }], error };
  add('Blocked', `reason-${reason}`, blocked);
  add('MutationReceipt', `blocked-${reason}`, { clientOperationId: 'operation-a', outcome: { case: 'blocked', value: blocked } });
  add('CallFailure', `refused-${reason}`, { code: 9, message: 'Action unavailable', error }, CallFailureSchema);
}
add('Blocked', 'older-refusal', { requirements: [{ kind: 1, explanation: 'Unavailable' }] });
add('CallFailure', 'existence-hiding', { code: 5, message: 'Not found', error: { reason: 300 } }, CallFailureSchema);
add('SearchHit', 'readable-labels', { thread, domain: 1, summary: 'Match', matchKind: 1, threadName: 'Feature', spoolPath: ['team', 'api'] });
add('SearchHit', 'older-or-withheld-labels', { thread, domain: 1, summary: 'Match', matchKind: 1 });
for (const lifecycle of [0, 2, 4, 99]) add('ThreadRelationship', `lifecycle-${lifecycle}`, {
  thread, kind: 1, ...(lifecycle === 0 ? {} : { name: 'Target', lifecycle }),
});
writeFileSync(new URL('./fixtures/cleanup-lane-v1.json', import.meta.url), JSON.stringify({ baseline: '54f3e3fd16ddf319c06d990f6fa691fdd12c8182', vectors }, null, 2) + '\n');
