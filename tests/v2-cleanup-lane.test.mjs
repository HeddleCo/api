import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { create, createFileRegistry, fromBinary, toBinary } from '@bufbuild/protobuf';
import { FileDescriptorSetSchema } from '@bufbuild/protobuf/wkt';
import * as api from '../packages/typescript/dist/v1alpha2/index.js';
import { CallFailureSchema } from '../packages/typescript/dist/common/index.js';

const fixture = JSON.parse(readFileSync(new URL('./fixtures/cleanup-lane-v1.json', import.meta.url)));
const old = createFileRegistry(fromBinary(FileDescriptorSetSchema,
  readFileSync(new URL('./fixtures/cleanup-lane-alpha15.binpb', import.meta.url))));
const bytes = hex => new Uint8Array(Buffer.from(hex, 'hex'));
const schema = type => type === 'CallFailure' ? CallFailureSchema : api[`${type}Schema`];
const vectors = type => fixture.vectors.filter(v => v.type === type);
const decode = vector => {
  const s = schema(vector.type);
  const value = fromBinary(s, bytes(vector.wire_hex));
  assert.equal(Buffer.from(toBinary(s, value)).toString('hex'), vector.wire_hex);
  return value;
};
const get = (type, name) => decode(vectors(type).find(v => v.name === name));

test('exact revision path listing preserves bounds, literal prefix and terminal status', () => {
  const request = get('ListPathsRequest', 'prefix-page');
  assert.equal(request.prefix, 'src/');
  assert.equal(request.revision.revision.case, 'gitCommitOid');
  assert.equal(request.revision.revision.value, 'a'.repeat(40));
  assert.deepEqual(request.revision.spool, request.thread.spool);
  assert.equal(request.page.size, 4096);
  assert.deepEqual(request.page.afterPage, bytes('0708'));
  assert.equal(request.budget.maxSnapshotBytes, 16777216n);
  const root = get('ListPathsRequest', 'root-defaults');
  assert.equal(root.prefix, '');
  assert.equal(root.page, undefined);
  assert.equal(root.revision.revision.case, 'state');
  const deep = get('ListPathsEvent', 'deep-leaf');
  assert.equal(deep.payload.case, 'path');
  assert.equal(deep.payload.value, 'nested/'.repeat(65) + 'file.ts');
  const more = get('ListPathsEvent', 'more').payload.value;
  assert.equal(more.section, 'paths');
  assert.equal(more.coverage, 1);
  assert.deepEqual(more.computedFor, request.revision);
  assert.equal(more.page.exhausted, false);
  assert.deepEqual(more.page.nextPage, bytes('08'));
  const end = get('ListPathsEvent', 'exhausted').payload.value;
  assert.equal(end.page.exhausted, true);
  assert.equal(end.page.matchingCount, 0n);
  const unavailable = get('ListPathsEvent', 'unavailable').payload.value;
  assert.equal(unavailable.coverage, 3);
  assert.equal(unavailable.page, undefined);
});

test('ancestry is an ordered visible subsequence with an actual immediate parent', () => {
  const nested = get('SpoolOverview', 'nested');
  assert.deepEqual(nested.ancestors.map(a => a.ref.id), ['root', 'parent']);
  assert.deepEqual(nested.ancestors.map(a => a.pathSegments), [['team'], ['team', 'project']]);
  assert.deepEqual(nested.parent, nested.ancestors.at(-1).ref);
  const subsequence = get('SpoolOverview', 'visible-subsequence');
  assert.deepEqual(subsequence.ancestors.map(a => a.ref.id), ['parent']);
  assert.deepEqual(subsequence.parent, subsequence.ancestors[0].ref);
  const root = get('SpoolOverview', 'root');
  assert.equal(root.parent, undefined);
  assert.deepEqual(root.ancestors, []);
});

test('live collaboration names and existing snapshot history names need no member join', () => {
  for (const type of ['ContextRecord', 'DiscussionTurn']) {
    const record = get(type, 'live-author');
    assert.equal(record.authorDisplayName, 'Renamed Author');
    assert.equal(record.principalId, 'principal-a');
    assert.equal(record.agentId, 'agent-a');
    assert.ok(record.causalId.length > 0);
    assert.equal(create(schema(type)).authorDisplayName, '');
  }
  assert.equal(get('ContextRecord', 'unresolved-import').authorDisplayName, '');
  assert.equal(get('ContextRecord', 'unresolved-import').principalId, 'gh:luke');
  assert.equal(get('DiscussionTurn', 'unresolved').authorDisplayName, '');
  const history = get('CaptureSummary', 'snapshot-author');
  assert.equal(history.principalName, 'Original claimed name');
  assert.equal(history.attributionAssurance, 1);
  assert.equal(history.principalId, '');
});

test('provider default, bounded selectors and ref-page readiness are distinct', () => {
  const repository = get('ProviderRepository', 'refs-page');
  assert.equal(repository.defaultBranch, 'main');
  assert.equal(repository.private, true);
  assert.deepEqual(repository.linkedSpools.map(s => s.id), ['spool-a']);
  assert.deepEqual(repository.refs.map(r => [r.name, r.kind, r.headOid]), [
    ['refs/heads/main', 1, 'b'.repeat(40)], ['refs/tags/v1', 2, 'c'.repeat(40)],
  ]);
  assert.equal(repository.refsStatus.page.exhausted, false);
  assert.deepEqual(repository.refsStatus.page.nextPage, bytes('09'));
  const empty = get('ProviderRepository', 'known-empty');
  assert.deepEqual(empty.refs, []);
  assert.equal(empty.refsStatus.coverage, 1);
  assert.equal(empty.refsStatus.page.exhausted, true);
  assert.equal(empty.refsStatus.page.matchingCount, 0n);
  assert.equal(get('ProviderRepository', 'unavailable').refsStatus.coverage, 3);
  assert.equal(get('ProviderRepository', 'unrequested').refsStatus, undefined);
  assert.equal(get('ProviderRepository', 'unrequested').defaultBranch, '');
  for (const kind of [0, 99]) assert.equal(get('ProviderRef', `kind-${kind}`).kind, kind);
  const request = get('ObserveIntegrationsRequest', 'refs-selectors-at-cap');
  assert.equal(request.includeRepositories, true);
  assert.equal(request.includeRefsFor.length, 8);
  assert.equal(request.includeRefsFor.reduce((n, r) => n + r.page.size, 0), 4096);
  assert.equal(new Set(request.includeRefsFor.map(r => r.providerRepositoryId)).size, 8);
  assert.deepEqual(get('ObserveIntegrationsRequest', 'older-inventory').includeRefsFor, []);
});

test('capability numbers preserve zero and unknown values without invented semantics', () => {
  assert.deepEqual([api.Capability.UNSPECIFIED, api.Capability.RECORD_REVIEW, api.Capability.LAND,
    api.Capability.PUT_GRANT, api.Capability.CREATE_INVITATION, api.Capability.REVISE_SPOOL], [0, 1, 2, 3, 4, 5]);
  for (const capability of [0, 1, 2, 3, 4, 5, 99]) {
    const action = get('ActionAvailability', `capability-${capability}`);
    assert.equal(action.capability, capability);
    assert.equal(action.implemented, true);
    assert.equal(action.authorized, true);
  }
  assert.equal(create(api.ActionAvailabilitySchema).capability, api.Capability.UNSPECIFIED);
});

test('typed refusals pass through blocked receipts and existing call-failure channels', () => {
  for (const reason of [0, 202, 203, 601, 9999]) {
    const blocked = get('Blocked', `reason-${reason}`);
    assert.equal(blocked.error.reason, reason);
    assert.equal(blocked.requirements[0].kind, 1);
    assert.equal(blocked.error.resource, '');
    assert.equal(blocked.error.context.case, undefined);
    const receipt = get('MutationReceipt', `blocked-${reason}`);
    assert.equal(receipt.outcome.case, 'blocked');
    assert.deepEqual(receipt.outcome.value, blocked);
    assert.equal(get('CallFailure', `refused-${reason}`).error.reason, reason);
  }
  assert.equal(get('Blocked', 'older-refusal').error, undefined);
  const hidden = get('CallFailure', 'existence-hiding');
  assert.equal(hidden.code, 5);
  assert.equal(hidden.error.reason, 300);
  assert.equal(hidden.error.resource, '');
  assert.equal(hidden.error.field, '');
  assert.equal(hidden.error.context.case, undefined);
});

test('search and relationship metadata preserve readable labels and unknown states', () => {
  const hit = get('SearchHit', 'readable-labels');
  assert.equal(hit.threadName, 'Feature');
  assert.deepEqual(hit.spoolPath, ['team', 'api']);
  const omitted = get('SearchHit', 'older-or-withheld-labels');
  assert.equal(omitted.threadName, '');
  assert.deepEqual(omitted.spoolPath, []);
  assert.deepEqual(omitted.thread, hit.thread);
  for (const lifecycle of [0, 2, 4, 99]) assert.equal(get('ThreadRelationship', `lifecycle-${lifecycle}`).lifecycle, lifecycle);
  assert.equal(get('ThreadRelationship', 'lifecycle-0').name, '');
  assert.equal(get('ThreadRelationship', 'lifecycle-2').name, 'Target');
});

test('frozen alpha.15 readers retain all old fields and new readers accept their output', () => {
  for (const vector of fixture.vectors) {
    const current = schema(vector.type);
    decode(vector);
    if (vector.legacy_wire_hex === undefined) continue;
    const legacy = old.getMessage(current.typeName);
    const value = fromBinary(legacy, bytes(vector.wire_hex), { readUnknownFields: false });
    const wire = toBinary(legacy, value, { writeUnknownFields: false });
    assert.equal(Buffer.from(wire).toString('hex'), vector.legacy_wire_hex, `${vector.type}/${vector.name}`);
    const reread = fromBinary(current, wire);
    const additions = {
      SpoolOverview: { ancestors: [] }, ContextRecord: { authorDisplayName: '' },
      DiscussionTurn: { authorDisplayName: '' }, ProviderRepository: { defaultBranch: '', refs: [], refsStatus: undefined },
      ObserveIntegrationsRequest: { includeRefsFor: [] }, ActionAvailability: { capability: 0 },
      SearchHit: { threadName: '', spoolPath: [] }, ThreadRelationship: { name: '', lifecycle: 0 }, Blocked: { error: undefined },
    }[vector.type];
    for (const [key, value] of Object.entries(additions ?? {})) assert.deepEqual(reread[key], value);
    if (vector.type === 'MutationReceipt') assert.equal(reread.outcome.value.error, undefined);
    // Existing call-level ErrorDetail must survive the older reader unchanged.
    if (vector.type === 'CallFailure') assert.deepEqual(reread.error, decode(vector).error);
  }
});
