import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { create, fromBinary, toBinary } from '@bufbuild/protobuf';
import * as api from '../packages/typescript/dist/v1alpha2/index.js';
import {
  normalizeDisplayName, normalizeAdvisoryLabel, validateAaguid,
  validatePasskeyCredentialId, validateSessionUserAgent,
  HELD_NAME_REQUESTED, HELD_NAME_REQUEST_LAPSED,
} from '../packages/typescript/dist/v1alpha2/account-metadata.js';

const fixture = JSON.parse(readFileSync(new URL('./fixtures/account-metadata.json', import.meta.url), 'utf8'));
const unicode = JSON.parse(readFileSync(new URL('./fixtures/passkey-label-unicode.json', import.meta.url), 'utf8'));
test('account wire vectors match Rust', () => {
  const vectors = JSON.parse(readFileSync(new URL('./fixtures/account-management-wire.json', import.meta.url), 'utf8'));
  const values = {
    RemovePasskeyRequest: { clientOperationId: 'remove-1', passkey: { id: 'passkey-1' }, expectedVersion: new Uint8Array(32).fill(1) },
    SetDisplayNameRequest: { clientOperationId: 'name-1', displayName: 'José' },
    SetPrimaryHandleRequest: { clientOperationId: 'primary-1', handle: 'alice' },
    RemoveHandleRequest: { clientOperationId: 'handle-1', handle: 'alice2' },
    PasskeyRecord: { createdAt: { seconds: 1n }, lastUsedAt: { seconds: 2n }, aaguid: new Uint8Array(16), authenticatorName: 'Key' },
    CurrentCredentialRecord: { passkeyCredentialId: new Uint8Array([1, 2]) },
    SessionRecord: { userAgent: 'Browser', deviceLabel: 'Laptop' },
    ObserveIdentityRequest: { sessions: {}, sessionState: api.SessionStateFilter.ACTIVE },
  };
  assert.equal(vectors.length, Object.keys(values).length);
  for (const { type, hex } of vectors) {
    const schema = api[`${type}Schema`];
    const value = create(schema, values[type]);
    assert.equal(Buffer.from(toBinary(schema, value)).toString('hex'), hex, type);
    assert.deepEqual(fromBinary(schema, new Uint8Array(Buffer.from(hex, 'hex'))), value, type);
  }
});

test('account metadata uses shared Rust bounds and passkey Unicode policy', () => {
  for (const normalize of [normalizeDisplayName, normalizeAdvisoryLabel]) {
    for (const { input, normalized } of [...fixture.labels, ...unicode]) {
      if (normalized === undefined) assert.throws(() => normalize(input));
      else assert.equal(normalize(input), normalized);
    }
    for (const { character, count, valid } of fixture.label_bounds) {
      if (valid) assert.equal(normalize(character.repeat(count)), character.repeat(count).normalize('NFC'));
      else assert.throws(() => normalize(character.repeat(count)), /256 UTF-8 bytes/);
    }
    assert.throws(() => normalize('\ud800'), /forbidden Unicode/);
  }
  for (const [vectors, validate] of [[fixture.aaguid, validateAaguid], [fixture.credential_ids, validatePasskeyCredentialId]]) {
    for (const { length, valid } of vectors) {
      const value = length === null ? undefined : new Uint8Array(length);
      if (valid) assert.doesNotThrow(() => validate(value));
      else assert.throws(() => validate(value));
    }
  }
  for (const { character, count, valid } of fixture.user_agents) {
    if (valid) assert.doesNotThrow(() => validateSessionUserAgent(character.repeat(count)));
    else assert.throws(() => validateSessionUserAgent(character.repeat(count)));
  }
  assert.throws(() => validateSessionUserAgent('\ud800'), /invalid Unicode/);
  assert.equal(HELD_NAME_REQUESTED, 'HELD_NAME_REQUESTED');
  assert.equal(HELD_NAME_REQUEST_LAPSED, 'HELD_NAME_REQUEST_LAPSED');
});

test('account RPCs expose receipt and CAS with additive identity fields', () => {
  for (const name of ['removePasskey', 'setDisplayName', 'setPrimaryHandle', 'removeHandle']) {
    const method = api.IdentityService.method[name];
    assert.ok(method, name);
    assert.equal(method.input.fields.find(f => f.name === 'client_operation_id')?.number, 1);
    if (name === 'removePasskey') assert.equal(method.input.fields.find(f => f.name === 'expected_version')?.number, 3);
    assert.equal(method.output.fields.find(f => f.name === 'receipt')?.message.typeName, 'heddle.api.v1alpha2.MutationReceipt');
  }
  for (const [schema, fields] of [
    [api.PasskeyRecordSchema, { created_at: 6, last_used_at: 7, aaguid: 8, authenticator_name: 9 }],
    [api.SessionRecordSchema, { user_agent: 8, device_label: 11 }],
    [api.CurrentCredentialRecordSchema, { passkey_credential_id: 18 }],
    [api.PrincipalRecordSchema, { actions: 9, display_name: 12 }],
    [api.ObserveIdentityRequestSchema, { sessions: 2, session_state: 10 }],
  ]) {
    for (const [name, tag] of Object.entries(fields)) assert.equal(schema.fields.find(f => f.name === name)?.number, tag);
  }
  assert.equal(create(api.ObserveIdentityRequestSchema).sessionState, api.SessionStateFilter.UNSPECIFIED);
  assert.equal(api.SessionStateFilter.ACTIVE, 1);
  assert.equal(api.SessionStateFilter.ENDED, 2);
  assert.equal(api.SessionStateFilter.ALL, 3);
  for (const [schema, field, value] of [
    [api.PasskeyRecordSchema, 'aaguid', new Uint8Array(16)],
    [api.PasskeyRecordSchema, 'authenticatorName', 'Security key'],
    [api.CurrentCredentialRecordSchema, 'passkeyCredentialId', new Uint8Array([1, 2])],
    [api.SessionRecordSchema, 'deviceLabel', 'Work browser'],
  ]) {
    const absent = create(schema);
    assert.equal(absent[field], undefined);
    const present = create(schema, { [field]: value });
    assert.deepEqual(fromBinary(schema, toBinary(schema, present)), present);
  }
});
