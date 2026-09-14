import assert from 'node:assert/strict';
import { test } from 'node:test';
import { create, fromBinary, toBinary, fromJson, toJson } from '@bufbuild/protobuf';
import { ReplicationOperationsSchema, ThreadGenesisRecordSchema } from '../packages/typescript/dist/v2alpha1/sync_pb.js';
const evidence = { format: 'heddle-original-boundary-acceptance-v1', canonicalRecord: new Uint8Array([0, 255, 19, 72]), signatures: [{ publicKey: new Uint8Array(32).fill(7), signature: new Uint8Array(64).fill(9) }] };
for (const [name, schema, original] of [
  ['operation batch', ReplicationOperationsSchema, { operations: [{ ...evidence, format: 'unchanged-original' }], authorityAdmissions: [{ ...evidence, format: 'unchanged-receipt' }] }],
  ['genesis and claims', ThreadGenesisRecordSchema, { genesis: evidence, creatorAuthority: new Uint8Array([11, 17]), admission: evidence, ownershipClaims: [evidence], ownershipClaimAdmissions: [evidence] }],
]) {
  test(`${name} preserves populated acceptance bytes and signatures through generated binary and JSON mappings`, () => {
    const value = create(schema, { ...original, boundaryAcceptances: [evidence] });
    assert.equal(value.boundaryAcceptances.length, 1);
    const binary = fromBinary(schema, toBinary(schema, value));
    assert.deepEqual(binary, value);
    const json = toJson(schema, binary);
    assert.equal(json.boundaryAcceptances.length, 1);
    assert.deepEqual(fromJson(schema, json), value);
    assert.deepEqual(binary.boundaryAcceptances[0].canonicalRecord, evidence.canonicalRecord);
    assert.deepEqual(binary.boundaryAcceptances[0].signatures[0].signature, evidence.signatures[0].signature);
  });
}
