import { create, toBinary, toJson } from '@bufbuild/protobuf';
import { sha256 } from '@noble/hashes/sha2.js';
import { writeFileSync } from 'node:fs';
import * as p from '../packages/typescript/dist/v1alpha2/immutable_objects_pb.js';
import * as c from '../packages/typescript/dist/v1alpha2/immutable-objects.js';
import { blake3 } from '@noble/hashes/blake3.js';
const bytes = (n, length = 32) => new Uint8Array(length).fill(n);
const hex = b => Buffer.from(b).toString('hex');
const treeData = new TextEncoder().encode('immutable-tree-vector');
const blobData = new TextEncoder().encode('immutable-blob-vector');
const root = { kind: 1, algorithm: 'blake3', digest: blake3(treeData) };
const blob = { kind: 2, algorithm: 'blake3', digest: blake3(blobData) };
const snapshot = create(p.ImmutableObjectSnapshotSchema, {
  formatVersion: 1, hostPublicKey: bytes(1), userId: bytes(2,16), principalSha256: bytes(3),
  spoolId: bytes(4,16), threadId: bytes(5), stateId: bytes(6), viewDigest: bytes(7),
  authorizationEpoch: 8n, visibilityEpoch: 9n, rootTree: root,
  inventory: [{id: root, decodedLength: BigInt(treeData.length)}, {id: blob, decodedLength: BigInt(blobData.length)}],
  limits: c.OBJECT_LIMITS, authorizedAtUnixSeconds: 1800000000n, expiresAtUnixSeconds: 1800000060n,
  maxCacheTtlSeconds: c.DEFAULT_MAX_CACHE_TTL_SECONDS,
});
const authorityBinding = c.objectAuthorityBinding(snapshot);
const thread = {spool: {id: '04040404-0404-0404-0404-040404040404'}, id: {value: bytes(5)}};
const sessionHandle = bytes(10,16);
const openRequest = create(p.OpenObjectSnapshotRequestSchema, {thread,
  revision: {spool: thread.spool, revision: {case:'state',value:{value: bytes(6)}}}, limits: c.OBJECT_LIMITS});
const openResponse = create(p.OpenObjectSnapshotResponseSchema, {snapshot, authorityBinding, sessionHandle});
const request = create(p.ReadObjectsRequestSchema, {thread, authorityBinding, sessionHandle,
  objects: [{id: root, offset:0n, length:treeData.length}, {id:blob, offset:0n, length:blobData.length}]});
const chunks = [treeData,blobData].map((data,i) => ({id:request.objects[i].id, codec:'identity',
  decodedLength:BigInt(data.length), offset:0n, data, chunkSha256:sha256(data)}));
const partialResponse = create(p.ReadObjectsResponseSchema, {authorityBinding, chunks:chunks.slice(0,1), nextObjectIndex:1, complete:false});
const response = create(p.ReadObjectsResponseSchema, {authorityBinding, chunks, nextObjectIndex:2, complete:true});
const rangeRequest = create(p.ReadObjectsRequestSchema, {thread, authorityBinding, sessionHandle, objects:[{id:blob,offset:10n,length:blobData.length-10}]});
const rangeResponse = create(p.ReadObjectsResponseSchema, {authorityBinding, chunks:[{...chunks[1], offset:10n,
  data:blobData.slice(10),chunkSha256:sha256(blobData.slice(10))}], nextObjectIndex:1,complete:true});
c.validateObjectOpenResponse(openRequest,openResponse,1800000000n);
for (const [req,res] of [[request,partialResponse],[request,response],[rangeRequest,rangeResponse]]) c.validateObjectReadResponse(snapshot,req,res,1800000000n);
const vectors = Object.entries({snapshot,openRequest,openResponse,request,partialResponse,response,rangeRequest,rangeResponse}).map(([name,value]) => {
  const schema = {snapshot:p.ImmutableObjectSnapshotSchema,openRequest:p.OpenObjectSnapshotRequestSchema,
    openResponse:p.OpenObjectSnapshotResponseSchema,request:p.ReadObjectsRequestSchema,partialResponse:p.ReadObjectsResponseSchema,
    response:p.ReadObjectsResponseSchema,rangeRequest:p.ReadObjectsRequestSchema,rangeResponse:p.ReadObjectsResponseSchema}[name];
  return {name,json:toJson(schema,value),protobufHex:hex(toBinary(schema,value))};
});
writeFileSync('tests/fixtures/immutable-objects-v1.json', JSON.stringify({format:1,authorityBinding:hex(authorityBinding),
  cacheKeys:request.objects.map(r=>hex(c.objectCacheKey(authorityBinding,r))), vectors},null,2)+'\n');
