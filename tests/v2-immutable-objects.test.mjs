import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { blake3 } from '@noble/hashes/blake3.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { clone, create, fromBinary, fromJson, toBinary } from '@bufbuild/protobuf';
import * as p from '../packages/typescript/dist/v1alpha2/immutable_objects_pb.js';
import * as c from '../packages/typescript/dist/v1alpha2/immutable-objects.js';
const f = JSON.parse(readFileSync(new URL('./fixtures/immutable-objects-v1.json', import.meta.url)));
const hex = b => Buffer.from(b).toString('hex');
const schemas = {snapshot:p.ImmutableObjectSnapshotSchema,openRequest:p.OpenObjectSnapshotRequestSchema,
  openResponse:p.OpenObjectSnapshotResponseSchema,request:p.ReadObjectsRequestSchema,partialResponse:p.ReadObjectsResponseSchema,
  response:p.ReadObjectsResponseSchema,rangeRequest:p.ReadObjectsRequestSchema,rangeResponse:p.ReadObjectsResponseSchema};
const vector = name => fromJson(schemas[name], f.vectors.find(v=>v.name===name).json);
const copy = (name) => clone(schemas[name], vector(name));
const now = 1800000000n;
const rejects = (reason, fn) => assert.throws(fn, e => e instanceof c.ObjectContractError && e.reason === reason);

test('shared golden JSON/protobuf round trips, binding, cache keys and resumed prefixes', () => {
  for (const v of f.vectors) {
    assert.equal(hex(toBinary(schemas[v.name],fromJson(schemas[v.name],v.json))),v.protobufHex);
    assert.equal(hex(toBinary(schemas[v.name],fromBinary(schemas[v.name],Buffer.from(v.protobufHex,'hex')))),v.protobufHex);
  }
  const s = vector('snapshot'), r = vector('request');
  assert.equal(hex(c.objectAuthorityBinding(s)),f.authorityBinding);
  assert.deepEqual(r.objects.map(o=>hex(c.objectCacheKey(r.authorityBinding,o))),f.cacheKeys);
  c.validateObjectOpenResponse(vector('openRequest'),vector('openResponse'),now);
  c.validateObjectReadResponse(s,r,vector('partialResponse'),now);
  c.validateObjectReadResponse(s,r,vector('response'),now);
  c.validateObjectReadResponse(s,vector('rangeRequest'),vector('rangeResponse'),now);
  assert.deepEqual(c.decodeObjectSnapshot(toBinary(schemas.snapshot,s)),s);
  assert.deepEqual(c.decodeObjectReadRequest(toBinary(schemas.request,r)),r);
  const res=vector('response'); assert.deepEqual(c.decodeObjectReadResponse(toBinary(schemas.response,res),s.limits),res);
});
test('over-limit batch rejects', () => {
  const s=vector('snapshot'),r=copy('request');s.inventory=s.inventory.slice(0,1);r.objects=[];
  for(let i=0;i<513;i++) {
    const digest=new Uint8Array(32);new DataView(digest.buffer).setUint32(28,i);
    const id={kind:2,algorithm:'blake3',digest};
    s.inventory.push(create(p.ImmutableObjectInventoryEntrySchema,{id,decodedLength:1n}));
    r.objects.push(create(p.ImmutableObjectRangeSchema,{id,offset:0n,length:1}));
  }
  r.authorityBinding=c.objectAuthorityBinding(s);
  const boundary=clone(p.ReadObjectsRequestSchema,r);boundary.objects.pop();c.validateObjectReadRequest(s,boundary,now);
  rejects('Limits',()=>c.validateObjectReadRequest(s,r,now));
});
test('malformed IDs and unavailable inventory members reject', () => {
  for (const field of ['digest','algorithm','kind','unavailable']) {
    const r=copy('request'),id=r.objects[0].id;
    if(field==='digest')id.digest=id.digest.slice(1);
    if(field==='algorithm')id.algorithm='sha256';
    if(field==='kind')id.kind=0;
    if(field==='unavailable')id.digest=new Uint8Array(32).fill(99);
    rejects(field==='unavailable'?'Unavailable':'Malformed',()=>c.validateObjectReadRequest(vector('snapshot'),r,now));
  }
});
test('binding and cache key include all authority scopes', () => {
  const r=vector('request');
  for(const key of ['hostPublicKey','userId','principalSha256','spoolId','threadId','stateId','viewDigest',
    'authorizationEpoch','visibilityEpoch','maxCacheTtlSeconds','inventory','limits']) {
    const s=copy('snapshot');
    if(s[key] instanceof Uint8Array)s[key][0]^=1;
    else if(key==='inventory')s.inventory[0].decodedLength+=1n;
    else if(key==='limits')s.limits.maxBatchObjects-=1;
    else s[key]+=typeof s[key]==='bigint'?1n:1;
    rejects('Binding',()=>c.validateObjectReadRequest(s,r,now));
    assert.notEqual(hex(c.objectCacheKey(c.objectAuthorityBinding(s),r.objects[0])),f.cacheKeys[0]);
  }
  const wrong=copy('request');wrong.thread.id.value[0]^=1;
  rejects('Binding',()=>c.validateObjectReadRequest(vector('snapshot'),wrong,now));
  const open=copy('openRequest');open.revision.revision={case:'gitCommitOid',value:'a'.repeat(40)};
  rejects('Malformed',()=>c.validateObjectOpenResponse(open,vector('openResponse'),now));
});
test('TTL is exclusive, host configurable, and cache hits cannot renew it', () => {
  const s=vector('snapshot'),r=vector('request');c.validateObjectReadRequest(s,r,now+59n);
  rejects('Expired',()=>c.validateObjectReadRequest(s,r,now+60n));
  rejects('Expired',()=>c.validateObjectReadRequest(s,r,now-1n));
  s.expiresAtUnixSeconds+=1n;rejects('Limits',()=>c.validateObjectSnapshot(s));
  s.maxCacheTtlSeconds=120;c.validateObjectSnapshot(s);
});
test('lengths, all advertised limits, and pre-decode wire caps reject', () => {
  const s=vector('snapshot'),r=copy('request');r.objects[0].offset=0xffffffffffffffffn;
  rejects('Limits',()=>c.validateObjectReadRequest(s,r,now));
  r.objects[0].offset=0n;r.objects[0].length=c.OBJECT_LIMITS.maxChunkBytes+1;
  rejects('Limits',()=>c.validateObjectReadRequest(s,r,now));
  const huge=copy('snapshot');huge.inventory[0].decodedLength=0xffffffffffffffffn;
  rejects('Limits',()=>c.validateObjectSnapshot(huge));
  const unordered=copy('snapshot');unordered.inventory.reverse();rejects('Malformed',()=>c.validateObjectSnapshot(unordered));
  for(const key of Object.keys(c.OBJECT_LIMITS)) {
    const l={...s.limits};l[key]+=typeof l[key]==='bigint'?1n:1;rejects('Limits',()=>c.validateObjectLimits(l));
  }
  rejects('Limits',()=>c.decodeObjectReadRequest(new Uint8Array(c.MAX_REQUEST_WIRE_BYTES+1)));
  rejects('Limits',()=>c.decodeObjectSnapshot(new Uint8Array(c.MAX_SNAPSHOT_WIRE_BYTES+1)));
  rejects('Limits',()=>c.decodeObjectReadResponse(new Uint8Array(c.OBJECT_LIMITS.maxResponseBytes+1),s.limits));
});
test('altered codec, chunk, declared length, ID, binding and completion reject', () => {
  for(const field of ['codec','chunk','length','offset','id','hash','index','complete','binding','empty']) {
    const response=copy('response'),chunk=response.chunks[0];
    if(field==='codec')chunk.codec='zstd';if(field==='chunk')chunk.data[0]^=1;
    if(field==='length')chunk.decodedLength=0xffffffffffffffffn;if(field==='offset')chunk.offset+=1n;
    if(field==='id')chunk.id.kind=2;if(field==='hash')chunk.chunkSha256=chunk.chunkSha256.slice(1);
    if(field==='index')response.nextObjectIndex=1;if(field==='complete')response.complete=false;
    if(field==='binding')response.authorityBinding[0]^=1;if(field==='empty')response.chunks=[];
    rejects(field==='binding'?'Binding':'Integrity',()=>c.validateObjectReadResponse(vector('snapshot'),vector('request'),response,now));
  }
});

test('response byte budget admits an exact prefix and refuses the full envelope', () => {
  const s=vector('snapshot'),r=vector('request'),partial=vector('partialResponse'),full=vector('response');
  s.limits.maxResponseBytes=toBinary(schemas.partialResponse,partial).length;s.limits.maxChunkBytes=32;
  r.authorityBinding=c.objectAuthorityBinding(s);partial.authorityBinding=r.authorityBinding;full.authorityBinding=r.authorityBinding;
  c.validateObjectReadResponse(s,r,partial,now);
  rejects('Limits',()=>c.validateObjectReadResponse(s,r,full,now));
});
test('empty blob completes one range, while out-of-bounds empty ranges refuse', () => {
  const s=vector('snapshot'),r=vector('request');
  const id=create(p.ImmutableObjectIdSchema,{kind:2,algorithm:'blake3',digest:blake3(new Uint8Array())});
  s.inventory[1]=create(p.ImmutableObjectInventoryEntrySchema,{id,decodedLength:0n});
  r.authorityBinding=c.objectAuthorityBinding(s);r.objects=[create(p.ImmutableObjectRangeSchema,{id})];
  const response=create(p.ReadObjectsResponseSchema,{authorityBinding:r.authorityBinding,chunks:[{id,codec:'identity',
    decodedLength:0n,offset:0n,data:new Uint8Array(),chunkSha256:sha256(new Uint8Array())}],nextObjectIndex:1,complete:true});
  c.validateObjectReadResponse(s,r,response,now);
  r.objects[0].offset=1n;rejects('Limits',()=>c.validateObjectReadRequest(s,r,now));
});

test('bounded decoders reject repeated empty messages before allocation', () => {
  const repeated = (tag, count) => Uint8Array.from({length:count*2},(_,i)=>i%2===0?tag:0);
  rejects('Limits',()=>c.decodeObjectReadRequest(repeated(0x22,513)));
  rejects('Limits',()=>c.decodeObjectReadResponse(repeated(0x12,513),vector('snapshot').limits));
  rejects('Limits',()=>c.decodeObjectSnapshot(repeated(0x62,4097)));
});
test('opening selection is validated before data lookup', () => {
  const request=vector('openRequest');c.validateObjectOpenRequest(request);
  request.revision.spool.id='05050505-0505-0505-0505-050505050505';
  rejects('Binding',()=>c.validateObjectOpenRequest(request));
  const malformed=vector('openRequest');malformed.thread.spool.id='not-a-uuid';
  rejects('Malformed',()=>c.validateObjectOpenRequest(malformed));
  const zero=vector('openRequest');zero.limits.maxBatchObjects=0;rejects('Limits',()=>c.validateObjectOpenRequest(zero));
});
test('bounded decoders discard unknown fields without retaining a per-field allocation', () => {
  for(const [name,decode] of [['request',c.decodeObjectReadRequest],['snapshot',c.decodeObjectSnapshot],
    ['response',bytes=>c.decodeObjectReadResponse(bytes,vector('snapshot').limits)]]) {
    const original=toBinary(schemas[name],vector(name));
    // Unknown field 31 repeated 4096 times, below each wire byte cap.
    const bytes=new Uint8Array(original.length+3*4096);bytes.set(original);
    for(let i=original.length;i<bytes.length;i+=3)bytes.set([0xfa,0x01,0],i);
    assert.equal(hex(toBinary(schemas[name],decode(bytes))),hex(original));
  }
});
