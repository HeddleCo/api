import {readFileSync} from 'node:fs';
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {clone,create,fromBinary} from '@bufbuild/protobuf';
import * as api from '../packages/typescript/dist/v1alpha2/index.js';
import * as authority from '../packages/typescript/dist/v1alpha2/import-authority.js';
const recipe=JSON.parse(readFileSync(new URL('./fixtures/import-discovery-v1.json',import.meta.url)));
const fixture=JSON.parse(readFileSync(new URL('./fixtures/import-authority-host-witness-v1.json',import.meta.url)));
const expected=reason=>error=>error instanceof authority.HybridContractError&&error.reason===reason;
const source=hashAlgorithm=>create(api.ProviderRepositorySchema,{cloneUrl:'https://github.com/example/repo.git',hashAlgorithm});
const hex=bytes=>Buffer.from(bytes).toString('hex');
function refs(hashAlgorithm){
 const width=hashAlgorithm===1?40:64,result=[];
 for(const [key,kind,offset] of [['branches',1,0],['pull_requests',3,8000],['tags',2,16000]])for(let i=0;i<recipe[key];i++){
  const name=kind===1?`refs/heads/b${String(i).padStart(5,'0')}`:kind===3?`refs/pull/${i+1}/head`:`refs/tags/v${String(i).padStart(5,'0')}`;
  result.push(create(api.ProviderRefSchema,{name,headOid:(i+offset).toString(16).padStart(width,'0'),kind,hashAlgorithm}));
 }
 return result.sort((a,b)=>Buffer.compare(Buffer.from(a.name),Buffer.from(b.name)));
}
const selected=r=>create(api.ImportBranchLimitV1Schema,{refName:r.name,hashAlgorithm:r.hashAlgorithm,refMode:1,pinnedCommitOid:Buffer.from(r.headOid,'hex'),genesisDigest:new Uint8Array(32).fill(1),targetThreadId:new Uint8Array(32).fill(2),expectedFrontierDigest:new Uint8Array(32).fill(3)});
const validator=(s,selection=[],mode='prepare')=>new authority.DiscoveryValidator(s,true,selection,{includePullRequestRefs:true},mode);
for(const vector of recipe.vectors)test(`20,000 refs: Rust/TS digest parity SHA${vector.hash_algorithm===1?1:256}`,()=>{
 const list=refs(vector.hash_algorithm),selection=[0,8500,15999].map(i=>selected(list[i]));
 for(const pageSize of [1,127,512]){
  const v=validator(source(vector.hash_algorithm),selection);
  for(let i=0;i<list.length;i+=pageSize)v.pushPage(list.slice(i,i+pageSize));
  const digest=v.finish();assert.equal(digest.refCount,recipe.ref_count);assert.equal(hex(digest.digest),vector.sha256);
  assert.throws(()=>v.finish(),expected('Canonical'));assert.throws(()=>v.pushPage([]),expected('Canonical'));
 }
 const whole=source(vector.hash_algorithm);whole.refs=list;
 assert.equal(hex(authority.discoverRepository(whole,selection,{includePullRequestRefs:true}).digest),vector.sha256);
 console.log(`DISCOVERY PARITY ${recipe.ref_count} refs, algorithm ${vector.hash_algorithm}: ${vector.sha256}`);
});
test('bad records reject on their page; failed validators cannot finish',()=>{
 for(const [mutate,reason] of [
  [r=>r.hashAlgorithm=1,'SourceSelection'],[r=>r.name='refs/heads/b00511','Canonical'],
  [r=>r.name='z'.repeat(1025),'Bounds'],[r=>r.headOid='A'.repeat(64),'Canonical'],
  [r=>r.kind=2,'SourceSelection'],[r=>r.name='refs/pull/01/head','Canonical'],[r=>r.headOid='0'.repeat(63)+'\n','Canonical']
 ]){
  const list=refs(2),v=validator(source(2));mutate(list[512]);v.pushPage(list.slice(0,512));
  assert.throws(()=>v.pushPage(list.slice(512,1024)),expected(reason));assert.throws(()=>v.pushPage([]),expected('Canonical'));assert.throws(()=>v.finish(),expected('Canonical'));
 }
});
test('selected membership, pins, namespace, UTF-8 and page bounds',()=>{
 const list=refs(2),selection=selected(list[0]);
 const absent=validator(source(2),[selection]);absent.pushPage([]);assert.throws(()=>absent.finish(),expected('SourceSelection'));
 selection.pinnedCommitOid.fill(9);
 assert.throws(()=>validator(source(2),[selection]).pushPage(list.slice(0,1)),expected('RefPinning'));
 const commit=validator(source(2),[selection],'commit');commit.pushPage(list.slice(0,1));commit.finish();
 assert.throws(()=>validator(source(2)).pushPage(list.slice(0,513)),expected('Bounds'));
 for(const name of ['refs/pull/0/head','refs/pull/01/head','refs/pull/1/merge','refs/pull/-1/head','refs/pull/1/head/x','refs/pull/1/head\n','refs/pull/1/head\u2028','refs/heads/\ud800'])
  assert.throws(()=>validator(source(2)).pushPage([create(api.ProviderRefSchema,{name,hashAlgorithm:2})]),expected('Canonical'));
 assert.throws(()=>new authority.DiscoveryValidator(source(2),true).pushPage(list.slice(8000,8001)),expected('Canonical'));
 const unknown=source(0),v=new authority.DiscoveryValidator(unknown,false);v.pushPage([]);v.finish();
 assert.throws(()=>new authority.DiscoveryValidator(unknown,true),expected('Version'));
 // Options and selected protobufs are copied; later mutation grants nothing.
 const options={includePullRequestRefs:false},mutable=selected(list[0]),v2=new authority.DiscoveryValidator(source(2),true,[mutable],options);
 mutable.refName=list[1].name;mutable.pinnedCommitOid.fill(9);options.includePullRequestRefs=true;
 v2.pushPage(list.slice(0,1));v2.finish();
});
test('safety ceiling accepts exactly 1,048,576 refs and refuses the next page',()=>{
 const at=validator(source(1)),over=validator(source(1));
 for(let start=0;start<authority.MAX_IMPORT_SOURCE_REFS;start+=512){
  const page=Array.from({length:512},(_,j)=>create(api.ProviderRefSchema,{name:`refs/heads/b${String(start+j).padStart(7,'0')}`,hashAlgorithm:1,kind:1}));
  at.pushPage(page);over.pushPage(page);
 }
 assert.equal(at.finish().refCount,authority.MAX_IMPORT_SOURCE_REFS);
 assert.throws(()=>over.pushPage([create(api.ProviderRefSchema,{name:'refs/heads/z',hashAlgorithm:1,kind:1})]),expected('Bounds'));
});
function legacy(s,known){
 const size=s.hashAlgorithm===1?40:s.hashAlgorithm===2?64:s.hashAlgorithm===0&&!known?undefined:(()=>{throw new authority.HybridContractError('Version')})();
 if(s.refs.length>4096)throw new authority.HybridContractError('Bounds');
 s.refs.forEach((r,i)=>{
  const fail=reason=>{throw new authority.HybridContractError(reason);};
  if(Buffer.byteLength(r.name)>1024)fail('Bounds');if(r.hashAlgorithm!==s.hashAlgorithm)fail('SourceSelection');
  if(i&&Buffer.compare(Buffer.from(s.refs[i-1].name),Buffer.from(r.name))>=0)fail('Canonical');
  if(r.headOid){if(size===undefined)fail('Version');if(r.headOid.length!==size)fail('SourceSelection');if(!/^[0-9a-f]+$/.test(r.headOid))fail('Canonical');}
 });
}
function outcome(fn){try{fn();return 'ok';}catch(e){assert.ok(e instanceof authority.HybridContractError);return e.reason;}}
test('incremental and former one-pass agree on every existing repository fixture',()=>{
 let count=0;
 for(const group of ['wire_vectors','signed_vectors'])for(const [name,record] of Object.entries(fixture[group])){
  if(record.schema!==api.ProviderRepositorySchema.typeName)continue;
  const s=fromBinary(api.ProviderRepositorySchema,Buffer.from(record.wire_hex,'hex'));
  for(const known of [false,true])assert.equal(outcome(()=>{
   const v=new authority.DiscoveryValidator(s,known);for(let i=0;i<s.refs.length;i+=512)v.pushPage(s.refs.slice(i,i+512));v.finish();
  }),outcome(()=>legacy(s,known)),`${name}: known=${known}`);
  count++;
 }
 assert.ok(count>20,`fixture inventory must be exercised: ${count}`);console.log(`DISCOVERY FIXTURE PARITY: ${count} repositories, known/unknown modes`);
});
function vector(name){const v=fixture.signed_vectors[name]??fixture.wire_vectors[name];return fromBinary(api[`${v.schema.split('.').at(-1)}Schema`],Buffer.from(v.wire_hex,'hex'));}
test('paged evidence admits Prepare/Commit and is bound to source, selection and phase',async()=>{
 const configuration=vector('import_configuration'),prepare=vector('prepare_public_sha256'),current=vector('source_public_sha256'),scope=prepare.proposedScope;
 current.refs=['dev','main'].map(n=>create(api.ProviderRefSchema,{name:`refs/heads/${n}`,kind:1,hashAlgorithm:current.hashAlgorithm}));
 const metadata=clone(api.ProviderRepositorySchema,current);metadata.refs=[];
 const p=validator(metadata,scope.branches);p.pushPage(current.refs);const evidence=p.finish();
 authority.prepareImportSourceScopeWithDiscovery(prepare,metadata,undefined,configuration,vector('scope').destinationVersion,evidence);
 const altered=clone(api.ProviderRepositorySchema,metadata);altered.hashAlgorithm=1;
 assert.throws(()=>authority.prepareImportSourceScopeWithDiscovery(prepare,altered,undefined,configuration,vector('scope').destinationVersion,evidence),expected('SourceSelection'));
 const changed=vector('prepare_public_sha256');changed.proposedScope.branches[0].targetThreadId.fill(9);
 assert.throws(()=>authority.prepareImportSourceScopeWithDiscovery(changed,metadata,undefined,configuration,vector('scope').destinationVersion,evidence),expected('SourceSelection'));
 assert.throws(()=>authority.prepareImportSourceScopeWithDiscovery(prepare,metadata,undefined,configuration,vector('scope').destinationVersion,{...evidence}),expected('SourceSelection'));
 const request=vector('commit_request'),connected=vector('source_connected'),selected=request.proof.delegations[0].body.scope.branches;
 connected.refs=['dev','main'].map(n=>create(api.ProviderRefSchema,{name:`refs/heads/${n}`,kind:1,hashAlgorithm:connected.hashAlgorithm}));
 const commitMetadata=clone(api.ProviderRepositorySchema,connected);commitMetadata.refs=[];
 const c=validator(commitMetadata,selected,'commit');c.pushPage(connected.refs);const committed=c.finish();
 await authority.validateImportCommitRequestWithDiscovery(request,'github',commitMetadata,configuration,committed);
 const wrong=validator(commitMetadata,selected);wrong.pushPage(connected.refs);
 await assert.rejects(authority.validateImportCommitRequestWithDiscovery(request,'github',commitMetadata,configuration,wrong.finish()),expected('SourceSelection'));
});
test('resolve option accepts PR heads and selections stay bounded at 256',()=>{
 const resolved=vector('source_public_sha256');resolved.refs=[create(api.ProviderRefSchema,{name:'refs/pull/42/head',headOid:'0'.repeat(64),hashAlgorithm:2,kind:3})];
 const request=create(api.ResolveImportSourceRequestSchema,{source:create(api.ProviderRepositorySchema,{cloneUrl:resolved.cloneUrl,providerRepositoryId:resolved.providerRepositoryId}),includeRefs:true,includePullRequestRefs:true});
 const response=create(api.ResolveImportSourceResponseSchema,{source:resolved});
 authority.validateResolveImportSourceResponse(request,response);
 request.includePullRequestRefs=false;assert.throws(()=>authority.validateResolveImportSourceResponse(request,response),expected('Canonical'));
 const list=refs(2),selection=list.slice(0,256).map(selected),v=validator(source(2),selection);v.pushPage(list.slice(0,256));v.finish();
 assert.throws(()=>validator(source(2),[...selection,selection[0]]),expected('Bounds'));
 const unicodeOid=create(api.ProviderRefSchema,{...list[0],headOid:'é'.repeat(64)});
 assert.throws(()=>validator(source(2)).pushPage([unicodeOid]),expected('SourceSelection'));
});
