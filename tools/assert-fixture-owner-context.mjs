// Maintenance guard, deliberately separate from the carrier validators. Owner
// roots and transitions are checked by the locked published native verifier.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { toBinary } from '@bufbuild/protobuf';
import { OwnerHistorySchema } from '../packages/typescript/dist/v1alpha2/owner_records_pb.js';
const hex=b=>Buffer.from(b).toString('hex');
const verified=new Map();
export function assertFixtureOwnerContext(codec,label,histories,chain,identity,admissionMillis,transfers=[]){
 const at=admissionMillis/1000n;
 // The current corpus has no handoffs. Fail closed if a future generator adds
 // one until its accepted-transfer timeline is covered by this semantic guard.
 assert.equal(transfers.length,0,`${label}: add native transfer timeline verification before generating handoff positives`);
 assert.equal(identity.ownershipTransferSequence,0n,`${label}: owner transfer at admission`);
 assert.equal(chain.transferAuditHashes.length,0,`${label}: owner-chain transfers at admission`);
 assert.equal(hex(chain.spoolGenesisDigest),hex(identity.spoolGenesisDigest),`${label}: Spool lineage`);
 const endpoints=chain.ownerStateHashes.map(state=>{
  const history=histories.find(h=>hex(h.stateHash)===hex(state));
  assert.ok(history,`${label}: retained owner-chain endpoint`);
  const bytes=hex(toBinary(OwnerHistorySchema,history)),cacheKey=`${at}:${bytes}`;
  if(!verified.has(cacheKey)){
   // A future rotation in a selected endpoint is rejected here, even if the
   // identity selects a different (older) endpoint in that same chain.
   const result=execFileSync(codec,['verify-owner-history',String(at)],{input:bytes,encoding:'utf8',stdio:['pipe','pipe','pipe']}).trim();
   assert.equal(result,hex(state),`${label}: verified owner state at admission`);
   verified.set(cacheKey,true);
  }
  return history;
 });
 const selected=endpoints.find(h=>hex(h.stateHash)===hex(identity.ownerStateHash));
 assert.ok(selected,`${label}: signed owner is a selected chain endpoint at admission`);
 assert.equal(hex(selected.root.root.ownerId),hex(identity.ownerId),`${label}: owner identity`);
 if(identity.ownerAccountUuid)assert.equal(hex(selected.root.root.accountUuid),hex(identity.ownerAccountUuid),`${label}: owner account`);
 const sameOwner=endpoints.filter(h=>hex(h.root.root.ownerId)===hex(identity.ownerId));
 assert.equal(selected.acceptedTransitions.length,Math.max(...sameOwner.map(h=>h.acceptedTransitions.length)),`${label}: signed owner is the chain state at witnessed admission`);
}
