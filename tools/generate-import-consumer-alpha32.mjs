// Add consumer vectors without regenerating any existing signed/wire record.
import {readFileSync,writeFileSync} from 'node:fs';
import {create,fromBinary,toBinary,clone} from '@bufbuild/protobuf';
import * as api from '../packages/typescript/dist/v1alpha2/index.js';
const old=JSON.parse(readFileSync('tests/fixtures/import-job-control-alpha31.json'));
const signed=JSON.parse(readFileSync('tests/fixtures/import-authority-host-witness-v1.json'));
const f={format_version:1,wire_vectors:{},availability:[],state_negatives:[],recovery:[],receipt_negatives:[]};
const v=name=>{const r=old.wire_vectors[name]??signed.wire_vectors[name]??signed.signed_vectors[name];return fromBinary(api[r.schema.split('.').at(-1)+'Schema'],Buffer.from(r.wire_hex,'hex'));};
const wire=(name,s,value)=>{f.wire_vectors[name]={schema:s.typeName,wire_hex:Buffer.from(toBinary(s,value)).toString('hex')};};
const available={case:'available',value:true},unavailable=value=>({case:'unavailable',value});
// Expected controls are explicit data, independent of the implementation.
for(const [id,base,account,change,expect] of [
 ['owner','control_connected_state','owner',{},[available,available,available]],
 ['connected_co_writer','control_connected_state','co-writer',{},[unavailable(1),unavailable(1),available]],
 ['public_co_writer','control_public_state','co-writer',{},[available,available,available]],
 ['cancelled','control_connected_state','owner',{terminal:true},[unavailable(3),unavailable(3),unavailable(3)]],
 ['lost_grant','control_connected_state','owner',{grants:false},[unavailable(2),unavailable(2),available]],
 ['replacement_connection','control_connected_state','owner',{replacement:true},[unavailable(2),unavailable(2),available]],
 ['commit_unavailable','control_connected_state','owner',{commits:false},[unavailable(6),unavailable(6),available]],
 ['no_retry_target','control_unavailable_1','owner',{},[unavailable(5),available,available]],
 ['expired','control_connected_state','owner',{now:1300},[unavailable(7),available,available]],
 ['before_window','control_connected_state','owner',{now:999},[unavailable(8),available,available]],
 ['original_window_ended','control_connected_state','owner',{now:1300,admitted:false},[unavailable(4),unavailable(4),available]],
]){
 const read=v(base);read.controlAvailability=create(api.ImportJobControlAvailabilityV1Schema,Object.fromEntries(['retry','renew','cancel'].map((key,i)=>[key,create(api.ImportControlAvailabilityV1Schema,{availability:expect[i]})])));
 if(change.terminal)read.retryAvailability={case:'retryUnavailable',value:4};
 const name='consumer_controls_'+id;wire(name,api.GetImportJobStateResponseSchema,read);
 f.availability.push({id,read:name,caller:account,change,expected:expect.map(x=>x.case==='available'?'AVAILABLE':api.ImportControlUnavailableReason[x.value])});
}
const base=fromBinary(api.GetImportJobStateResponseSchema,Buffer.from(f.wire_vectors.consumer_controls_owner.wire_hex,'hex'));
for(const [id,mutate] of [
 ['missing_controls',r=>r.controlAvailability=undefined],
 ['missing_retry',r=>r.controlAvailability.retry=undefined],
 ['missing_renew',r=>r.controlAvailability.renew=undefined],
 ['missing_cancel',r=>r.controlAvailability.cancel=undefined],
 ['missing_discriminant',r=>r.controlAvailability.retry.availability={case:undefined}],
 ['false_available',r=>r.controlAvailability.retry.availability={case:'available',value:false}],
 ['zero_reason',r=>r.controlAvailability.retry.availability=unavailable(0)],
 ['unknown_reason',r=>r.controlAvailability.renew.availability=unavailable(99)],
]){const read=clone(api.GetImportJobStateResponseSchema,base);mutate(read);const name='consumer_bad_'+id;wire(name,api.GetImportJobStateResponseSchema,read);f.state_negatives.push({id,read:name,expected:'Canonical',control:'consumer_controls_owner'});}
f.recovery=[
 {id:'no_set_no_snapshot',bundle:'review_scheduled_recovery',remove_set:true,input:false,expected_advanced:false,expected_snapshot:false},
 {id:'no_set_with_snapshot',bundle:'review_scheduled_recovery',remove_set:true,input:true,expected_advanced:false,expected_snapshot:true},
 {id:'same_set',bundle:'review_scheduled_recovery',input:true,expected_advanced:false,expected_snapshot:true},
 {id:'new_set',bundle:'review_scheduled_recovery',input:false,expected_advanced:true,expected_snapshot:true},
 {id:'replacement_set',bundle:'review_scheduled_recovery',initial_set:'retired_set',input:true,replacement:true,expected_advanced:true,expected_snapshot:true},
];
f.receipt_negatives=[
 {id:'modified_observation',bundle:'review_control',change:'observation',expected:'Signature'},
 {id:'modified_signature',bundle:'review_control',change:'signature',expected:'Signature'},
 {id:'missing_set_with_receipts',bundle:'review_control',change:'remove_set',expected:'Canonical'},
 {id:'untrusted_recovery_set',bundle:'review_scheduled_recovery',change:'set_signature',expected:'Signature'},
];
writeFileSync('tests/fixtures/import-consumer-alpha32.json',JSON.stringify(f,null,2)+'\n');
console.log('alpha.32 consumer vectors added; existing fixture bytes untouched');
