import { clone, create, toBinary } from "@bufbuild/protobuf";
import * as api from "./import_authority_pb.js";
import { CommitImportJobRequestSchema, ProviderRepositorySchema, ResolveImportSourceResponseSchema, type CommitImportJobRequest, type ImportSourceRequest, type ProviderRepository, type ResolveImportSourceRequest, type ResolveImportSourceResponse, type RetryImportSourceRequest } from "./integration_pb.js";
import { RecordRefSchema, SpoolRefSchema } from "./common_pb.js";
import type { HybridImportJobSelector, MutationResponse, OperationRecord, SpoolRef } from "./common_pb.js";
import { SignedSpoolOwnerGenesisSchema, OwnerHistorySchema, ResourceTransferAuditRecordSchema, SignedSpoolPolicyRecordSchema, type AuthorizationSignature } from "./owner_records_pb.js";
import type { ProtocolCompatibility } from "../common/contract_pb.js";
import { SignedHostedWitnessSetV1Schema, HostedWitnessStatementV1Schema, SignedHostedWitnessStatementV1Schema, HostedWitnessHistoryProofV1Schema, type SignedHostedWitnessSetV1, type HostedWitnessStatementV1, type SignedHostedWitnessStatementV1, type HostedWitnessHistoryProofV1 } from "../common/hosted_witness_pb.js";
import { resolveWitnessStatement, restoreWitnessHistorySnapshot, verifyWitnessSetAfterRootReplacement, verifyWitnessSet, verifyWitnessInclusion, leafDigest, recheckWitnessContext, type WitnessSetExpectation, type ResolvedWitnessStatement, type VerifiedWitnessSet } from "./witness-trust.js";
import { canonicalHybridV1, signingDigest, equal, width, keyId, verifySignature, reject, canonicalHttps, hash, compare, sized, utf8, HybridContractError } from "./_hybrid-codec.js";
export { canonicalHybridV1, signingDigest, strictDecode, HybridContractError } from "./_hybrid-codec.js";

export const PERMISSION_DOMAIN="heddle-import-member-permission-v1",GENESIS_DOMAIN="heddle-import-genesis-authority-v1",DELEGATION_DOMAIN="heddle-import-job-delegation-v1",RENEWAL_DOMAIN="heddle-import-job-renewal-v1",OPERATION_DOMAIN="heddle-delegated-import-operation-v1",MANIFEST_DOMAIN="heddle-import-result-manifest-v1";
export const MAX_BRANCHES=256,MAX_RECORD_BYTES=65536,MAX_BUNDLE_BYTES=1048576;
export const MAX_COMMIT_REQUEST_BYTES=2*MAX_BUNDLE_BYTES;
export const CANCELLATION_NAMESPACE="heddle-import-cancel-v1";
export const signedPermissionDigest=(v:api.SignedImportMemberPermissionV1)=>signingDigest("heddle-signed-import-member-permission-v1",api.SignedImportMemberPermissionV1Schema,v);
export const signedGenesisDigest=(v:api.SignedImportGenesisAuthorityV1)=>signingDigest("heddle-signed-import-genesis-authority-v1",api.SignedImportGenesisAuthorityV1Schema,v);
export const signedDelegationDigest=(v:api.SignedImportJobDelegationV1)=>signingDigest("heddle-signed-import-job-delegation-v1",api.SignedImportJobDelegationV1Schema,v);
export const signedOperationDigest=(v:api.SignedDelegatedImportOperationV1)=>signingDigest("heddle-signed-delegated-import-operation-v1",api.SignedDelegatedImportOperationV1Schema,v);
export const manifestDigest=(v:api.ImportResultManifestV1)=>signingDigest(MANIFEST_DOMAIN,api.ImportResultManifestV1Schema,v);
export function ownerChainDigest(v:api.ImportOwnerChainV1):Uint8Array{width(v.spoolGenesisDigest,32);if(!v.ownerStateHashes.length||v.ownerStateHashes.length>64||v.transferAuditHashes.length>64)reject("Bounds");for(const h of [...v.ownerStateHashes,...v.transferAuditHashes])width(h,32);for(let i=1;i<v.ownerStateHashes.length;i++){const a=v.ownerStateHashes[i-1]!,b=v.ownerStateHashes[i]!;let cmp=0;for(let j=0;j<32;j++){if(a[j]!==b[j]){cmp=a[j]!-b[j]!;break;}}if(cmp>=0)reject("Canonical");}return signingDigest("heddle-import-owner-chain-v1",api.ImportOwnerChainV1Schema,v);}

function identity(v:api.ImportIdentityV1|undefined):asserts v is api.ImportIdentityV1{if(!v)reject("Canonical");for(const b of [v.spoolUuid,v.ownerAccountUuid]){width(b,16);if(!b.some(Boolean))reject("Canonical");}for(const b of [v.spoolGenesisDigest,v.ownerId,v.ownerStateHash])width(b,32);}
function sameIdentity(a:api.ImportIdentityV1,b:api.ImportIdentityV1):boolean{return equal(canonicalHybridV1(api.ImportIdentityV1Schema,a),canonicalHybridV1(api.ImportIdentityV1Schema,b));}
function interval(start:bigint,end:bigint,now:bigint){if(start<0n||end<=start)reject("Semantic");if(now<start||now>=end)reject("Expired");}
// No synthetic historical observation time is used by structural validation.
function validity(start:bigint,end:bigint,now:bigint,current:boolean){if(start<0n||end<=start)reject("Semantic");if(current)interval(start,end,now);}
function branch(v:api.ImportBranchLimitV1){if(!v.refName.startsWith("refs/heads/")||v.refName.length>1024||v.refName.endsWith("/")||v.refName.endsWith(".")||v.refName.includes("..")||v.refName.includes("//")||v.refName.includes("@{")||v.refName.split("/").some(p=>p.startsWith(".")||p.endsWith(".lock"))||!/^[A-Za-z0-9/_\-.]+$/.test(v.refName))reject("Canonical");const size=v.hashAlgorithm===1?20:v.hashAlgorithm===2?32:reject("Version");if(v.refMode===1){width(v.pinnedCommitOid,size);if(v.refDisclosure!==0)reject("RefDisclosure");}else if(v.refMode===2&&!v.pinnedCommitOid.length){if(v.refDisclosure!==1)reject("RefDisclosure");}else reject("Semantic");for(const b of [v.genesisDigest,v.targetThreadId,v.expectedFrontierDigest])width(b,32);}
export function validateImportScope(v:api.ImportPermissionScopeV1){canonicalHttps(v.sourceUrl);if(!/^[a-z0-9-]{1,64}$/.test(v.provider)||!v.converterVersion||v.converterVersion.length>128||!/^[\x00-\x7f]+$/.test(v.converterVersion))reject("Canonical");width(v.destinationVersion,32);width(v.optionsDigest,32);if(!v.branches.length||v.branches.length>MAX_BRANCHES||v.maxOperations<=0||v.maxOperations>MAX_BRANCHES||v.maxResultBytes<=0n||v.maxResultBytes>=(1n<<64n))reject("Bounds");if(v.maxOperations<v.branches.length)reject("Scope");v.branches.forEach((b,i)=>{branch(b);if(i&&v.branches[i-1]!.refName>=b.refName)reject("Canonical");});}
function branchSubset(c:api.ImportBranchLimitV1,p:api.ImportBranchLimitV1):boolean{return equal(canonicalHybridV1(api.ImportBranchLimitV1Schema,c),canonicalHybridV1(api.ImportBranchLimitV1Schema,p));}

/** Compare independently observed OID knowledge before preparing/signing. */
export function validateImportRefSelection(value:api.ImportBranchLimitV1, knownCommitOid?:Uint8Array):void {
  branch(value);
  if (knownCommitOid !== undefined) {
    width(knownCommitOid, value.hashAlgorithm === 1 ? 20 : 32);
    if (value.refMode !== 1 || !equal(value.pinnedCommitOid, knownCommitOid)) reject("RefPinning");
  }
}

export function conversionOptionsDigest(version:string, options:Uint8Array):Uint8Array {
  if (!version || version.length > 128 || !/^[\x00-\x7f]+$/.test(version)) reject("Canonical");
  if (options.length > 4096) reject("Bounds");
  return hash(utf8.encode("heddle-import-conversion-options-v1"), sized(utf8.encode(version)), sized(options));
}

/** Current authenticated connection identity selects custody; domains never do. */
export function resolveImportProvider(source:ProviderRepository, connectionProvider?:string):"github"|"public-git" {
  canonicalHttps(source.cloneUrl);
  if(utf8.encode(source.providerRepositoryId).length>4096||utf8.encode(source.name).length>4096)reject("Bounds");
  if(source.connection){
    const positive=(v:string)=>/^[0-9]+$/.test(v)&&BigInt(v)>0n&&BigInt(v)<=0xffffffffffffffffn;
    if(connectionProvider!=="github"||source.connection.spool||!source.connection.id||!positive(source.providerRepositoryId)||!positive(source.installationId))reject("SourceSelection");
    const path=source.cloneUrl.startsWith("https://github.com/")?source.cloneUrl.slice(19).split("/"):[];
    if(path.length!==2||!path[0]||!path[1]?.endsWith(".git")||path[1].length<=4)reject("SourceSelection");
    return "github";
  }
  if(connectionProvider!==undefined||source.private||source.installationId||(source.providerRepositoryId&&source.providerRepositoryId!==source.cloneUrl))reject("SourceSelection");
  return "public-git";
}
function sourceSelection(source:ProviderRepository):api.ImportSourceSelectionV1 {
  return create(api.ImportSourceSelectionV1Schema,{connection:source.connection,providerRepositoryId:source.providerRepositoryId,installationId:source.installationId,private:source.private});
}
function sameSourceSelection(a:api.ImportSourceSelectionV1,b:api.ImportSourceSelectionV1):boolean {
  return equal(toBinary(api.ImportSourceSelectionV1Schema,a),toBinary(api.ImportSourceSelectionV1Schema,b));
}
/** Advisory Git storage size in KiB; UNKNOWN carries zero and grants nothing. */
export function validateRepositorySizeEstimate(source:ProviderRepository):void {
  if(source.sizeEstimateState===0&&source.gitSizeKib===0n)return;
  if(source.sizeEstimateState===1&&source.connection&&source.gitSizeKib>=0n&&source.gitSizeKib<=0xffffffffffffffffn)return;
  reject("Canonical");
}
/** Exact identity preservation; network/redirect policy and current grants are host gates. */
export function validateResolveImportSourceResponse(request:ResolveImportSourceRequest,response:ResolveImportSourceResponse,connectionProvider?:string):void {
  if(toBinary(ResolveImportSourceResponseSchema,response).length>MAX_BUNDLE_BYTES)reject("Bounds");
  const selected=request.source??reject("SourceSelection"),resolved=response.source??reject("SourceSelection");
  const provider=resolveImportProvider(selected,connectionProvider),selection=sourceSelection(selected);
  if(!selection.connection&&!selection.providerRepositoryId)selection.providerRepositoryId=selected.cloneUrl;
  if(resolveImportProvider(resolved,connectionProvider)!==provider||selected.cloneUrl!==resolved.cloneUrl
    ||!sameSourceSelection(selection,sourceSelection(resolved))
    ||(!resolved.connection&&resolved.providerRepositoryId!==selected.cloneUrl))reject("SourceSelection");
  validateRepositorySizeEstimate(resolved);
  validateRepositoryHashAlgorithm(resolved,false);
}
function validateRetainedImportSource(selector:api.ImportSourceSelectionV1,scope:api.ImportPermissionScopeV1):void {
  const source=create(ProviderRepositorySchema,{connection:selector.connection,providerRepositoryId:selector.providerRepositoryId,installationId:selector.installationId,private:selector.private,cloneUrl:scope.sourceUrl});
  if(resolveImportProvider(source,selector.connection?"github":undefined)!==scope.provider
    ||(!selector.connection&&selector.providerRepositoryId!==scope.sourceUrl))reject("SourceSelection");
}
export function validateRepositoryHashAlgorithm(source:ProviderRepository, known:boolean):void {
  const size=source.hashAlgorithm===1?40:source.hashAlgorithm===2?64:source.hashAlgorithm===0&&!known?undefined:reject("Version");
  if(source.refs.length>512)reject("Bounds");
  source.refs.forEach((r,i)=>{
    if(r.hashAlgorithm!==source.hashAlgorithm)reject("SourceSelection");
    if(i&&compare(utf8.encode(source.refs[i-1]!.name),utf8.encode(r.name))>=0)reject("Canonical");
    if(r.headOid){if(size===undefined)reject("Version");if(r.headOid.length!==size)reject("SourceSelection");if(!/^[0-9a-f]+$/.test(r.headOid))reject("Canonical");}
  });
}
export function validateDiscoveredImportScope(scope:api.ImportPermissionScopeV1, source:ProviderRepository):void {
  validateDiscoveredImportScopeInner(scope,source,false);
}
function validateDiscoveredImportScopeInner(scope:api.ImportPermissionScopeV1, source:ProviderRepository, retained:boolean):void {
  validateRepositoryHashAlgorithm(source,true);
  if(scope.sourceUrl!==source.cloneUrl)reject("SourceSelection");
  for(const b of scope.branches){
    if(b.hashAlgorithm!==source.hashAlgorithm)reject("SourceSelection");
    const text=source.refs.find(r=>r.name===b.refName)?.headOid;
    const oid=text?Uint8Array.from(text.match(/../g)!,v=>parseInt(v,16)):undefined;
    validateImportRefSelection(b,retained&&b.refMode===1?undefined:oid);
  }
}
/** Host rechecks current grants and selected-commit availability. Retained state
 * comes from an authenticated read or durable host state, bound to the verified token. */
export function prepareImportSourceScope(request:api.PrepareImportJobRequest, currentSource:ProviderRepository, connectionProvider:string|undefined, configuration:api.GetImportConfigurationResponse, currentDestinationVersion:Uint8Array, retained?:{predecessor:VerifiedImportRenewalPredecessor;state:api.ImportJobCasStateV1;source:api.ImportSourceSelectionV1}):api.ImportPermissionScopeV1 {
  const s=request.source??reject("SourceSelection");
  if(s.connection?.id!==currentSource.connection?.id||s.connection?.spool?.id!==currentSource.connection?.spool?.id||(s.providerRepositoryId!==currentSource.providerRepositoryId&&(s.connection!==undefined||s.providerRepositoryId!==""))||s.installationId!==currentSource.installationId||s.private!==currentSource.private)reject("SourceSelection");
  const scope=request.proposedScope??reject("Canonical");
  if(scope.provider!==resolveImportProvider(currentSource,connectionProvider))reject("SourceSelection");
  if(retained){
    const old=predecessors.get(retained.predecessor)??reject("Canonical"),state=retained.state;
    validateCasState(state);const previous=read(old.previous).body;
    if(!equal(signingDigest("heddle-import-job-cas-state-v1",api.ImportJobCasStateV1Schema,state),old.stateDigest)
      ||!equal(request.renewLogicalJobId,previous.logicalJobId)||!equal(request.retryLineageId,previous.retryLineageId)
      ||request.destination?.id!==initialImportOperationId(previous.identity!.spoolUuid,false))reject("StaleContext");
    validateRetainedImportSource(retained.source,previous.scope!);
    if(!sameSourceSelection(s,retained.source))reject("SourceSelection");
    const selected=clone(api.ImportPermissionScopeV1Schema,scope);
    if(!selected.destinationVersion.length)selected.destinationVersion=currentDestinationVersion.slice();
    remainingScope(selected,previous.scope!,state.committedManifest!);
  }else if(request.renewLogicalJobId.length)reject("StaleContext");
  validateDiscoveredImportScopeInner(scope,currentSource,Boolean(retained));
  return prepareImportScope(scope,configuration,currentDestinationVersion);
}
function validateProviderSupport(provider:string,configuration:api.GetImportConfigurationResponse):void {
  if(!configuration.providers.some(p=>p.provider===provider))reject("SourceSelection");
}

export function validateImportConfiguration(v:api.GetImportConfigurationResponse):void {
  if (toBinary(api.GetImportConfigurationResponseSchema,v).length > MAX_BUNDLE_BYTES || !v.converters.length || v.converters.length > 32) reject("Bounds");
  v.converters.forEach((c,i) => {
    for (const text of [c.converterVersion,c.optionsEncoding]) {
      if (!text || text.length > 128 || !/^[\x00-\x7f]+$/.test(text)) reject("Canonical");
    }
    if (i && v.converters[i-1]!.converterVersion >= c.converterVersion) reject("Canonical");
    if (!c.canonicalOptions.length || c.canonicalOptions.length > 64 || c.canonicalOptions.some(o=>o.length > 4096)) reject("Bounds");
    if (c.canonicalOptions.some((o,j)=>j>0 && compare(c.canonicalOptions[j-1]!,o)>=0) || !c.canonicalOptions.some(o=>equal(o,c.defaultOptions))) reject("Canonical");
  });
  if(!v.providers.length||v.providers.length>2)reject("Bounds");
  v.providers.forEach((p,i)=>{
    if(i&&v.providers[i-1]!.provider>=p.provider)reject("Canonical");
    const mode=p.provider==="github"?1:p.provider==="public-git"?2:reject("SourceSelection");
    if(p.sourceModes.length!==1||p.sourceModes[0]!==mode)reject("SourceSelection");
  });
  if(v.defaultConverterVersion!==undefined&&!v.converters.some(c=>c.converterVersion===v.defaultConverterVersion))reject("Canonical");
  const l=v.limits??reject("Canonical");
  if (l.maxBranches<=0 || l.maxBranches>MAX_BRANCHES || l.maxOperations<=0 || l.maxOperations>MAX_BRANCHES || l.maxResultBytes<=0n || l.maxResultBytes>=(1n<<64n)) reject("Bounds");
}

/** Host negotiation against CURRENT configuration and the current destination CAS. */
export function prepareImportScope(proposed:api.ImportPermissionScopeV1, configuration:api.GetImportConfigurationResponse, currentDestinationVersion:Uint8Array):api.ImportPermissionScopeV1 {
  const reason=api.ImportPreparationRefusalReason;
  const refuse=(r:api.ImportPreparationRefusalReason):never=>{throw new HybridContractError("PreparationRefused",r);};
  validateImportConfiguration(configuration);width(currentDestinationVersion,32);
  if (proposed.destinationVersion.length && proposed.destinationVersion.length!==32) refuse(reason.INVALID_SCOPE);
  if (proposed.destinationVersion.length && !equal(proposed.destinationVersion,currentDestinationVersion)) refuse(reason.DESTINATION_CONFLICT);
  const selected=clone(api.ImportPermissionScopeV1Schema,proposed);selected.destinationVersion=currentDestinationVersion.slice();
  try { validateImportScope(selected); } catch (error) { if (error instanceof HybridContractError) refuse(reason.INVALID_SCOPE); throw error; }
  try { validateProviderSupport(selected.provider,configuration); } catch { refuse(reason.INVALID_SCOPE); }
  const c=configuration.converters.find(c=>c.converterVersion===selected.converterVersion)??refuse(reason.UNSUPPORTED_CONVERTER);
  if (!c.canonicalOptions.some(o=>equal(conversionOptionsDigest(c.converterVersion,o),selected.optionsDigest))) refuse(reason.UNSUPPORTED_OPTIONS);
  const l=configuration.limits!;
  if (selected.branches.length>l.maxBranches || selected.maxOperations>l.maxOperations || selected.maxResultBytes>l.maxResultBytes) refuse(reason.BUDGET_EXCEEDED);
  return selected;
}

/** Complete independently retained original refs/slots for a non-terminal job.
 * Hosts read this inventory under the reservation/activation transaction. */
export interface ImportSpoolReservation {
  readonly spoolUuid: Uint8Array;
  readonly logicalJobId: Uint8Array;
  readonly branches: readonly api.ImportBranchLimitV1[];
}

/** Full refs and (full ref, slot_id) keys are exclusive per spool across jobs,
 * regardless of source. Same-job renewal keeps the original branch identity.
 * This check stores nothing; hosts atomically reserve the entire selection. */
export function checkImportSpoolReservations(spoolUuid:Uint8Array,logicalJobId:Uint8Array,scope:api.ImportPermissionScopeV1,reservations:readonly ImportSpoolReservation[]):void {
  initialImportOperationId(spoolUuid,false);initialImportOperationId(logicalJobId,false);validateImportScope(scope);
  for(const held of reservations){
    initialImportOperationId(held.spoolUuid,false);initialImportOperationId(held.logicalJobId,false);
    if(!equal(held.spoolUuid,spoolUuid))continue;
    const sameJob=equal(held.logicalJobId,logicalJobId);
    for(const selected of scope.branches){
      const conflict=sameJob?!held.branches.some(b=>branchSubset(selected,b)):held.branches.some(b=>b.refName===selected.refName);
      if(conflict)throw new HybridContractError("PreparationRefused",api.ImportPreparationRefusalReason.DESTINATION_CONFLICT);
    }
  }
}

/** Configuration/ownership/policy CAS at activation; other imports do not
 * advance it. Resolve exact stored receipt replay before calling this gate. */
export function checkImportDestinationVersion(scope:api.ImportPermissionScopeV1,currentDestinationVersion:Uint8Array):void {
  width(scope.destinationVersion,32);width(currentDestinationVersion,32);
  if(!equal(scope.destinationVersion,currentDestinationVersion))reject("StaleContext");
}

/** Caller comparison before signing; no silent negotiation, including reductions. */
export function validateImportPreparationResponse(request:api.PrepareImportJobRequest, response:api.PrepareImportJobResponse):void {
  const r=response.refusal;
  if (r) {
    if (r.reason<0 || r.reason>6) reject("Version");
    if (r.reason===0 || r.field.length>256 || !/^[\x00-\x7f]*$/.test(r.field) || response.proposal || response.renewalState || response.reservationExpiresAtUnixSeconds!==0n || response.preparedAtUnixSeconds!==0n || response.maxValidityDurationSeconds!==0n || response.clockSkewAllowanceSeconds!==0n) reject("Canonical");
    throw new HybridContractError("PreparationRefused",r.reason);
  }
  const p=response.proposal??reject("Canonical"),returned=p.scope??reject("Canonical");
  if (!request.proposedScope) reject("Canonical");
  const requested=clone(api.ImportPermissionScopeV1Schema,request.proposedScope);
  if (!requested.destinationVersion.length) requested.destinationVersion=returned.destinationVersion.slice();
  if (!equal(canonicalHybridV1(api.ImportPermissionScopeV1Schema,requested),canonicalHybridV1(api.ImportPermissionScopeV1Schema,returned)) || !request.identity || !p.identity || !sameIdentity(p.identity,request.identity) || !equal(p.retryLineageId,request.retryLineageId)) reject("PreparedFields");
  validateImportScope(returned);
  if (!request.renewLogicalJobId.length) {
    if (response.renewalState || p.predecessorDelegationDigest.some(Boolean)) reject("PreparedFields");
  } else {
    if (!equal(p.logicalJobId,request.renewLogicalJobId)) reject("PreparedFields");
    validateRenewalPreparation(response);
  }
}

/** Provider identity comes from an authenticated resolver, never projection hints.
 * Native base decoding/identity, source grants and atomic activation remain host gates. */
export async function validateImportCommitRequest(request:CommitImportJobRequest, resolvedProvider:string, currentSource:ProviderRepository, configuration:api.GetImportConfigurationResponse):Promise<void> {
  validateImportCommitRequestBounds(request);
  request=clone(CommitImportJobRequestSchema,request);
  const source=request.source??reject("SourceSelection"),proof=request.proof??reject("Canonical");
  if (!request.clientOperationId || utf8.encode(request.clientOperationId).length>128 || !request.destination?.id) reject("Canonical");
  if (request.initialBaseState.length>4096 || toBinary(api.ImportPublicProofBundleV1Schema,proof).length>MAX_BUNDLE_BYTES) reject("Bounds");
  if (proof.formatVersion!==1 || proof.delegations.length!==1 || proof.renewals.length || proof.operations.length || proof.terminalManifest || proof.manifests.length) reject("Canonical");
  const d=proof.delegations[0]!.body??reject("Canonical"),scope=d.scope??reject("Canonical");validateImportScope(scope);
  identity(d.identity);
  const uuid=Array.from(d.identity.spoolUuid,b=>b.toString(16).padStart(2,"0")).join("");
  const destinationId=`${uuid.slice(0,8)}-${uuid.slice(8,12)}-${uuid.slice(12,16)}-${uuid.slice(16,20)}-${uuid.slice(20)}`;
  if (request.destination.id!==destinationId) reject("Scope");
  if (d.predecessorDelegationDigest.length!==32 || d.predecessorDelegationDigest.some(Boolean)) reject("Canonical");
  if (source.cloneUrl!==scope.sourceUrl || resolvedProvider!==scope.provider || utf8.encode(source.providerRepositoryId).length>4096 || utf8.encode(source.name).length>4096) reject("SourceSelection");
  if(source.connection?.id!==currentSource.connection?.id||source.connection?.spool?.id!==currentSource.connection?.spool?.id||(source.providerRepositoryId!==currentSource.providerRepositoryId&&(source.connection!==undefined||source.providerRepositoryId!==""))||source.cloneUrl!==currentSource.cloneUrl||source.installationId!==currentSource.installationId||source.private!==currentSource.private)reject("SourceSelection");
  const provider=resolveImportProvider(currentSource,currentSource.connection?resolvedProvider:undefined);
  if(provider!==resolvedProvider)reject("SourceSelection");
  validateImportConfiguration(configuration);validateProviderSupport(provider,configuration);
  validateRepositoryHashAlgorithm(currentSource,true);
  if(source.hashAlgorithm!==currentSource.hashAlgorithm)reject("SourceSelection");
  // Frozen pins survive branch movement; known OIDs cannot be hidden in OBSERVE.
  for(const b of scope.branches){
    if(b.hashAlgorithm!==currentSource.hashAlgorithm)reject("SourceSelection");
    if(b.refMode===2&&currentSource.refs.some(r=>r.name===b.refName&&r.headOid!==""))reject("RefPinning");
  }
  prepareImportScope(scope,configuration,scope.destinationVersion);
  if (proof.originalGeneses.length!==scope.branches.length || proof.creatorAuthorityEnvelopes.length!==scope.branches.length || proof.genesisAuthorities.length!==scope.branches.length || d.branchManifest.length!==scope.branches.length) reject("GenesisBinding");
  for (const [i,b] of scope.branches.entries()) {
    const original=proof.originalGeneses[i]!,binding=proof.genesisAuthorities[i]!,g=binding.body??reject("GenesisBinding"),m=d.branchManifest[i]!,envelope=proof.creatorAuthorityEnvelopes[i]!;
    if (!equal(nativeOctetsId(original.format,original.canonicalRecord),b.genesisDigest) || !equal(g.genesisDigest,b.genesisDigest) || !m.limit || !equal(canonicalHybridV1(api.ImportBranchLimitV1Schema,m.limit),canonicalHybridV1(api.ImportBranchLimitV1Schema,b)) || !equal(m.genesisAuthorityDigest,signedGenesisDigest(binding)) || !equal(g.creatorAuthorityEnvelopeDigest,hash(envelope)) || !envelope.length || envelope.length>MAX_RECORD_BYTES || !original.signatures.some(s=>equal(s.publicKey,g.creatorPublicKey)&&equal(s.signature,g.originalCreatorSignature))) reject("GenesisBinding");
    await verifyNativeRecord(original,"heddle-thread-genesis-v1");
  }
}

export function validateImportSource(_request:ImportSourceRequest):never { return reject("ImportSourceRequiresCommit"); }

/** Complete initial validation; native model/owner history and live transaction
 * checks remain the hosted implementation's responsibility. */
export async function verifyImportCommitSubmission(request:CommitImportJobRequest, prepared:api.PrepareImportJobResponse, resolvedProvider:string, currentSource:ProviderRepository, configuration:api.GetImportConfigurationResponse, e:ImportOwnerExpectation):Promise<VerifiedImportDelegation> {
  request=clone(CommitImportJobRequestSchema,request);prepared=clone(api.PrepareImportJobResponseSchema,prepared);e=snapshotExpectation(e);
  await validateImportCommitRequest(request,resolvedProvider,currentSource,configuration);
  const proof=request.proof!,member=proof.memberPermission??proof.memberPermissions[0];
  if (proof.memberPermissions.length>1 || (proof.memberPermissions[0] && (!member || !equal(canonicalHybridV1(api.SignedImportMemberPermissionV1Schema,proof.memberPermissions[0]),canonicalHybridV1(api.SignedImportMemberPermissionV1Schema,member))))) reject("ImportPermission");
  return verifyPreparedImportDelegation(prepared,proof.delegations[0]!,member,proof.genesisAuthorities,e);
}

export function validateImportCommitResponse(request:CommitImportJobRequest, response:MutationResponse):void {
  const r=response.receipt;
  if (!r || r.outcome.case!=="pendingOperation" || !request.clientOperationId || r.clientOperationId!==request.clientOperationId || !request.destination || r.outcome.value.spool?.id!==request.destination.id || r.outcome.value.id!==initialImportOperationId(request.proof?.delegations[0]?.body?.retryLineageId??reject("PendingOperation"),false)) reject("PendingOperation");
}

/** Host looks up its durable caller-scoped row before revalidating expired authority. */
export function checkImportCommitReplay(request:CommitImportJobRequest, stored:CommitImportJobRequest, response:MutationResponse):void {
  if (!equal(toBinary(CommitImportJobRequestSchema,request),toBinary(CommitImportJobRequestSchema,stored))) reject("OperationIdReused");
  validateImportCommitResponse(request,response);
}
function subset(c:api.ImportPermissionScopeV1,p:api.ImportPermissionScopeV1):boolean{return c.provider===p.provider&&c.sourceUrl===p.sourceUrl&&equal(c.destinationVersion,p.destinationVersion)&&equal(c.optionsDigest,p.optionsDigest)&&c.converterVersion===p.converterVersion&&c.maxOperations<=p.maxOperations&&c.maxResultBytes<=p.maxResultBytes&&c.branches.every(b=>p.branches.some(a=>branchSubset(b,a)));}
export interface ImportOwnerExpectation{identity:api.ImportIdentityV1;ownerPublicKey:Uint8Array;ownerChainDigest:Uint8Array;/** Effective selected owner state at nowUnixSeconds; immutable-root deadlines do not survive claim. */authorityExpiresAtSeconds:bigint;nowUnixSeconds:bigint;forbiddenJobKeys:readonly Uint8Array[];knownJobAssociations:readonly {key:Uint8Array;logicalJobId:Uint8Array}[];}
function snapshotExpectation(e:ImportOwnerExpectation):ImportOwnerExpectation{return {...e,identity:clone(api.ImportIdentityV1Schema,e.identity),ownerPublicKey:e.ownerPublicKey.slice(),ownerChainDigest:e.ownerChainDigest.slice(),forbiddenJobKeys:e.forbiddenJobKeys.map(k=>k.slice()),knownJobAssociations:e.knownJobAssociations.map(a=>({key:a.key.slice(),logicalJobId:a.logicalJobId.slice()}))};}
async function auth(key:Uint8Array,domain:string,schema:Parameters<typeof canonicalHybridV1>[0],body:Parameters<typeof canonicalHybridV1>[1],sig:AuthorizationSignature|undefined){if(!sig||!equal(sig.signerKeyId,keyId(key)))reject("Signature");if(canonicalHybridV1(schema,body).length>MAX_RECORD_BYTES)reject("Bounds");await verifySignature(key,signingDigest(domain,schema,body),sig.signature);}
export async function verifyImportMemberPermission(signed:api.SignedImportMemberPermissionV1,e:ImportOwnerExpectation){return verifyMemberPermissionInner(signed,e,true);}
async function verifyMemberPermissionInner(signed:api.SignedImportMemberPermissionV1,e:ImportOwnerExpectation,current:boolean){e=snapshotExpectation(e);signed=clone(api.SignedImportMemberPermissionV1Schema,signed);const p=signed.body;if(!p||p.formatVersion!==1||p.purpose!==1)reject("ImportPermission");identity(p.identity);if(!sameIdentity(p.identity,e.identity)||!equal(p.ownerChainDigest,e.ownerChainDigest))reject("Root");width(p.logicalJobId,16);width(p.retryLineageId,16);width(p.subjectPublicKey,32);for(const b of [p.cancellationId,p.nonce,p.ownerChainDigest])width(b,32);if(!p.scope)reject("Canonical");validateImportScope(p.scope);validity(p.notBeforeUnixSeconds,p.expiresAtUnixSeconds,e.nowUnixSeconds,current);if(p.expiresAtUnixSeconds>e.authorityExpiresAtSeconds)reject("Scope");await auth(e.ownerPublicKey,PERMISSION_DOMAIN,api.ImportMemberPermissionV1Schema,p,signed.ownerSignature);}
const checked=new WeakMap<object,{body:api.ImportJobDelegationV1;digest:Uint8Array;member:api.SignedImportMemberPermissionV1|undefined}>();
export interface VerifiedImportDelegation{readonly body:api.ImportJobDelegationV1;readonly digest:Uint8Array;}
function read(d:VerifiedImportDelegation){return checked.get(d)??reject("Canonical");}
export async function verifyImportDelegation(signed:api.SignedImportJobDelegationV1,member:api.SignedImportMemberPermissionV1|undefined,e:ImportOwnerExpectation):Promise<VerifiedImportDelegation>{
  return verifyDelegationInner(signed,member,e,true);
}
async function verifyDelegationInner(signed:api.SignedImportJobDelegationV1,member:api.SignedImportMemberPermissionV1|undefined,e:ImportOwnerExpectation,current:boolean):Promise<VerifiedImportDelegation>{
  e=snapshotExpectation(e);member=member?clone(api.SignedImportMemberPermissionV1Schema,member):undefined;
  const snapshot=clone(api.SignedImportJobDelegationV1Schema,signed),d=snapshot.body;if(!d)reject("Canonical");if(d.formatVersion!==1||d.purpose!==1)reject("Version");identity(d.identity);if(!sameIdentity(d.identity,e.identity)||!equal(d.ownerChainDigest,e.ownerChainDigest))reject("Root");for(const b of [d.delegationId,d.logicalJobId,d.retryLineageId]){width(b,16);if(!b.some(Boolean))reject("Canonical");}for(const b of [d.jobPublicKey,d.jobKeyId,d.delegatingPublicKey,d.parentPermissionDigest,d.ownerChainDigest,d.cancellationId,d.predecessorDelegationDigest])width(b,32);if(!equal(d.jobKeyId,keyId(d.jobPublicKey)))reject("Canonical");if(equal(d.jobPublicKey,d.delegatingPublicKey)||equal(d.jobPublicKey,e.ownerPublicKey)||e.forbiddenJobKeys.some(k=>equal(k,d.jobPublicKey)))reject("KeyRole");if(e.knownJobAssociations.some(a=>equal(a.key,d.jobPublicKey)&&!equal(a.logicalJobId,d.logicalJobId)))reject("Scope");if(!d.scope)reject("Canonical");validateImportScope(d.scope);if(d.branchManifest.length!==d.scope.branches.length)reject("Scope");d.branchManifest.forEach((m,i)=>{width(m.genesisAuthorityDigest,32);if(!m.limit||!equal(canonicalHybridV1(api.ImportBranchLimitV1Schema,m.limit),canonicalHybridV1(api.ImportBranchLimitV1Schema,d.scope!.branches[i]!)))reject("Scope");});validity(d.notBeforeUnixSeconds,d.expiresAtUnixSeconds,e.nowUnixSeconds,current);if(d.expiresAtUnixSeconds>e.authorityExpiresAtSeconds)reject("Scope");
  if(equal(d.delegatingPublicKey,e.ownerPublicKey)){if(member||d.parentPermissionDigest.some(Boolean))reject("ImportPermission");}
  else{if(!member)reject("ImportPermission");await verifyMemberPermissionInner(member,e,current);const p=member.body!;if(!equal(d.parentPermissionDigest,signedPermissionDigest(member))||!equal(d.delegatingPublicKey,p.subjectPublicKey)||!equal(d.logicalJobId,p.logicalJobId)||!equal(d.retryLineageId,p.retryLineageId)||d.notBeforeUnixSeconds<p.notBeforeUnixSeconds||d.expiresAtUnixSeconds>p.expiresAtUnixSeconds||!subset(d.scope,p.scope!))reject("Scope");}
  await auth(d.delegatingPublicKey,DELEGATION_DOMAIN,api.ImportJobDelegationV1Schema,d,snapshot.delegatingSignature);const digest=signedDelegationDigest(snapshot);const result={get body(){return clone(api.ImportJobDelegationV1Schema,d);},get digest(){return digest.slice();}};checked.set(result,{body:d,digest,member});return result;
}
/** Exact server-frozen projection; no normalization of signed scope. */
export function delegationPreparation(d:api.ImportJobDelegationV1):api.ImportJobPreparationV1 {
  return create(api.ImportJobPreparationV1Schema, {
    formatVersion:d.formatVersion, identity:d.identity, delegationId:d.delegationId,
    logicalJobId:d.logicalJobId, retryLineageId:d.retryLineageId, jobPublicKey:d.jobPublicKey,
    jobKeyId:d.jobKeyId, ownerChainDigest:d.ownerChainDigest, purpose:d.purpose,
    scope:d.scope, cancellationId:d.cancellationId, predecessorDelegationDigest:d.predecessorDelegationDigest,
  });
}
/** Compare with HOST-STORED preparation and independently selected authority.
 * Native originals, online revocation and transactional activation remain host
 * gates. Renewal's retained genesis bindings use their original context. */
export async function verifyPreparedImportDelegation(
  prepared:api.PrepareImportJobResponse, signed:api.SignedImportJobDelegationV1,
  member:api.SignedImportMemberPermissionV1|undefined, geneses:readonly api.SignedImportGenesisAuthorityV1[],
  e:ImportOwnerExpectation,
):Promise<VerifiedImportDelegation> {
  return verifyPreparedInner(prepared,signed,member,geneses,e,false);
}
/** Browser signing preflight only. Returns no execution/admission token. */
export async function preflightPreparedImportDelegation(prepared:api.PrepareImportJobResponse,signed:api.SignedImportJobDelegationV1,member:api.SignedImportMemberPermissionV1|undefined,geneses:readonly api.SignedImportGenesisAuthorityV1[],e:ImportOwnerExpectation):Promise<void>{
  await verifyPreparedInner(prepared,signed,member,geneses,e,true);
}
async function verifyPreparedInner(prepared:api.PrepareImportJobResponse,signed:api.SignedImportJobDelegationV1,member:api.SignedImportMemberPermissionV1|undefined,geneses:readonly api.SignedImportGenesisAuthorityV1[],e:ImportOwnerExpectation,browser:boolean):Promise<VerifiedImportDelegation>{
  // Snapshot every caller-owned input before the first asynchronous signature check.
  prepared=clone(api.PrepareImportJobResponseSchema,prepared);
  signed=clone(api.SignedImportJobDelegationV1Schema,signed);
  member=member?clone(api.SignedImportMemberPermissionV1Schema,member):undefined;
  geneses=geneses.map(g=>clone(api.SignedImportGenesisAuthorityV1Schema,g));e=snapshotExpectation(e);
  const p=prepared.proposal??reject("Canonical"),d=signed.body??reject("Canonical");
  if(!equal(canonicalHybridV1(api.ImportJobPreparationV1Schema,p),canonicalHybridV1(api.ImportJobPreparationV1Schema,delegationPreparation(d))))reject("PreparedFields");
  const scope=p.scope??reject("Canonical");
  if(d.branchManifest.length!==scope.branches.length)reject("PreparedFields");
  d.branchManifest.forEach((m,i)=>{
    if(!m.limit||!equal(canonicalHybridV1(api.ImportBranchLimitV1Schema,m.limit),canonicalHybridV1(api.ImportBranchLimitV1Schema,scope.branches[i]!)))reject("PreparedFields");
  });
  const now=e.nowUnixSeconds,start=d.notBeforeUnixSeconds,end=d.expiresAtUnixSeconds,
    at=prepared.preparedAtUnixSeconds,skew=prepared.clockSkewAllowanceSeconds;
  if(at<0n||now<0n||(browser?now+skew<at:now<at)||prepared.reservationExpiresAtUnixSeconds!==at+3600n||now>=prepared.reservationExpiresAtUnixSeconds)reject("Expired");
  if(prepared.maxValidityDurationSeconds===0n||start<0n||start<at-skew||start>now+skew||end<=start||end<=now||end-start>prepared.maxValidityDurationSeconds)reject("ValidityBounds");
  if(member){
    if(browser){await verifyMemberPermissionInner(member,e,false);const p=member.body!;if(p.notBeforeUnixSeconds>now+skew||p.expiresAtUnixSeconds<=now)reject("Expired");}
    else await verifyImportMemberPermission(member,e);
  }
  const verified=await verifyDelegationInner(signed,member,browser?e:{...e,nowUnixSeconds:now>start?now:start},!browser);
  if(geneses.length!==d.branchManifest.length)reject("GenesisBinding");
  for(const m of d.branchManifest){
    const branch=m.limit!,g=geneses.find(g=>equal(signedGenesisDigest(g),m.genesisAuthorityDigest))??reject("GenesisBinding"),body=g.body??reject("GenesisBinding");
    if(!equal(body.genesisDigest,branch.genesisDigest))reject("GenesisBinding");
    if(!d.predecessorDelegationDigest.some(Boolean))await verifyImportGenesisAuthority(g,verified,branch.genesisDigest,body.originalCreatorSignature,body.creatorAuthorityEnvelopeDigest);
  }
  return verified;
}
export async function verifyImportGenesisAuthority(signed:api.SignedImportGenesisAuthorityV1,delegation:VerifiedImportDelegation,genesisDigest:Uint8Array,originalSignature:Uint8Array,envelopeDigest:Uint8Array){const g=signed.body,d=read(delegation).body;if(!g)reject("Canonical");if(g.formatVersion!==1)reject("Version");width(g.originalCreatorSignature,64);for(const b of [g.genesisDigest,g.creatorPublicKey,g.creatorAuthorityEnvelopeDigest,g.parentPermissionDigest,g.ownerChainDigest])width(b,32);if(!g.identity||!sameIdentity(g.identity,d.identity!)||!equal(g.creatorPublicKey,d.delegatingPublicKey)||!equal(g.parentPermissionDigest,d.parentPermissionDigest)||!equal(g.ownerChainDigest,d.ownerChainDigest)||!equal(g.genesisDigest,genesisDigest)||!equal(g.originalCreatorSignature,originalSignature)||!equal(g.creatorAuthorityEnvelopeDigest,envelopeDigest)||!d.branchManifest.some(m=>m.limit&&equal(m.limit.genesisDigest,g.genesisDigest)&&equal(m.genesisAuthorityDigest,signedGenesisDigest(signed))))reject("Scope");await auth(g.creatorPublicKey,GENESIS_DOMAIN,api.ImportGenesisAuthorityV1Schema,g,signed.creatorSignature);}
export async function verifyDelegatedImportOperation(signed:api.SignedDelegatedImportOperationV1,delegation:VerifiedImportDelegation){const o=signed.body,{body:d,digest}=read(delegation);if(!o)reject("Canonical");if(o.formatVersion!==1)reject("Version");width(o.physicalOperationId,16);for(const b of [o.spoolGenesisDigest,o.delegationDigest,o.genesisDigest,o.targetThreadId,o.expectedFrontierDigest,o.resultingFrontierDigest,o.resultingContentDigest,o.optionsDigest])width(b,32);width(o.spoolUuid,16);width(o.logicalJobId,16);width(o.retryLineageId,16);const s=d.scope!,b=s.branches.find(b=>b.refName===o.refName&&b.slotId===o.slotId);if(!b)reject("Scope");width(o.observedCommitOid,o.hashAlgorithm===1?20:o.hashAlgorithm===2?32:reject("Version"));if(!equal(o.spoolUuid,d.identity!.spoolUuid)||!equal(o.spoolGenesisDigest,d.identity!.spoolGenesisDigest)||!equal(o.logicalJobId,d.logicalJobId)||!equal(o.retryLineageId,d.retryLineageId)||!equal(o.delegationDigest,digest)||o.hashAlgorithm!==b.hashAlgorithm||(b.refMode===1&&!equal(o.observedCommitOid,b.pinnedCommitOid))||!equal(o.genesisDigest,b.genesisDigest)||!equal(o.targetThreadId,b.targetThreadId)||!equal(o.expectedFrontierDigest,b.expectedFrontierDigest)||o.resultBytes>d.scope!.maxResultBytes||o.resultBytes===0n||!equal(o.optionsDigest,s.optionsDigest)||o.converterVersion!==s.converterVersion)reject("Scope");await auth(d.jobPublicKey,OPERATION_DOMAIN,api.DelegatedImportOperationV1Schema,o,signed.jobSignature);}
export async function verifyNewImportOperation(signed:api.SignedDelegatedImportOperationV1,d:VerifiedImportDelegation,now:bigint){const b=read(d).body;interval(b.notBeforeUnixSeconds,b.expiresAtUnixSeconds,now);await verifyDelegatedImportOperation(signed,d);}
export function validateImportManifest(m:api.ImportResultManifestV1){if(m.formatVersion!==1)reject("Version");width(m.logicalJobId,16);width(m.retryLineageId,16);if(m.slots.length>MAX_BRANCHES)reject("Bounds");m.slots.forEach((s,i)=>{width(s.signedOperationDigest,32);width(s.resultingFrontierDigest,32);if(!s.refName.startsWith("refs/heads/")||!/^[\x00-\x7f]+$/.test(s.refName))reject("Canonical");if(new TextEncoder().encode(s.refName).length>1024||s.resultBytes<=0n||s.resultBytes>=(1n<<64n))reject("Bounds");const p=m.slots[i-1];if(p&&(p.refName>s.refName||(p.refName===s.refName&&p.slotId>=s.slotId)))reject("Canonical");});}
export async function verifyImportRenewal(signed:api.SignedImportJobRenewalV1,previous:VerifiedImportDelegation,committed:api.ImportResultManifestV1,epoch:bigint,member:api.SignedImportMemberPermissionV1|undefined,e:ImportOwnerExpectation):Promise<VerifiedImportDelegation>{return verifyRenewalInner(signed,previous,committed,epoch,member,e,true);}
async function verifyRenewalInner(signed:api.SignedImportJobRenewalV1,previous:VerifiedImportDelegation,committed:api.ImportResultManifestV1,epoch:bigint,member:api.SignedImportMemberPermissionV1|undefined,e:ImportOwnerExpectation,current:boolean):Promise<VerifiedImportDelegation>{e=snapshotExpectation(e);signed=clone(api.SignedImportJobRenewalV1Schema,signed);committed=clone(api.ImportResultManifestV1Schema,committed);member=member?clone(api.SignedImportMemberPermissionV1Schema,member):undefined;const r=signed.body;if(!r)reject("Canonical");if(r.formatVersion!==1)reject("Version");validateImportManifest(committed);if(r.expectedAuthorityEpoch!==epoch)reject("StaleContext");const old=read(previous);if(!equal(r.predecessorDelegationDigest,old.digest))reject("RenewalFork");if(!equal(r.committedManifestDigest,manifestDigest(committed)))reject("StaleManifest");if(!r.replacement)reject("Canonical");const next=await verifyDelegationInner(r.replacement,member,e,current),after=read(next).body,before=old.body;if(!equal(after.logicalJobId,before.logicalJobId)||!equal(after.retryLineageId,before.retryLineageId)||!equal(committed.logicalJobId,before.logicalJobId)||!equal(committed.retryLineageId,before.retryLineageId)||!equal(after.identity!.spoolUuid,before.identity!.spoolUuid)||!equal(after.identity!.spoolGenesisDigest,before.identity!.spoolGenesisDigest)||!equal(after.predecessorDelegationDigest,old.digest)||equal(after.jobPublicKey,before.jobPublicKey)||equal(after.delegationId,before.delegationId))reject("RenewalFork");const os=before.scope!,ns=after.scope!;if(!subset(ns,os))reject("RenewalFork");let consumed=0n;for(const slot of committed.slots){const b=os.branches.find(b=>b.refName===slot.refName&&b.slotId===slot.slotId);if(b){consumed+=slot.resultBytes;}if(ns.branches.some(b=>b.refName===slot.refName&&b.slotId===slot.slotId))reject("CommittedSlot");}const removed=os.branches.filter(b=>committed.slots.some(s=>s.refName===b.refName&&s.slotId===b.slotId)).length;if(ns.maxOperations>os.maxOperations-removed||ns.maxResultBytes>os.maxResultBytes-consumed||after.branchManifest.some(m=>!before.branchManifest.some(old=>equal(old.genesisAuthorityDigest,m.genesisAuthorityDigest)&&old.limit&&m.limit&&old.limit.refName===m.limit.refName&&equal(old.limit.genesisDigest,m.limit.genesisDigest))))reject("RenewalFork");if(member){const p=member.body!;remainingScope(p.scope!,os,committed);if(old.member){const oldParent=old.member.body!;if(equal(p.subjectPublicKey,oldParent.subjectPublicKey)&&equal(p.logicalJobId,oldParent.logicalJobId)&&equal(p.retryLineageId,oldParent.retryLineageId)&&(!equal(p.cancellationId,oldParent.cancellationId)||(!equal(toBinary(api.SignedImportMemberPermissionV1Schema,member),toBinary(api.SignedImportMemberPermissionV1Schema,old.member))&&equal(p.nonce,oldParent.nonce))))reject("ImportPermission");}}await auth(after.delegatingPublicKey,RENEWAL_DOMAIN,api.ImportJobRenewalV1Schema,r,signed.delegatingSignature);return next;}
export function checkImportSlotReplay(m:api.ImportResultManifestV1,signed:api.SignedDelegatedImportOperationV1):boolean{validateImportManifest(m);const o=signed.body;if(!o)reject("Canonical");if(!equal(m.logicalJobId,o.logicalJobId)||!equal(m.retryLineageId,o.retryLineageId))reject("Scope");const s=m.slots.find(s=>s.refName===o.refName&&s.slotId===o.slotId);if(!s)return false;if(!equal(s.signedOperationDigest,signedOperationDigest(signed))||!equal(s.resultingFrontierDigest,o.resultingFrontierDigest)||s.resultBytes!==o.resultBytes)reject("SlotConflict");return true;}
export function requireHybridPeer(protocol:ProtocolCompatibility|undefined):void{if(!protocol||protocol.protocolVersion!==2||protocol.mandatoryFeatures.length!==1||protocol.mandatoryFeatures[0]!==1)reject("Protocol");}
export async function verifyImportPublication(operation:api.SignedDelegatedImportOperationV1,delegation:VerifiedImportDelegation,manifest:api.ImportResultManifestV1,statement:SignedHostedWitnessStatementV1,set:VerifiedWitnessSet,proof:HostedWitnessHistoryProofV1|undefined,now:bigint){operation=clone(api.SignedDelegatedImportOperationV1Schema,operation);manifest=clone(api.ImportResultManifestV1Schema,manifest);statement=clone(SignedHostedWitnessStatementV1Schema,statement);proof=proof?clone(HostedWitnessHistoryProofV1Schema,proof):undefined;if(statement.body)validateStatementBoundary(statement.body);await verifyDelegatedImportOperation(operation,delegation);if(!checkImportSlotReplay(manifest,operation))reject("Scope");const o=operation.body!,{body:d,digest}=read(delegation),s=statement.body,id=d.identity!;if(!s)reject("Canonical");const payload=create(api.ImportPublicationWitnessV1Schema,{formatVersion:1,signedOperationDigest:signedOperationDigest(operation),delegationDigest:digest,logicalJobId:o.logicalJobId,retryLineageId:o.retryLineageId,physicalOperationId:o.physicalOperationId,refName:o.refName,slotId:o.slotId,hashAlgorithm:o.hashAlgorithm,observedCommitOid:o.observedCommitOid,expectedFrontierDigest:o.expectedFrontierDigest,resultingFrontierDigest:o.resultingFrontierDigest,terminalManifestDigest:manifestDigest(manifest)});if(s.purpose!==3||!equal(s.spoolUuid,id.spoolUuid)||!equal(s.spoolGenesisDigest,id.spoolGenesisDigest)||!equal(s.ownerId,id.ownerId)||!equal(s.ownerStateHash,id.ownerStateHash)||s.ownershipTransferSequence!==id.ownershipTransferSequence||!equal(s.authorityDigest,digest)||!operation.jobSignature||!equal(s.originalSignaturesDigest,hash(operation.jobSignature.signature))||!equal(s.canonicalPayload,canonicalHybridV1(api.ImportPublicationWitnessV1Schema,payload))||s.basis!==1)reject("Scope");interval(d.notBeforeUnixSeconds,d.expiresAtUnixSeconds,s.observedAtUnixMillis/1000n);return resolveWitnessStatement(set,statement,proof,false,now);}

export function checkImportJobFence(logicalJobId:Uint8Array,activeDigest:Uint8Array,expectedEpoch:bigint,active:VerifiedImportDelegation,durableEpoch:bigint):void{const d=read(active);if(!equal(logicalJobId,d.body.logicalJobId))reject("Scope");if(expectedEpoch!==durableEpoch||!equal(activeDigest,d.digest))reject("StaleContext");}

export interface ImportSigner{publicKey:Uint8Array;sign(digest:Uint8Array):Promise<Uint8Array>;}
async function signature(domain:string,schema:Parameters<typeof canonicalHybridV1>[0],body:Parameters<typeof canonicalHybridV1>[1],signer:ImportSigner):Promise<AuthorizationSignature>{const digest=signingDigest(domain,schema,body);const signature=await signer.sign(digest);await verifySignature(signer.publicKey,digest,signature);return {$typeName:"heddle.api.v1alpha2.AuthorizationSignature",signerKeyId:keyId(signer.publicKey),signature};}
export async function signImportMemberPermission(body:api.ImportMemberPermissionV1,signer:ImportSigner){const b=clone(api.ImportMemberPermissionV1Schema,body);return create(api.SignedImportMemberPermissionV1Schema,{body:b,ownerSignature:await signature(PERMISSION_DOMAIN,api.ImportMemberPermissionV1Schema,b,signer)});}
export async function signImportGenesisAuthority(body:api.ImportGenesisAuthorityV1,signer:ImportSigner){const b=clone(api.ImportGenesisAuthorityV1Schema,body);if(!equal(b.creatorPublicKey,signer.publicKey))reject("Signature");return create(api.SignedImportGenesisAuthorityV1Schema,{body:b,creatorSignature:await signature(GENESIS_DOMAIN,api.ImportGenesisAuthorityV1Schema,b,signer)});}
export async function signImportDelegation(body:api.ImportJobDelegationV1,signer:ImportSigner){const b=clone(api.ImportJobDelegationV1Schema,body);if(!equal(b.delegatingPublicKey,signer.publicKey))reject("Signature");return create(api.SignedImportJobDelegationV1Schema,{body:b,delegatingSignature:await signature(DELEGATION_DOMAIN,api.ImportJobDelegationV1Schema,b,signer)});}
export async function signImportRenewal(body:api.ImportJobRenewalV1,signer:ImportSigner){const b=clone(api.ImportJobRenewalV1Schema,body);if(!b.replacement?.body||!equal(b.replacement.body.delegatingPublicKey,signer.publicKey))reject("Signature");return create(api.SignedImportJobRenewalV1Schema,{body:b,delegatingSignature:await signature(RENEWAL_DOMAIN,api.ImportJobRenewalV1Schema,b,signer)});}
export async function signDelegatedImportOperation(body:api.DelegatedImportOperationV1,signer:ImportSigner){const b=clone(api.DelegatedImportOperationV1Schema,body);return create(api.SignedDelegatedImportOperationV1Schema,{body:b,jobSignature:await signature(OPERATION_DOMAIN,api.DelegatedImportOperationV1Schema,b,signer)});}

import { SignedRecordSchema, type SignedRecord, type RecordSignature } from "./common_pb.js";
import { u32, join } from "./_hybrid-codec.js";
import { unarySigningBytes } from "../signing.js";
import { threadGenesisId } from "./thread-genesis.js";

export type ImportPermissionEvidence = {kind:"import";record:api.SignedImportMemberPermissionV1} | {kind:"owner_capability";record:import("./owner_records_pb.js").SignedOwnerCapability} | {kind:"online_role";role:string};
export function selectImportPermission(e:ImportPermissionEvidence):api.SignedImportMemberPermissionV1{if(e.kind!=="import")reject("ImportPermission");return e.record;}
export function requireImportOperationFormat(format:string):void{if(format!==OPERATION_DOMAIN)reject("Protocol");}
export function frontierDigest(f:api.ImportFrontierV1):Uint8Array{if(f.formatVersion!==1)reject("Version");width(f.threadId,32);if(f.operationIds.length>128)reject("Bounds");f.operationIds.forEach((id,i)=>{width(id,32);if(i&&compare(f.operationIds[i-1]!,id)>=0)reject("Canonical");});return signingDigest("heddle-import-frontier-v1",api.ImportFrontierV1Schema,f);}
export function contentDigest(c:api.ImportContentV1):Uint8Array{if(c.formatVersion!==1)reject("Version");if(!c.canonicalCapture.length)reject("Bounds");return signingDigest("heddle-import-content-v1",api.ImportContentV1Schema,c);}
export const signedNativeDigest=(r:SignedRecord)=>signingDigest("heddle-signed-native-record-v1",SignedRecordSchema,r);
export async function verifyNativeRecord(r:SignedRecord,format:string){if(r.format!==format)reject("Version");if(!r.canonicalRecord.length||r.canonicalRecord.length>65536||!r.signatures.length||r.signatures.length>16)reject("Bounds");for(let i=0;i<r.signatures.length;i++){const s=r.signatures[i]!;if(i&&compare(r.signatures[i-1]!.publicKey,s.publicKey)>=0)reject("Canonical");await verifySignature(s.publicKey,join(utf8.encode(format),Uint8Array.of(0),r.canonicalRecord),s.signature);}}
import { decode } from "./_collaboration-msgpack.js";
import { blake3 } from "@noble/hashes/blake3.js";
import type { HostedWitnessBoundaryAcceptanceV1 } from "../common/hosted_witness_pb.js";
export function boundaryOctetsDigest(domain:string,bytes:Uint8Array):Uint8Array{return hash(utf8.encode(domain),sized(bytes));}
function nativeOctetsId(format:string,bytes:Uint8Array):Uint8Array{const n=new Uint8Array(8);new DataView(n.buffer).setBigUint64(0,BigInt(bytes.length),true);return blake3(join(utf8.encode(format),n,Uint8Array.of(0),bytes));}
type NativeSelectors={originals_manifest:unknown;publication_intent:unknown;thread:unknown;subject?:Record<string,unknown>;basis?:{BoundaryAcceptance?:{acceptance:unknown}}};
function nativeSelectors(bytes:Uint8Array):NativeSelectors{try{const value=decode(bytes);if(!value||typeof value!=="object"||Array.isArray(value)||value instanceof Uint8Array)reject("Canonical");return value as unknown as NativeSelectors;}catch{reject("Canonical");}}
function selectorBytes(value:unknown):Uint8Array{if(!Array.isArray(value)||value.length!==32||value.some(b=>!Number.isInteger(b)||b<0||b>255))reject("Canonical");return Uint8Array.from(value);}
export function validateBoundaryBinding(b:HostedWitnessBoundaryAcceptanceV1):void{
  if(b.formatVersion!==1)reject("Version");for(const d of [b.acceptanceId,b.signedAcceptanceDigest,b.originalsManifestDigest,b.publicationIntentDigest])width(d,32);
  if(!b.originalReceiptDigests.length||b.originalReceiptDigests.length>128)reject("Bounds");b.originalReceiptDigests.forEach((d,i)=>{width(d,32);if(i&&compare(b.originalReceiptDigests[i-1]!,d)>=0)reject("Canonical");});
}
export function validateStatementBoundary(s:HostedWitnessStatementV1):void{if(s.basis===1&&!s.boundaryAcceptance)return;if(s.basis===2&&s.boundaryAcceptance&&(s.purpose===1||s.purpose===2)){validateBoundaryBinding(s.boundaryAcceptance);return;}reject("BoundaryAcceptance");}
export async function verifyBoundaryAcceptance(e:api.ImportBoundaryAcceptanceV1):Promise<void>{
  e=clone(api.ImportBoundaryAcceptanceV1Schema,e);const b=e.binding??reject("BoundaryAcceptance"),a=e.signedAcceptance??reject("BoundaryAcceptance");validateBoundaryBinding(b);await verifyNativeRecord(a,"heddle-original-boundary-acceptance-v1");if(a.signatures.length!==1)reject("Signature");
  if(!e.originalsManifest.length||!e.publicationIntent.length||e.originalsManifest.length>MAX_RECORD_BYTES||e.publicationIntent.length>MAX_RECORD_BYTES||!e.originalReceipts.length||e.originalReceipts.length>128)reject("Bounds");
  if(!equal(b.acceptanceId,nativeOctetsId(a.format,a.canonicalRecord))||!equal(b.signedAcceptanceDigest,signedNativeDigest(a))||!equal(b.originalsManifestDigest,boundaryOctetsDigest("heddle-boundary-originals-manifest-v1",e.originalsManifest))||!equal(b.publicationIntentDigest,boundaryOctetsDigest("heddle-boundary-publication-intent-v1",e.publicationIntent)))reject("BoundaryAcceptance");
  const selection=nativeSelectors(a.canonicalRecord);if(!equal(selectorBytes(selection.originals_manifest),nativeOctetsId("heddle-original-publication-manifest-v1",e.originalsManifest))||!equal(selectorBytes(selection.publication_intent),nativeOctetsId("heddle-original-publication-intent-v1",e.publicationIntent)))reject("BoundaryAcceptance");
  if(e.originalReceipts.length!==b.originalReceiptDigests.length)reject("BoundaryAcceptance");
  for(let i=0;i<e.originalReceipts.length;i++){const r=e.originalReceipts[i]!;if(!["heddle-thread-genesis-admission-v2","heddle-thread-authority-admission-v3"].includes(r.format))reject("Version");await verifyNativeRecord(r,r.format);if(r.signatures.length!==1)reject("Signature");const basis=nativeSelectors(r.canonicalRecord).basis;if(!basis?.BoundaryAcceptance||!equal(selectorBytes(basis.BoundaryAcceptance.acceptance),b.acceptanceId)||!equal(signedNativeDigest(r),b.originalReceiptDigests[i]!))reject("BoundaryAcceptance");}
}
export function requireBoundaryOriginal(e:api.ImportBoundaryAcceptanceV1,original:SignedRecord):void{
  const id=nativeOctetsId(original.format,original.canonicalRecord);
  for(const receipt of e.originalReceipts){const r=nativeSelectors(receipt.canonicalRecord),subject=r.subject;let format:string,value:unknown;
    if(!subject&&receipt.format==="heddle-thread-genesis-admission-v2"){format="heddle-thread-genesis-v1";value=r.thread;}
    else{const names:Record<string,string>={Operation:"heddle-thread-operation-v1",OwnershipClaim:"heddle-thread-ownership-claim-v1",OwnershipResolution:"heddle-thread-ownership-resolution-v1"};const key=Object.keys(subject??{})[0];if(!subject||!key||!names[key])reject("BoundaryAcceptance");format=names[key]!;value=subject[key];}
    if(original.format===format&&equal(id,selectorBytes(value)))return;
  }
  reject("BoundaryAcceptance");
}
export async function matchWitnessBoundary(s:HostedWitnessStatementV1,evidence:api.ImportBoundaryAcceptanceV1[]):Promise<void>{validateStatementBoundary(s);for(let i=0;i<evidence.length;i++){const e=evidence[i]!;await verifyBoundaryAcceptance(e);if(i&&compare(evidence[i-1]!.binding!.acceptanceId,e.binding!.acceptanceId)>=0)reject("Canonical");}if(s.boundaryAcceptance&&!evidence.some(e=>equal(canonicalHybridV1(common.HostedWitnessBoundaryAcceptanceV1Schema,e.binding!),canonicalHybridV1(common.HostedWitnessBoundaryAcceptanceV1Schema,s.boundaryAcceptance!))))reject("BoundaryAcceptance");}
import * as common from "../common/hosted_witness_pb.js";
async function dependencies(records:SignedRecord[],evidence:api.ImportBoundaryAcceptanceV1[]=[]){if(records.length>128)reject("Bounds");for(let i=0;i<records.length;i++){const r=records[i]!;if(!["heddle-thread-genesis-v1","heddle-thread-operation-v1","heddle-thread-ownership-claim-v1","heddle-thread-ownership-resolution-v1"].includes(r.format)){if(!["heddle-original-boundary-acceptance-v1","heddle-thread-genesis-admission-v2","heddle-thread-authority-admission-v3"].includes(r.format))reject("Version");if(!evidence.some(e=>[e.signedAcceptance,...e.originalReceipts].some(v=>v&&equal(signedNativeDigest(v),signedNativeDigest(r)))))reject("BoundaryAcceptance");}await verifyNativeRecord(r,r.format);if(i&&compare(signedNativeDigest(records[i-1]!),signedNativeDigest(r))>=0)reject("Canonical");}}
export function originalSignaturesDigest(records:SignedRecord[],extra:RecordSignature[]=[]):Uint8Array{const signatures=[...records.flatMap(r=>r.signatures),...extra];return hash(utf8.encode("heddle-hosted-original-signatures-v1"),u32(signatures.length),...signatures.flatMap(s=>[sized(s.publicKey),sized(s.signature)]));}
export const authorityEnvelopeDigest=(e:Uint8Array)=>hash(utf8.encode("heddle-hosted-authority-envelope-v1"),sized(e));
export type WitnessPayload={kind:"genesis";payload:api.ImportGenesisWitnessV1}|{kind:"authority";payload:api.ImportAuthorityWitnessV1}|{kind:"landing";payload:api.HostedLandingWitnessV1};
/** Supply independently verified native objects/authority and accepted context.
 * Exact matching + original signatures are separate from witness resolution. */
export async function verifyWitnessPayload(s:import("../common/hosted_witness_pb.js").HostedWitnessStatementV1,payload:WitnessPayload):Promise<void>{
  s=clone((await import("../common/hosted_witness_pb.js")).HostedWitnessStatementV1Schema,s);
  let purpose:number,bytes:Uint8Array,authority:Uint8Array,signatures:Uint8Array,publisher=s.publisherKeyId;
  if(payload.kind==="genesis"){const p=clone(api.ImportGenesisWitnessV1Schema,payload.payload);if(p.formatVersion!==1)reject("Version");if(!p.binding?.body||!p.originalGenesis)reject("Canonical");const b=p.binding.body;await matchWitnessBoundary(s,p.boundaryAcceptance?[p.boundaryAcceptance]:[]);if((s.basis===2)!==!!p.boundaryAcceptance)reject("BoundaryAcceptance");if(p.boundaryAcceptance)requireBoundaryOriginal(p.boundaryAcceptance,p.originalGenesis);await verifyNativeRecord(p.originalGenesis,"heddle-thread-genesis-v1");if(!equal(threadGenesisId(p.originalGenesis.canonicalRecord),b.genesisDigest)||!b.identity||!equal(s.spoolUuid,b.identity.spoolUuid)||!equal(s.spoolGenesisDigest,b.identity.spoolGenesisDigest)||!equal(s.ownerId,b.identity.ownerId)||!equal(s.ownerStateHash,b.identity.ownerStateHash)||s.ownershipTransferSequence!==b.identity.ownershipTransferSequence)reject("Scope");const creator=p.originalGenesis.signatures.find(x=>equal(x.publicKey,b.creatorPublicKey));if(!creator)reject("Signature");if(!equal(b.originalCreatorSignature,creator.signature)||!equal(b.creatorAuthorityEnvelopeDigest,hash(p.creatorAuthorityEnvelope)))reject("Scope");await auth(b.creatorPublicKey,GENESIS_DOMAIN,api.ImportGenesisAuthorityV1Schema,b,p.binding.creatorSignature);purpose=1;bytes=canonicalHybridV1(api.ImportGenesisWitnessV1Schema,p);authority=signedGenesisDigest(p.binding);signatures=originalSignaturesDigest([p.originalGenesis]);publisher=keyId(b.creatorPublicKey);}
  else if(payload.kind==="authority"){const p=clone(api.ImportAuthorityWitnessV1Schema,payload.payload);if(p.formatVersion!==1)reject("Version");if(!p.original)reject("Canonical");const format=["","heddle-thread-operation-v1","heddle-thread-ownership-claim-v1","heddle-thread-ownership-resolution-v1"][p.kind];if(!format)reject("Version");await verifyNativeRecord(p.original,format);if((p.kind===2||p.kind===3)&&p.original.signatures.length!==2)reject("Signature");if(!p.original.signatures.some(x=>equal(keyId(x.publicKey),s.publisherKeyId)))reject("Signature");if(!p.authorityEnvelope.length||p.authorityEnvelope.length>MAX_RECORD_BYTES)reject("Bounds");await matchWitnessBoundary(s,p.boundaryAcceptances);if(s.boundaryAcceptance){const e=p.boundaryAcceptances.find(e=>equal(e.binding!.acceptanceId,s.boundaryAcceptance!.acceptanceId))??reject("BoundaryAcceptance");requireBoundaryOriginal(e,p.original);}await dependencies(p.dependencies,p.boundaryAcceptances);purpose=2;bytes=canonicalHybridV1(api.ImportAuthorityWitnessV1Schema,p);authority=authorityEnvelopeDigest(p.authorityEnvelope);signatures=originalSignaturesDigest([p.original,...p.dependencies]);}
  else{const p=clone(api.HostedLandingWitnessV1Schema,payload.payload);if(p.formatVersion!==1)reject("Version");if(!p.execution||!p.sourceOperation||!p.request?.signature)reject("Canonical");const r=p.request;if(r.formatVersion!==1||r.methodPath!=="/heddle.api.v1alpha2.ThreadService/LandThread")reject("Version");await verifyNativeRecord(p.execution,"heddle-thread-operation-v1");await verifyNativeRecord(p.sourceOperation,"heddle-thread-operation-v1");await matchWitnessBoundary(s,[]);await dependencies(p.reviewEvidence);if(r.signingIdentity!==`principal:device-key:${Array.from(r.signature!.publicKey,b=>b.toString(16).padStart(2,"0")).join("")}`)reject("Signature");width(r.nonce,16);if(r.timestampMillis<=0n||!r.requestBody.length||r.requestBody.length>MAX_RECORD_BYTES||!p.authorityEnvelope.length||p.authorityEnvelope.length>MAX_RECORD_BYTES)reject("Bounds");await verifySignature(r.signature!.publicKey,await unarySigningBytes(r.signingIdentity,r.methodPath,r.timestampMillis,r.nonce,r.requestBody),r.signature!.signature);purpose=4;bytes=canonicalHybridV1(api.HostedLandingWitnessV1Schema,p);authority=authorityEnvelopeDigest(p.authorityEnvelope);signatures=originalSignaturesDigest([p.execution,p.sourceOperation,...p.reviewEvidence],[r.signature!]);publisher=keyId(r.signature!.publicKey);}
  if(bytes.length>MAX_RECORD_BYTES)reject("Bounds");if(s.purpose!==purpose||!equal(s.canonicalPayload,bytes)||!equal(s.authorityDigest,authority)||!equal(s.originalSignaturesDigest,signatures)||!equal(s.publisherKeyId,publisher))reject("Scope");
}
export function resolveBundlePermission(bundle:api.ImportPublicProofBundleV1,digest:Uint8Array):api.SignedImportMemberPermissionV1|undefined{width(digest,32);if(!digest.some(Boolean))return;return bundle.memberPermissions.find(p=>equal(signedPermissionDigest(p),digest))??reject("ImportPermission");}
export function resolveBundleManifest(bundle:api.ImportPublicProofBundleV1,digest:Uint8Array):api.ImportResultManifestV1{width(digest,32);return bundle.manifests.find(m=>equal(manifestDigest(m),digest))??reject("StaleManifest");}
export function publicationPayload(operation:api.SignedDelegatedImportOperationV1,m:api.ImportResultManifestV1):api.ImportPublicationWitnessV1{const o=operation.body??reject("Canonical");return create(api.ImportPublicationWitnessV1Schema,{formatVersion:1,signedOperationDigest:signedOperationDigest(operation),delegationDigest:o.delegationDigest,logicalJobId:o.logicalJobId,retryLineageId:o.retryLineageId,physicalOperationId:o.physicalOperationId,refName:o.refName,slotId:o.slotId,hashAlgorithm:o.hashAlgorithm,observedCommitOid:o.observedCommitOid,expectedFrontierDigest:o.expectedFrontierDigest,resultingFrontierDigest:o.resultingFrontierDigest,terminalManifestDigest:manifestDigest(m)});}
export function validatePublicBundle(b:api.ImportPublicProofBundleV1):void { validateBundle(b,true); }
function validateBundleBounds(b:api.ImportPublicProofBundleV1):void {
  if(b.formatVersion!==1)reject("Version");if(toBinary(api.ImportPublicProofBundleV1Schema,b).length>MAX_BUNDLE_BYTES||b.ownerHistories.length>64||b.ownershipTransfers.length>64||b.delegations.length>64||b.renewals.length>63||b.memberPermissions.length>64||b.manifests.length>320||b.operations.length>256||b.genesisAuthorities.length>256||b.originalGeneses.length>256||b.creatorAuthorityEnvelopes.length>256||b.statements.length>1024||b.historyProofs.length>1024||b.policies.length>256||b.genesisWitnesses.length>256||b.authorityWitnesses.length>256||b.landingWitnesses.length>256)reject("Bounds");
}
function validateBundle(b:api.ImportPublicProofBundleV1,requireAdmissions:boolean):void{
  validateBundleBounds(b);
  for(const {body:s} of b.statements){if(!s)reject("Canonical");validateStatementBoundary(s);requirePolicyHistory(b.policies,s.spoolUuid,s.policySequence,s.policyStateHash);}
  for(const list of [b.memberPermissions.map(signedPermissionDigest),b.manifests.map(manifestDigest)])for(let i=1;i<list.length;i++)if(compare(list[i-1]!,list[i]!)>=0)reject("Canonical");
  if(b.memberPermission&&!equal(canonicalHybridV1(api.SignedImportMemberPermissionV1Schema,resolveBundlePermission(b,signedPermissionDigest(b.memberPermission))!),canonicalHybridV1(api.SignedImportMemberPermissionV1Schema,b.memberPermission)))reject("ImportPermission");const terminal=b.terminalManifest??reject("Canonical");resolveBundleManifest(b,manifestDigest(terminal));if(!b.delegations.length||b.renewals.length+1!==b.delegations.length)reject("Canonical");
  b.delegations.forEach((d,i)=>{const body=d.body??reject("Canonical");resolveBundlePermission(b,body.parentPermissionDigest);if(!i){if(body.predecessorDelegationDigest.some(Boolean))reject("RenewalFork");}else{const r=b.renewals[i-1]!.body??reject("Canonical");if(!r.replacement||!equal(signedDelegationDigest(r.replacement),signedDelegationDigest(d))||!equal(r.predecessorDelegationDigest,signedDelegationDigest(b.delegations[i-1]!))||!equal(body.predecessorDelegationDigest,r.predecessorDelegationDigest)||r.expectedAuthorityEpoch!==BigInt(i))reject("RenewalFork");resolveBundleManifest(b,r.committedManifestDigest);}for(const branch of body.branchManifest){const g=b.genesisAuthorities.find(g=>equal(signedGenesisDigest(g),branch.genesisAuthorityDigest))?.body??reject("Scope");resolveBundlePermission(b,g.parentPermissionDigest);if(!b.originalGeneses.some(o=>equal(threadGenesisId(o.canonicalRecord),g.genesisDigest))||!b.creatorAuthorityEnvelopes.some(e=>equal(hash(e),g.creatorAuthorityEnvelopeDigest)))reject("Scope");if(requireAdmissions&&!b.genesisWitnesses.some(p=>p.binding&&equal(signedGenesisDigest(p.binding),branch.genesisAuthorityDigest)&&p.originalGenesis&&equal(threadGenesisId(p.originalGenesis.canonicalRecord),g.genesisDigest)&&b.originalGeneses.some(o=>equal(signedNativeDigest(o),signedNativeDigest(p.originalGenesis!)))&&equal(hash(p.creatorAuthorityEnvelope),g.creatorAuthorityEnvelopeDigest)&&b.statements.some(s=>s.body?.purpose===1&&equal(s.body.canonicalPayload,canonicalHybridV1(api.ImportGenesisWitnessV1Schema,p)))))reject("Scope");}});
  for(const m of b.manifests){validateImportManifest(m);if(!equal(m.logicalJobId,terminal.logicalJobId)||!equal(m.retryLineageId,terminal.retryLineageId))reject("Scope");for(const slot of m.slots){const o=b.operations.find(o=>equal(signedOperationDigest(o),slot.signedOperationDigest))??reject("Scope");if(!checkImportSlotReplay(m,o)||!checkImportSlotReplay(terminal,o))reject("Scope");}}
  for(const o of b.operations){if(!o.body||!b.delegations.some(d=>equal(signedDelegationDigest(d),o.body!.delegationDigest))||!checkImportSlotReplay(terminal,o)||!b.manifests.some(m=>checkImportSlotReplay(m,o)&&b.statements.some(s=>s.body?.purpose===3&&equal(s.body.canonicalPayload,canonicalHybridV1(api.ImportPublicationWitnessV1Schema,publicationPayload(o,m))))))reject("Scope");}
  for(const {body:s} of b.statements){if(!s)reject("Canonical");const payloads=s.purpose===1?b.genesisWitnesses.map(p=>canonicalHybridV1(api.ImportGenesisWitnessV1Schema,p)):s.purpose===2?b.authorityWitnesses.map(p=>canonicalHybridV1(api.ImportAuthorityWitnessV1Schema,p)):s.purpose===4?b.landingWitnesses.map(p=>canonicalHybridV1(api.HostedLandingWitnessV1Schema,p)):s.purpose===3?b.operations.flatMap(o=>b.manifests.map(m=>canonicalHybridV1(api.ImportPublicationWitnessV1Schema,publicationPayload(o,m)))):reject("Version");if(!payloads.some(p=>equal(p,s.canonicalPayload)))reject("Scope");}
}
// Reference completeness; native verification authenticates policy and owner context.
export function requirePolicyHistory(policies:import("./owner_records_pb.js").SignedSpoolPolicyRecord[],spool:Uint8Array,sequence:bigint,stateHash:Uint8Array):void{
  for(let i=0;i<=policies.length;i++){
    width(stateHash,32);if(sequence===0n){if(stateHash.some(Boolean))reject("Scope");return;}
    const matches=policies.filter(p=>p.body&&equal(p.body.spoolUuid,spool)&&p.body.sequence===sequence&&equal(p.body.policyStateHash,stateHash));
    if(!matches.length)reject("Scope");if(matches.length!==1)reject("Canonical");const head=matches[0]!.body!.expectedHead??reject("Canonical");if(head.sequence+1n!==sequence)reject("Scope");sequence=head.sequence;stateHash=head.stateHash;
  }
  reject("Scope");
}
export function validateRenewalPreparation(response:api.PrepareImportJobResponse):void{const s=response.renewalState,p=response.proposal;if(!s?.activePredecessor?.body||!s.committedManifest||!p)reject("Canonical");const old=s.activePredecessor.body,m=s.committedManifest;validateImportManifest(m);if(s.formatVersion!==1||s.authorityEpoch===0n||!equal(s.logicalJobId,old.logicalJobId)||!equal(s.retryLineageId,old.retryLineageId)||!equal(p.logicalJobId,s.logicalJobId)||!equal(p.retryLineageId,s.retryLineageId)||!equal(m.logicalJobId,s.logicalJobId)||!equal(m.retryLineageId,s.retryLineageId)||!equal(p.predecessorDelegationDigest,signedDelegationDigest(s.activePredecessor)))reject("StaleContext");}

/** Caller-generated non-nil UUID, reserved as the first physical operation ID.
 * Host checks occupancy in the reservation/activation transaction. */
export function initialImportOperationId(lineage:Uint8Array,occupied:boolean):string {
  width(lineage,16);if(!lineage.some(Boolean))reject("Canonical");if(occupied)reject("OperationIdReused");
  const h=Array.from(lineage,b=>b.toString(16).padStart(2,"0")).join("");
  return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`;
}
/** Inside the Cancel transaction, after caller-scoped replay lookup. */
export function checkImportCancelRequest(request:api.CancelImportJobRequest,active:api.SignedImportJobDelegationV1,durableEpoch:bigint,cancelled:boolean):void {
  const d=active.body??reject("Canonical"),id=d.identity??reject("Canonical");
  width(request.logicalJobId,16);width(request.cancellationId,32);
  if(!request.clientOperationId||request.destination?.id!==initialImportOperationId(id.spoolUuid,false)||!equal(request.logicalJobId,d.logicalJobId))reject("Scope");
  if(durableEpoch===0n||request.expectedAuthorityEpoch!==durableEpoch)reject("StaleContext");
  if(!equal(request.cancellationId,d.cancellationId))reject("Scope");
  if(cancelled)reject("Revoked");
}
/** Exact replay returns the stored receipt without another epoch increment. */
export function checkImportCancelReplay(request:api.CancelImportJobRequest,stored:api.CancelImportJobRequest):void {
  if(!equal(toBinary(api.CancelImportJobRequestSchema,request),toBinary(api.CancelImportJobRequestSchema,stored)))reject("OperationIdReused");
}
/** Both independent revocation selectors remain effective. */
export function checkImportRevocations(delegation:api.SignedImportJobDelegationV1,member:api.SignedImportMemberPermissionV1|undefined,revoked:readonly Uint8Array[]):void {
  const d=delegation.body??reject("Canonical");width(d.cancellationId,32);
  if(revoked.some(id=>equal(id,d.cancellationId)))reject("Revoked");
  if(member){const p=member.body??reject("ImportPermission");width(p.cancellationId,32);if(revoked.some(id=>equal(id,p.cancellationId)))reject("Revoked");}
}
/** Exact remaining total/slots from an authenticated manifest. Empty means complete. */
export function remainingImportScope(scope:api.ImportPermissionScopeV1,committed:api.ImportResultManifestV1):api.ImportPermissionScopeV1 {
  validateImportScope(scope);validateImportManifest(committed);const remaining=clone(api.ImportPermissionScopeV1Schema,scope);
  for(const slot of committed.slots)if(scope.branches.some(b=>b.refName===slot.refName&&b.slotId===slot.slotId)){remaining.maxResultBytes-=slot.resultBytes;remaining.maxOperations--;}
  if(remaining.maxResultBytes<0n||remaining.maxOperations<0)reject("RenewalFork");
  remaining.branches=remaining.branches.filter(b=>!committed.slots.some(s=>s.refName===b.refName&&s.slotId===b.slotId));return remaining;
}
function remainingScope(scope:api.ImportPermissionScopeV1,old:api.ImportPermissionScopeV1,committed:api.ImportResultManifestV1):void {
  if(!subset(scope,old))reject("RenewalFork");let consumed=0n,removed=0;
  for(const slot of committed.slots){const b=old.branches.find(b=>b.refName===slot.refName&&b.slotId===slot.slotId);if(b){consumed+=slot.resultBytes;removed++;}if(scope.branches.some(b=>b.refName===slot.refName&&b.slotId===slot.slotId))reject("CommittedSlot");}
  if(scope.maxOperations>old.maxOperations-removed||scope.maxResultBytes>old.maxResultBytes-consumed)reject("RenewalFork");
}
// Separate opaque storage: this token cannot enter operation/publication validation.
const predecessors=new WeakMap<object,{previous:VerifiedImportDelegation;stateDigest:Uint8Array}>();
declare const predecessorBrand:unique symbol;
export interface VerifiedImportRenewalPredecessor {readonly [predecessorBrand]:true;}
function validateCasState(state:api.ImportJobCasStateV1):void {
  const p=state.activePredecessor?.body??reject("Canonical"),m=state.committedManifest??reject("Canonical");validateImportManifest(m);
  if(state.formatVersion!==1||state.authorityEpoch===0n||!equal(state.logicalJobId,p.logicalJobId)||!equal(state.retryLineageId,p.retryLineageId)||!equal(m.logicalJobId,state.logicalJobId)||!equal(m.retryLineageId,state.retryLineageId))reject("StaleContext");
}
/** Authenticated Prepare/receiver-owned state and independently verified old
 * owner context. Signature/scope only: no historical admission or current grant. */
export async function verifyImportRenewalPredecessor(state:api.ImportJobCasStateV1,member:api.SignedImportMemberPermissionV1|undefined,e:ImportOwnerExpectation):Promise<VerifiedImportRenewalPredecessor> {
  state=clone(api.ImportJobCasStateV1Schema,state);e=snapshotExpectation(e);member=member?clone(api.SignedImportMemberPermissionV1Schema,member):undefined;
  validateCasState(state);const previous=await verifyDelegationInner(state.activePredecessor!,member,e,false);
  const token=Object.freeze({}) as VerifiedImportRenewalPredecessor;
  predecessors.set(token,{previous,stateDigest:signingDigest("heddle-import-job-cas-state-v1",api.ImportJobCasStateV1Schema,state)});return token;
}
/** Current replacement authority and atomic activation CAS remain mandatory. */
export async function verifyImportRenewalFromState(signed:api.SignedImportJobRenewalV1,previous:VerifiedImportRenewalPredecessor,state:api.ImportJobCasStateV1,member:api.SignedImportMemberPermissionV1|undefined,e:ImportOwnerExpectation):Promise<VerifiedImportDelegation> {
  state=clone(api.ImportJobCasStateV1Schema,state);const old=predecessors.get(previous)??reject("Canonical");validateCasState(state);
  if(!equal(signingDigest("heddle-import-job-cas-state-v1",api.ImportJobCasStateV1Schema,state),old.stateDigest))reject("StaleContext");
  return verifyImportRenewal(signed,old.previous,state.committedManifest!,state.authorityEpoch,member,e);
}

/** Validate discovery metadata only; a well-shaped selector grants no authority. */
export function validateHybridImportJobSelector(selector:HybridImportJobSelector):void {
  width(selector.logicalJobId,16);
  if(!selector.logicalJobId.some(Boolean))reject("Canonical");
}

/** Project the durable HYBRID association into the writer-only read. Missing/unknown
 * subject or selector is unavailable. Shape validation supplies no authorization. */
export function importJobStateRequestFromOperation(operation:OperationRecord):api.GetImportJobStateRequest|undefined {
  const subject=operation.subject?.subject;
  if(subject?.case!=="import"||!subject.value.hybridJob)return undefined;
  const selector=subject.value.hybridJob;
  validateHybridImportJobSelector(selector);
  const request=create(api.GetImportJobStateRequestSchema,{
    destination:operation.ref?.spool?{id:operation.ref.spool.id}:undefined,
    logicalJobId:selector.logicalJobId.slice(),
  });
  validateImportJobStateRequest(request);
  return request;
}

/** Finite writer read. The generated RPC contract supplies authentication and authorization. */
export function validateImportJobStateRequest(request:api.GetImportJobStateRequest):void {
  if(toBinary(api.GetImportJobStateRequestSchema,request).length>4096)reject("Bounds");
  initialImportOperationId(request.logicalJobId,false);
  if(!request.destination||!/^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/.test(request.destination.id)||!request.destination.id.replaceAll("-", "").split("").some(c=>c!=="0"))reject("Scope");
}
function ownerReference(b:api.ImportPublicProofBundleV1,id:api.ImportIdentityV1|undefined):void {
  identity(id);
  if(!b.ownerHistories.some(h=>equal(h.stateHash,id.ownerStateHash)&&h.root?.root&&equal(h.root.root.ownerId,id.ownerId)&&equal(h.root.root.accountUuid,id.ownerAccountUuid)))reject("Root");
}
function retainedProof(state:api.ImportJobCasStateV1,b:api.ImportPublicProofBundleV1):void {
  validateCasState(state);
  if(!state.activePredecessor||!state.committedManifest)reject("Canonical");
  const last=b.delegations.at(-1);
  if(!last||!equal(toBinary(api.SignedImportJobDelegationV1Schema,last),toBinary(api.SignedImportJobDelegationV1Schema,state.activePredecessor))||!b.terminalManifest||!equal(toBinary(api.ImportResultManifestV1Schema,b.terminalManifest),toBinary(api.ImportResultManifestV1Schema,state.committedManifest)))reject("StaleContext");
  validateBundle(b,state.committedManifest.slots.length>0);
  const active=state.activePredecessor.body??reject("Canonical"),id=active.identity??reject("Canonical");
  if(!b.ownerGenesis?.genesis||!equal(b.ownerGenesis.genesis.spoolUuid,id.spoolUuid)||!b.ownerChain||!equal(ownerChainDigest(b.ownerChain),active.ownerChainDigest)||!equal(b.ownerChain.spoolGenesisDigest,id.spoolGenesisDigest))reject("Root");
  for(const {body:d} of b.delegations){if(!d)reject("Canonical");if(!equal(d.logicalJobId,state.logicalJobId)||!equal(d.retryLineageId,state.retryLineageId))reject("Scope");ownerReference(b,d.identity);}
  for(const g of b.genesisAuthorities)ownerReference(b,g.body?.identity);
}
/** Supply the authenticated response, never an incoming state assertion. */
export function validateImportJobStateResponse(request:api.GetImportJobStateRequest,response:api.GetImportJobStateResponse):void {
  validateImportJobStateRequest(request);
  if(toBinary(api.GetImportJobStateResponseSchema,response).length>2*MAX_BUNDLE_BYTES)reject("Bounds");
  const state=response.state??reject("Canonical"),proof=response.retainedProof??reject("Canonical");
  retainedProof(state,proof);
  const id=state.activePredecessor?.body?.identity??reject("Canonical");
  if(!equal(state.logicalJobId,request.logicalJobId)||request.destination?.id!==initialImportOperationId(id.spoolUuid,false))reject("Scope");
  const selector=response.retainedSource??reject("SourceSelection");
  for(const d of proof.delegations)validateRetainedImportSource(selector,d.body?.scope??reject("Canonical"));
}
/** A changed snapshot requires recomputation and another exact Prepare before signing. */
export function validateRenewalPreparationFromRead(request:api.PrepareImportJobRequest,response:api.PrepareImportJobResponse,read:api.GetImportJobStateResponse):void {
  validateImportPreparationResponse(request,response);
  validateImportJobStateResponse(create(api.GetImportJobStateRequestSchema,{destination:request.destination,logicalJobId:request.renewLogicalJobId}),read);
  if(!request.source||!read.retainedSource||!sameSourceSelection(request.source,read.retainedSource))reject("SourceSelection");
  if(!read.state||!response.renewalState||!equal(toBinary(api.ImportJobCasStateV1Schema,read.state),toBinary(api.ImportJobCasStateV1Schema,response.renewalState)))reject("StaleContext");
}
/** Composition/references only. Independently verify owner/policy and witnessed
 * accepted history. The authenticated read supplies exact retained evidence.
 * logicalJobTerminal is independently selected under the host transaction. */
export function validateImportRenewRequest(request:api.RenewImportJobRequest,read:api.GetImportJobStateResponse,logicalJobTerminal:boolean):void {
  if(toBinary(api.RenewImportJobRequestSchema,request).length>2*MAX_BUNDLE_BYTES)reject("Bounds");
  if(typeof logicalJobTerminal!=="boolean")reject("Canonical");
  if(logicalJobTerminal)reject("Transition");
  if(!request.clientOperationId||utf8.encode(request.clientOperationId).length>128)reject("Canonical");
  const r=request.renewal?.body??reject("Canonical"),d=r.replacement?.body??reject("Canonical");
  validateImportJobStateResponse(create(api.GetImportJobStateRequestSchema,{destination:request.destination,logicalJobId:d.logicalJobId}),read);
  const state=read.state!,retained=read.retainedProof!,b=request.proof??reject("Canonical");
  // Validate bounds and retained closure without applying export-only admissions
  // to a zero-publication submission. Every pending field is compared below.
  validateBundleBounds(b);
  if(!equal(r.predecessorDelegationDigest,signedDelegationDigest(state.activePredecessor!))||r.expectedAuthorityEpoch!==state.authorityEpoch)reject("StaleContext");
  if(!equal(r.committedManifestDigest,manifestDigest(state.committedManifest!)))reject("StaleManifest");
  const parent=resolveBundlePermission(b,d.parentPermissionDigest),permissions=[...retained.memberPermissions];
  if(parent&&!permissions.some(p=>equal(toBinary(api.SignedImportMemberPermissionV1Schema,p),toBinary(api.SignedImportMemberPermissionV1Schema,parent))))permissions.push(parent);
  permissions.sort((a,b)=>compare(signedPermissionDigest(a),signedPermissionDigest(b)));
  if(permissions.length!==b.memberPermissions.length||permissions.some((p,i)=>!equal(toBinary(api.SignedImportMemberPermissionV1Schema,p),toBinary(api.SignedImportMemberPermissionV1Schema,b.memberPermissions[i]!))))reject("ImportPermission");
  if(b.memberPermission&&(!parent||!equal(toBinary(api.SignedImportMemberPermissionV1Schema,b.memberPermission),toBinary(api.SignedImportMemberPermissionV1Schema,parent))))reject("ImportPermission");
  const normalized=clone(api.ImportPublicProofBundleV1Schema,b);
  if(!retained.ownerHistories.every(h=>b.ownerHistories.some(v=>equal(toBinary(OwnerHistorySchema,h),toBinary(OwnerHistorySchema,v))))
    ||!retained.ownershipTransfers.every((t,i)=>b.ownershipTransfers[i]&&equal(toBinary(ResourceTransferAuditRecordSchema,t),toBinary(ResourceTransferAuditRecordSchema,b.ownershipTransfers[i]!)))
    ||!retained.policies.every(p=>b.policies.some(v=>equal(toBinary(SignedSpoolPolicyRecordSchema,p),toBinary(SignedSpoolPolicyRecordSchema,v)))))reject("Root");
  ownerReference(b,d.identity);
  if(!b.ownerChain||!d.identity||!equal(ownerChainDigest(b.ownerChain),d.ownerChainDigest)||!equal(b.ownerChain.spoolGenesisDigest,d.identity.spoolGenesisDigest))reject("Root");
  normalized.memberPermissions=retained.memberPermissions;normalized.memberPermission=retained.memberPermission;
  normalized.ownerHistories=retained.ownerHistories;normalized.ownershipTransfers=retained.ownershipTransfers;
  normalized.policies=retained.policies;normalized.ownerChain=retained.ownerChain;
  if(!equal(toBinary(api.ImportPublicProofBundleV1Schema,normalized),toBinary(api.ImportPublicProofBundleV1Schema,retained)))reject("Scope");
  const initial=retained.delegations[0]?.body??reject("Canonical");
  for(const branch of d.branchManifest)if(!initial.branchManifest.some(b=>equal(b.genesisAuthorityDigest,branch.genesisAuthorityDigest)&&b.limit&&branch.limit&&equal(b.limit.genesisDigest,branch.limit.genesisDigest)&&b.limit.refName===branch.limit.refName&&b.limit.slotId===branch.limit.slotId))reject("GenesisBinding");
}
/** Separate independently authenticated historical and current owner contexts.
 * Host transaction gates and accepted evidence verification remain mandatory. */
export async function verifyImportRenewSubmission(request:api.RenewImportJobRequest,read:api.GetImportJobStateResponse,predecessorOwner:ImportOwnerExpectation,currentOwner:ImportOwnerExpectation,logicalJobTerminal:boolean):Promise<VerifiedImportDelegation> {
  request=clone(api.RenewImportJobRequestSchema,request);read=clone(api.GetImportJobStateResponseSchema,read);
  predecessorOwner=snapshotExpectation(predecessorOwner);currentOwner=snapshotExpectation(currentOwner);
  validateImportRenewRequest(request,read,logicalJobTerminal);
  const state=read.state!,active=state.activePredecessor!.body!,r=request.renewal!,d=r.body!.replacement!.body!;
  const old=await verifyImportRenewalPredecessor(state,resolveBundlePermission(read.retainedProof!,active.parentPermissionDigest),predecessorOwner);
  return verifyImportRenewalFromState(r,old,state,resolveBundlePermission(request.proof!,d.parentPermissionDigest),currentOwner);
}
/** Compare exact frozen raw request bytes before replay CAS/expiry checks. */
export function checkImportRenewReplay(requestBytes:Uint8Array,storedBytes:Uint8Array):void {
  if(requestBytes.length>2*MAX_BUNDLE_BYTES)reject("Bounds");
  if(!equal(requestBytes,storedBytes))reject("OperationIdReused");
}

/** Supply the independently verified EFFECTIVE state at the selected time. */
export function effectiveOwnerAuthorityExpiry(deferredHuman:boolean,claimableUntil:bigint):bigint {
  if(deferredHuman&&claimableUntil<=0n)reject("Scope");
  return deferredHuman?claimableUntil:(1n<<63n)-1n;
}
export interface ImportWitnessRootPin {authority:string;rootId:string;publicKey:Uint8Array;epoch:bigint;}
/** Receiver-owned durable data; never restore from the incoming proof. */
export interface ImportWitnessSnapshot {
  root:ImportWitnessRootPin;witnessSet:SignedHostedWitnessSetV1;clockFloorUnixMillis:bigint;
  jobAssociations:{key:Uint8Array;logicalJobId:Uint8Array}[];acceptedHistory:api.ImportPublicProofBundleV1[];
}
export type ImportBundleOwnerExpectation=Omit<ImportOwnerExpectation,"nowUnixSeconds">;
export interface VerifiedImportBundleWitnesses {
  evidence:"recovery"|"witnessed";acceptedHistory:api.ImportJobCasStateV1;
  snapshot:ImportWitnessSnapshot|undefined;snapshotAdvanced:boolean;
  ownerCheckTimesUnixSeconds:(bigint|undefined)[];
}
/** After authenticating the state RPC, supply independently verified historical
 * owner contexts in delegation order, without times. The verifier selects the
 * first authenticated publication (else initial admission) time internally.
 * Unwitnessed certificates are recovery only.
 * The mandatory hook receives undefined for time-free policy closure when there
 * are no statements, and otherwise authenticates each
 * selected policy chain and owner/native context at its verified statement time
 * with heddle's verifySignedPolicyChain (WASM). Commit the snapshot atomically. */
export async function verifyImportBundleWitnesses(
  bundle:api.ImportPublicProofBundleV1,pin:ImportWitnessRootPin,snapshot:ImportWitnessSnapshot|undefined,
  now:bigint,owners:readonly ImportBundleOwnerExpectation[],
  verifyPolicy:(bundle:api.ImportPublicProofBundleV1,statement:HostedWitnessStatementV1|undefined)=>void|Promise<void>,
):Promise<VerifiedImportBundleWitnesses> {
  if(typeof verifyPolicy!=="function")reject("Canonical");
  bundle=clone(api.ImportPublicProofBundleV1Schema,bundle);pin={...pin,publicKey:pin.publicKey.slice()};
  snapshot=snapshot?cloneImportWitnessSnapshot(snapshot):undefined;
  owners=owners.map(o=>{const {nowUnixSeconds:_,...facts}=snapshotExpectation({...o,nowUnixSeconds:0n});return facts;});
  width(pin.publicKey,32);if(pin.epoch<=0n||pin.epoch>0xffffffffffffffffn)reject("StaleContext");
  validateBundleBounds(bundle);const terminal=bundle.terminalManifest??reject("Canonical");
  validateBundle(bundle,terminal.slots.length>0);if(owners.length!==bundle.delegations.length)reject("Root");
  const associations=snapshot?.jobAssociations.map(a=>({key:a.key.slice(),logicalJobId:a.logicalJobId.slice()}))??[];
  for(const owner of owners)for(const a of owner.knownJobAssociations){if(associations.some(old=>equal(old.key,a.key)&&!equal(old.logicalJobId,a.logicalJobId)))reject("KeyRole");if(!associations.some(old=>equal(old.key,a.key)))associations.push({key:a.key.slice(),logicalJobId:a.logicalJobId.slice()});}
  for(const {body:b} of bundle.delegations){if(!b)reject("Canonical");if(associations.some(a=>equal(a.key,b.jobPublicKey)&&!equal(a.logicalJobId,b.logicalJobId)))reject("KeyRole");if(!associations.some(a=>equal(a.key,b.jobPublicKey)))associations.push({key:b.jobPublicKey.slice(),logicalJobId:b.logicalJobId.slice()});}
  const expectation=(root:ImportWitnessRootPin,floor:bigint):WitnessSetExpectation=>({authority:root.authority,rootId:root.rootId,rootPublicKey:root.publicKey,rootEpoch:root.epoch,nowUnixMillis:now,clockFloorUnixMillis:floor,knownJobKeys:associations.map(a=>a.key)});
  let previous:VerifiedWitnessSet|undefined;let replacing=false;
  if(snapshot){if(snapshot.root.authority!==pin.authority)reject("Root");previous=await restoreWitnessHistorySnapshot(snapshot.witnessSet,expectation(snapshot.root,0n));if(snapshot.root.rootId!==pin.rootId||!equal(snapshot.root.publicKey,pin.publicKey)||snapshot.root.epoch!==pin.epoch)replacing=true;}
  const carried=bundle.witnessSet;
  if(!carried&&bundle.statements.length)reject("Canonical");
  const newSet=!!carried&&(!snapshot||replacing||!equal(toBinary(SignedHostedWitnessSetV1Schema,carried),toBinary(SignedHostedWitnessSetV1Schema,snapshot.witnessSet)));
  const set=carried?(replacing?await verifyWitnessSetAfterRootReplacement(carried,expectation(pin,snapshot?.clockFloorUnixMillis??0n),previous!):await verifyWitnessSet(carried,expectation(pin,snapshot?.clockFloorUnixMillis??0n),previous)):undefined;
  const resolved:{context:ResolvedWitnessStatement;proof:HostedWitnessHistoryProofV1|undefined}[]=[];
  for(const signed of bundle.statements){const s=signed.body??reject("Canonical"),entry=(set??reject("Canonical")).body.entries.find(e=>equal(e.executorId,s.executorId))??reject("Root");
    const leaf=leafDigest(s.purpose,canonicalHybridV1(HostedWitnessStatementV1Schema,s),signed.signature);
    const proof=entry.state===2?bundle.historyProofs.find(p=>{if(p.purpose!==s.purpose)return false;try{verifyWitnessInclusion(leaf,p,entry);return true;}catch(e){if(e instanceof HybridContractError)return false;throw e;}}):undefined;
    const context=await resolveWitnessStatement(set??reject("Canonical"),signed,proof,false,now);
    // Give hooks separate copies so an async consumer cannot mutate verification.
    await verifyPolicy(clone(api.ImportPublicProofBundleV1Schema,bundle),clone(HostedWitnessStatementV1Schema,s));resolved.push({context,proof});
  }
  if(!bundle.statements.length)await verifyPolicy(clone(api.ImportPublicProofBundleV1Schema,bundle),undefined);
  const times:({order:bigint;time:bigint}|undefined)[]=bundle.delegations.map(()=>undefined);
  const publications=new Map<SignedHostedWitnessStatementV1,{o:api.SignedDelegatedImportOperationV1;m:api.ImportResultManifestV1;index:number}>();
  for(const signed of bundle.statements){const s=signed.body!;if(s.purpose!==3)continue;
    const pair=bundle.operations.flatMap(o=>bundle.manifests.map(m=>({o,m}))).find(({o,m})=>equal(canonicalHybridV1(api.ImportPublicationWitnessV1Schema,publicationPayload(o,m)),s.canonicalPayload))??reject("Scope");
    const index=bundle.delegations.findIndex(d=>equal(signedDelegationDigest(d),pair.o.body!.delegationDigest));if(index<0)reject("Scope");
    if(!times[index]||s.admissionOrder<times[index]!.order)times[index]={order:s.admissionOrder,time:s.observedAtUnixMillis/1000n};
    publications.set(signed,{...pair,index});
  }
  if(!times[0]){const admissions=bundle.statements.map(s=>s.body!).filter(s=>s.purpose===1).sort((a,b)=>a.observedAtUnixMillis<b.observedAtUnixMillis?-1:a.observedAtUnixMillis>b.observedAtUnixMillis?1:a.admissionOrder<b.admissionOrder?-1:a.admissionOrder>b.admissionOrder?1:0);if(admissions[0])times[0]={order:admissions[0].admissionOrder,time:admissions[0].observedAtUnixMillis/1000n};}
  const verified:VerifiedImportDelegation[]=[];
  for(let i=0;i<bundle.delegations.length;i++){const d=bundle.delegations[i]!,b=d.body??reject("Canonical"),parent=resolveBundlePermission(bundle,b.parentPermissionDigest),owner={...owners[i]!,knownJobAssociations:associations,nowUnixSeconds:times[i]?.time??0n};
    verified.push(i===0?await verifyDelegationInner(d,parent,owner,!!times[i]):await verifyRenewalInner(bundle.renewals[i-1]!,verified[i-1]!,resolveBundleManifest(bundle,bundle.renewals[i-1]!.body!.committedManifestDigest),BigInt(i),parent,owner,!!times[i]));
  }
  const initial=read(verified[0]??reject("Canonical")).body;
  for(const branch of initial.branchManifest){const limit=branch.limit??reject("Canonical"),binding=bundle.genesisAuthorities.find(g=>equal(signedGenesisDigest(g),branch.genesisAuthorityDigest))??reject("Scope"),g=binding.body??reject("Canonical");
    const original=bundle.originalGeneses.find(o=>equal(threadGenesisId(o.canonicalRecord),limit.genesisDigest))??reject("Scope"),envelope=bundle.creatorAuthorityEnvelopes.find(e=>equal(hash(e),g.creatorAuthorityEnvelopeDigest))??reject("Scope");
    await verifyNativeRecord(original,"heddle-thread-genesis-v1");const signature=original.signatures.find(s=>equal(s.publicKey,g.creatorPublicKey))??reject("Scope");await verifyImportGenesisAuthority(binding,verified[0]!,limit.genesisDigest,signature.signature,hash(envelope));
  }
  for(let i=0;i<bundle.statements.length;i++){const signed=bundle.statements[i]!,s=signed.body!,{context,proof}=resolved[i]!;
    if(!verified.some(d=>{const id=read(d).body.identity!;return equal(s.spoolUuid,id.spoolUuid)&&equal(s.spoolGenesisDigest,id.spoolGenesisDigest)&&equal(s.ownerId,id.ownerId)&&equal(s.ownerStateHash,id.ownerStateHash)&&s.ownershipTransferSequence===id.ownershipTransferSequence;}))reject("Scope");
    if(s.purpose===1){await verifyImportDelegation(bundle.delegations[0]!,resolveBundlePermission(bundle,initial.parentPermissionDigest),{...owners[0]!,knownJobAssociations:associations,nowUnixSeconds:s.observedAtUnixMillis/1000n});await verifyWitnessPayload(s,{kind:'genesis',payload:bundle.genesisWitnesses.find(p=>equal(canonicalHybridV1(api.ImportGenesisWitnessV1Schema,p),s.canonicalPayload))??reject("Scope")});}
    else if(s.purpose===2)await verifyWitnessPayload(s,{kind:'authority',payload:bundle.authorityWitnesses.find(p=>equal(canonicalHybridV1(api.ImportAuthorityWitnessV1Schema,p),s.canonicalPayload))??reject("Scope")});
    else if(s.purpose===4)await verifyWitnessPayload(s,{kind:'landing',payload:bundle.landingWitnesses.find(p=>equal(canonicalHybridV1(api.HostedLandingWitnessV1Schema,p),s.canonicalPayload))??reject("Scope")});
    else if(s.purpose===3){const {o,m,index}=publications.get(signed)??reject("Scope"),d=bundle.delegations[index]!;const delegation=await verifyImportDelegation(d,resolveBundlePermission(bundle,d.body!.parentPermissionDigest),{...owners[index]!,knownJobAssociations:associations,nowUnixSeconds:s.observedAtUnixMillis/1000n});await verifyImportPublication(o,delegation,m,signed,set??reject("Canonical"),proof,now);}
    else reject("Version");recheckWitnessContext(context,set??reject("Canonical"),signed,now);
  }
  const progressive=clone(api.ImportResultManifestV1Schema,terminal);progressive.slots=[];let order=0n,observed=0n,activeIndex=0,totalBytes=0n;const consumed=new Map<string,{operations:number;bytes:bigint}>();
  for(const o of bundle.operations){const before=manifestDigest(progressive),digest=signedOperationDigest(o),slot=terminal.slots.find(s=>equal(s.signedOperationDigest,digest))??reject("Scope");progressive.slots.push(slot);progressive.slots.sort((a,b)=>a.refName<b.refName?-1:a.refName>b.refName?1:a.slotId<b.slotId?-1:a.slotId>b.slotId?1:0);const payload=canonicalHybridV1(api.ImportPublicationWitnessV1Schema,publicationPayload(o,progressive)),s=bundle.statements.find(s=>s.body?.purpose===3&&equal(s.body.canonicalPayload,payload))?.body??reject("Transition");if(s.admissionOrder<=order||s.observedAtUnixMillis<observed)reject("Transition");order=s.admissionOrder;observed=s.observedAtUnixMillis;
    const index=verified.findIndex(d=>equal(d.digest,o.body!.delegationDigest));if(index<0)reject("Scope");if(index<activeIndex)reject("Transition");
    totalBytes+=o.body!.resultBytes;const originalScope=initial.scope!;
    if(totalBytes>originalScope.maxResultBytes||progressive.slots.length>originalScope.maxOperations)reject("Scope");
    const delegation=read(verified[index]!),budgets:{digest:Uint8Array;scope:api.ImportPermissionScopeV1}[]=[{digest:delegation.digest,scope:delegation.body.scope!}];
    if(delegation.member)budgets.push({digest:delegation.body.parentPermissionDigest,scope:delegation.member.body!.scope!});
    for(const {digest,scope} of budgets){const key=Array.from(digest).join(",")+":"+Array.from(delegation.body.logicalJobId).join(","),count=consumed.get(key)??{operations:0,bytes:0n};count.operations++;count.bytes+=o.body!.resultBytes;consumed.set(key,count);if(count.operations>scope.maxOperations||count.bytes>scope.maxResultBytes)reject("Scope");}
    while(activeIndex<index){if(!equal(bundle.renewals[activeIndex]!.body!.committedManifestDigest,before))reject("StaleManifest");activeIndex++;}
  }
  if(!equal(toBinary(api.ImportResultManifestV1Schema,progressive),toBinary(api.ImportResultManifestV1Schema,terminal)))reject("Scope");
  const finalDigest=manifestDigest(progressive);for(const r of bundle.renewals.slice(activeIndex))if(!equal(r.body!.committedManifestDigest,finalDigest))reject("StaleManifest");
  const history=snapshot?.acceptedHistory.slice()??[],index=history.findIndex(b=>equal(b.terminalManifest!.logicalJobId,terminal.logicalJobId)&&equal(b.delegations[0]!.body!.identity!.spoolUuid,bundle.delegations[0]!.body!.identity!.spoolUuid));
  if(index>=0){const old=history[index]!;if(!old.delegations.every((d,i)=>bundle.delegations[i]&&equal(toBinary(api.SignedImportJobDelegationV1Schema,d),toBinary(api.SignedImportJobDelegationV1Schema,bundle.delegations[i]!)))||!old.renewals.every((r,i)=>bundle.renewals[i]&&equal(toBinary(api.SignedImportJobRenewalV1Schema,r),toBinary(api.SignedImportJobRenewalV1Schema,bundle.renewals[i]!)))||!old.operations.every((o,i)=>bundle.operations[i]&&equal(toBinary(api.SignedDelegatedImportOperationV1Schema,o),toBinary(api.SignedDelegatedImportOperationV1Schema,bundle.operations[i]!))))reject("HighWater");
    const contains=<T extends import("@bufbuild/protobuf").Message>(schema:import("@bufbuild/protobuf").DescMessage,newValues:T[],oldValues:T[])=>oldValues.every(v=>newValues.some(n=>equal(toBinary(schema,n),toBinary(schema,v))));
    if(Boolean(old.ownerGenesis)!==Boolean(bundle.ownerGenesis)||(old.ownerGenesis&&bundle.ownerGenesis&&!equal(toBinary(SignedSpoolOwnerGenesisSchema,old.ownerGenesis),toBinary(SignedSpoolOwnerGenesisSchema,bundle.ownerGenesis)))
      ||!contains(OwnerHistorySchema,bundle.ownerHistories,old.ownerHistories)
      ||!old.ownershipTransfers.every((v,i)=>bundle.ownershipTransfers[i]&&equal(toBinary(ResourceTransferAuditRecordSchema,v),toBinary(ResourceTransferAuditRecordSchema,bundle.ownershipTransfers[i]!)))
      ||!contains(api.SignedImportMemberPermissionV1Schema,bundle.memberPermissions,old.memberPermissions)
      ||!contains(api.SignedImportGenesisAuthorityV1Schema,bundle.genesisAuthorities,old.genesisAuthorities)
      ||!contains(SignedRecordSchema,bundle.originalGeneses,old.originalGeneses)
      ||!old.creatorAuthorityEnvelopes.every(v=>bundle.creatorAuthorityEnvelopes.some(n=>equal(v,n)))
      ||!contains(api.ImportResultManifestV1Schema,bundle.manifests,old.manifests)
      ||!contains(SignedHostedWitnessStatementV1Schema,bundle.statements,old.statements)
      ||!contains(SignedSpoolPolicyRecordSchema,bundle.policies,old.policies)
      ||!contains(api.ImportGenesisWitnessV1Schema,bundle.genesisWitnesses,old.genesisWitnesses)
      ||!contains(api.ImportAuthorityWitnessV1Schema,bundle.authorityWitnesses,old.authorityWitnesses)
      ||!contains(api.HostedLandingWitnessV1Schema,bundle.landingWitnesses,old.landingWitnesses))reject("HighWater");
    history[index]=bundle;}else history.push(bundle);
  const witnessed=times.every(t=>t!==undefined);
  let persisted=snapshot;
  if(witnessed||newSet){
    const persistedAssociations=snapshot?.jobAssociations.map(a=>({key:a.key.slice(),logicalJobId:a.logicalJobId.slice()}))??[];
    if(witnessed)for(const d of bundle.delegations){const b=d.body!;if(!persistedAssociations.some(a=>equal(a.key,b.jobPublicKey)))persistedAssociations.push({key:b.jobPublicKey.slice(),logicalJobId:b.logicalJobId.slice()});}
    persisted=cloneImportWitnessSnapshot({root:pin,witnessSet:carried??reject("Canonical"),clockFloorUnixMillis:now,jobAssociations:persistedAssociations,acceptedHistory:witnessed?history:snapshot?.acceptedHistory??[]});
  }
  const snapshotAdvanced=!!persisted&&(!snapshot||persisted.clockFloorUnixMillis!==snapshot.clockFloorUnixMillis||persisted.root.rootId!==snapshot.root.rootId||persisted.root.epoch!==snapshot.root.epoch||!equal(persisted.root.publicKey,snapshot.root.publicKey)||!equal(toBinary(SignedHostedWitnessSetV1Schema,persisted.witnessSet),toBinary(SignedHostedWitnessSetV1Schema,snapshot.witnessSet))||persisted.acceptedHistory.length!==snapshot.acceptedHistory.length||persisted.acceptedHistory.some((b,i)=>!snapshot!.acceptedHistory[i]||!equal(toBinary(api.ImportPublicProofBundleV1Schema,b),toBinary(api.ImportPublicProofBundleV1Schema,snapshot!.acceptedHistory[i]!)))||persisted.jobAssociations.length!==snapshot.jobAssociations.length||persisted.jobAssociations.some((a,i)=>!equal(a.key,snapshot!.jobAssociations[i]!.key)||!equal(a.logicalJobId,snapshot!.jobAssociations[i]!.logicalJobId)));
  return {evidence:witnessed?"witnessed":"recovery",snapshotAdvanced,ownerCheckTimesUnixSeconds:times.map(t=>t?.time),acceptedHistory:create(api.ImportJobCasStateV1Schema,{formatVersion:1,logicalJobId:terminal.logicalJobId,retryLineageId:terminal.retryLineageId,activePredecessor:bundle.delegations.at(-1),authorityEpoch:BigInt(bundle.delegations.length),committedManifest:terminal}),snapshot:persisted};
}
function cloneImportWitnessSnapshot(s:ImportWitnessSnapshot):ImportWitnessSnapshot{return {root:{...s.root,publicKey:s.root.publicKey.slice()},witnessSet:clone(SignedHostedWitnessSetV1Schema,s.witnessSet),clockFloorUnixMillis:s.clockFloorUnixMillis,jobAssociations:s.jobAssociations.map(a=>({key:a.key.slice(),logicalJobId:a.logicalJobId.slice()})),acceptedHistory:s.acceptedHistory.map(b=>clone(api.ImportPublicProofBundleV1Schema,b))};}

/** Enforce decoded protobuf sizes; transports also bound the uncompressed payload. */
export function validateImportCommitRequestBounds(request:CommitImportJobRequest):void {
  if(toBinary(CommitImportJobRequestSchema,request).length>MAX_COMMIT_REQUEST_BYTES||toBinary(api.ImportPublicProofBundleV1Schema,request.proof??reject("Canonical")).length>MAX_BUNDLE_BYTES)reject("Bounds");
}
/** Independently authenticated CURRENT host facts, never caller-supplied claims. */
/** Independently retained original authority and actual native admission only. */
export function originalImportRetryUnavailable(original:api.SignedImportJobDelegationV1,admitted:boolean,now:bigint):api.ImportRetryUnavailableReason|undefined {
  const b=original.body??reject("Canonical");if(b.notBeforeUnixSeconds<0n||b.expiresAtUnixSeconds<=b.notBeforeUnixSeconds||now<0n)reject("Semantic");
  return !admitted&&now>=b.expiresAtUnixSeconds?api.ImportRetryUnavailableReason.ORIGINAL_WINDOW_ENDED:undefined;
}
export interface ImportControlCaller {
  authenticatedPop:boolean; destinationWriter:boolean; callerAccount:string;
  connectionOwnerAccount?:string; authorizedSource?:api.ImportSourceSelectionV1;
  exactGrantsCurrent:boolean; selectedCommitsAvailable:boolean;
}
export type ImportControlAction="Cancel"|"Retry"|"Renew";
/** Cancel requires destination control only; Retry/Renew fetch via this exact custody. */
export function checkImportControlCaller(action:ImportControlAction,retained:api.ImportSourceSelectionV1,scope:api.ImportPermissionScopeV1,caller:ImportControlCaller):void {
  if(!caller.authenticatedPop||!caller.destinationWriter||!caller.callerAccount)reject("Scope");
  if(action==="Cancel")return;
  validateRetainedImportSource(retained,scope);
  if(retained.connection&&(caller.connectionOwnerAccount!==caller.callerAccount||!caller.authorizedSource||!sameSourceSelection(caller.authorizedSource,retained)||!caller.exactGrantsCurrent))reject("SourceSelection");
  if(!caller.selectedCommitsAvailable)reject("SourceSelection");
}
/** Current host facts read under the same fence as the writer-only response. */
export interface ImportControlAvailabilityContext {
  read:api.GetImportJobStateResponse;logicalJobTerminal:boolean;
  originalAdmitted:boolean;nowUnixSeconds:bigint;
}
/** Caller-relative advice only. The admission checks remain authoritative. */
export function importJobControlAvailability(context:ImportControlAvailabilityContext,caller:ImportControlCaller):api.ImportJobControlAvailabilityV1 {
  if(!caller.authenticatedPop||!caller.destinationWriter||!caller.callerAccount)reject("Scope");
  const read=context.read,active=read.state?.activePredecessor?.body??reject("Canonical"),scope=active.scope??reject("Canonical"),retained=read.retainedSource??reject("SourceSelection");
  validateRetainedImportSource(retained,scope);
  const original=read.retainedProof?.delegations[0]??reject("Canonical"),windowEnded=originalImportRetryUnavailable(original,context.originalAdmitted,context.nowUnixSeconds)!==undefined,R=api.ImportControlUnavailableReason;
  const sourceReason=retained.connection&&caller.connectionOwnerAccount!==caller.callerAccount?R.NOT_CONNECTION_OWNER:
    retained.connection&&(!caller.authorizedSource||!sameSourceSelection(caller.authorizedSource,retained)||!caller.exactGrantsCurrent)?R.GRANT_MISSING:
    !caller.selectedCommitsAvailable?R.COMMIT_UNAVAILABLE:undefined;
  const shared=context.logicalJobTerminal?R.TERMINAL:windowEnded?R.ORIGINAL_WINDOW_ENDED:sourceReason;
  const retryReason=shared??(read.retryAvailability.case!=="eligibleRetryTarget"?R.NO_RETRY_TARGET:context.nowUnixSeconds>=active.expiresAtUnixSeconds?R.AUTHORITY_EXPIRED:context.nowUnixSeconds<active.notBeforeUnixSeconds?R.AUTHORITY_NOT_YET_VALID:undefined);
  const availability=(reason:api.ImportControlUnavailableReason|undefined)=>create(api.ImportControlAvailabilityV1Schema,{availability:reason===undefined?{case:"available",value:true}:{case:"unavailable",value:reason}});
  return create(api.ImportJobControlAvailabilityV1Schema,{retry:availability(retryReason),renew:availability(shared),cancel:availability(context.logicalJobTerminal?R.TERMINAL:undefined)});
}
/** Validate required current controls; historical frozen carriers use the older validators. */
export function validateImportControlStateResponse(request:api.GetImportJobStateRequest,response:api.GetImportJobStateResponse):void {
  validateImportRetryStateResponse(request,response);
  const controls=response.controlAvailability??reject("Canonical");
  for(const control of [controls.retry,controls.renew,controls.cancel]){
    const a=control?.availability??reject("Canonical");
    if(a.case==="available"&&a.value===true)continue;
    if(a.case==="unavailable"&&a.value>=1&&a.value<=8)continue;
    reject("Canonical");
  }
}

function sameSpool(a:SpoolRef|undefined,b:SpoolRef|undefined):boolean {return !!a&&!!b&&equal(toBinary(SpoolRefSchema,a),toBinary(SpoolRefSchema,b));}
function canonicalOperationId(id:string):void {
  const compact=id.replaceAll("-","");
  if(!/^[0-9a-f]{32}$/.test(compact)||initialImportOperationId(new Uint8Array(compact.match(/../g)!.map(h=>parseInt(h,16))),false)!==id)reject("Canonical");
}
function validateRetryAvailability(response:api.GetImportJobStateResponse,destination:SpoolRef):void {
  const availability=response.retryAvailability;
  if(availability.case==="eligibleRetryTarget"){
    const target=availability.value,op=target.operationRef??reject("Canonical");canonicalOperationId(op.id);
    if(!sameSpool(op.spool,destination))reject("Scope");
    if(!target.operationVersion.length||target.operationVersion.length>256)reject("Bounds");
  }else if(availability.case!=="retryUnavailable"||availability.value<1||availability.value>7)reject("Canonical");
}
/** New writer disclosure validation; historical frozen recovery carriers lack this addition. */
export function validateImportRetryStateResponse(request:api.GetImportJobStateRequest,response:api.GetImportJobStateResponse):void {
  validateImportJobStateResponse(request,response);validateRetryAvailability(response,request.destination??reject("Scope"));
}
/** Receiver-owned facts read under the same job/operation/source admission fence. */
export interface ImportRetryAdmission {
  read:api.GetImportJobStateResponse; original:OperationRecord; retryLineageId:Uint8Array;
  logicalJobTerminal:boolean; nowUnixSeconds:bigint;
}
/** Replay lookup precedes this check; owner/policy/revocation/lease checks remain host gates. */
export function checkImportRetryAdmission(request:RetryImportSourceRequest,context:ImportRetryAdmission,active:VerifiedImportDelegation,caller:ImportControlCaller):void {
  const readRequest=create(api.GetImportJobStateRequestSchema,{destination:request.originalOperation?.spool,logicalJobId:request.logicalJobId});
  validateImportRetryStateResponse(readRequest,context.read);
  if(!request.clientOperationId||utf8.encode(request.clientOperationId).length>128)reject("Canonical");
  if(context.logicalJobTerminal)reject("Revoked");
  const availability=context.read.retryAvailability;
  if(availability.case!=="eligibleRetryTarget")reject("StaleContext");
  const target=availability.value,targetRef=target.operationRef??reject("Canonical"),originalRef=context.original.ref??reject("Scope"),d=read(active);
  const operationRead=importJobStateRequestFromOperation(context.original);
  if(!request.originalOperation||!equal(toBinary(RecordRefSchema,request.originalOperation),toBinary(RecordRefSchema,originalRef))||!sameSpool(originalRef.spool,targetRef.spool)||originalRef.id!==targetRef.id||!equal(context.retryLineageId,d.body.retryLineageId)||!operationRead||!equal(toBinary(api.GetImportJobStateRequestSchema,operationRead),toBinary(api.GetImportJobStateRequestSchema,readRequest)))reject("Scope");
  if(!equal(request.expectedOperationVersion,target.operationVersion)||!equal(context.original.version,target.operationVersion)||context.original.supersededBy||![4,5].includes(context.original.state))reject("StaleContext");
  const state=context.read.state??reject("Canonical");
  if(!equal(signedDelegationDigest(state.activePredecessor??reject("Canonical")),d.digest))reject("StaleContext");
  checkImportJobFence(request.logicalJobId,request.activeDelegationDigest,request.expectedAuthorityEpoch,active,state.authorityEpoch);
  interval(d.body.notBeforeUnixSeconds,d.body.expiresAtUnixSeconds,context.nowUnixSeconds);
  const manifest=state.committedManifest??reject("Canonical"),scope=d.body.scope??reject("Canonical");
  if(!scope.branches.some(b=>!manifest.slots.some(s=>s.refName===b.refName&&s.slotId===b.slotId)))reject("StaleContext");
  checkImportControlCaller("Retry",context.read.retainedSource??reject("SourceSelection"),scope,caller);
}
/** Complete prior attempt set is host-owned; UUID allocation/links/receipt persist together. */
export function validateImportRetryResponse(request:RetryImportSourceRequest,response:MutationResponse,priorAttemptIds:readonly string[]):void {
  const receipt=response.receipt??reject("PendingOperation");
  if(receipt.outcome.case!=="pendingOperation")reject("PendingOperation");
  const operation=receipt.outcome.value,original=request.originalOperation??reject("PendingOperation");
  try{canonicalOperationId(operation.id);}catch{reject("PendingOperation");}
  if(!request.clientOperationId||receipt.clientOperationId!==request.clientOperationId||!sameSpool(operation.spool,original.spool)||operation.id===original.id||operation.id===request.clientOperationId||priorAttemptIds.includes(operation.id))reject("PendingOperation");
}
/** Applied may carry an empty version list; Renew creates no physical attempt. */
export function validateImportRenewResponse(request:api.RenewImportJobRequest,response:MutationResponse):void {
  const receipt=response.receipt??reject("Semantic");
  if(!request.clientOperationId||receipt.clientOperationId!==request.clientOperationId||receipt.outcome.case!=="applied")reject("Semantic");
}
export function checkImportRetryReplay(requestBytes:Uint8Array,storedBytes:Uint8Array):void {checkImportRenewReplay(requestBytes,storedBytes);}
