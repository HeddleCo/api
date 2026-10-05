import { fromBinary, toBinary, ScalarType, type DescMessage, type Message, type MessageShape } from "@bufbuild/protobuf";
import { sha256 } from "@noble/hashes/sha2.js";

export type RejectReason = "OriginalWindowEnded" | "Version" | "Canonical" | "Bounds" | "Signature" | "Root" | "Semantic" | "HighWater" | "Transition" | "JobAsWitness" | "KeyRole" | "Expired" | "Scope" | "ImportPermission" | "RenewalFork" | "StaleManifest" | "CommittedSlot" | "StaleContext" | "Proof" | "Revoked" | "SlotConflict" | "Protocol" | "BoundaryAcceptance" | "PreparedFields" | "ValidityBounds" | "GenesisBinding" | "PreparationRefused" | "RefDisclosure" | "RefPinning" | "SourceSelection" | "ImportSourceRequiresCommit" | "OperationIdReused" | "PendingOperation";
export class HybridContractError extends Error { constructor(readonly reason: RejectReason, readonly preparationRefusalReason?: number) { super(reason); } }
export function reject(reason: RejectReason): never { throw new HybridContractError(reason); }
export function equal(a: Uint8Array, b: Uint8Array): boolean { return a.length === b.length && a.every((v,i) => v === b[i]); }
export function compare(a: Uint8Array, b: Uint8Array): number { for(let i=0;i<Math.min(a.length,b.length);i++) { if(a[i]!==b[i]) return a[i]!-b[i]!; } return a.length-b.length; }
export const utf8 = new TextEncoder();
export function join(...values: Uint8Array[]): Uint8Array { const out=new Uint8Array(values.reduce((n,v)=>n+v.length,0));let i=0;for(const v of values){out.set(v,i);i+=v.length;}return out; }
export function u32(value: number): Uint8Array { if(!Number.isInteger(value)||value<0||value>0xffffffff) reject("Canonical");const out=new Uint8Array(4);new DataView(out.buffer).setUint32(0,value);return out; }
export function integer(value: bigint, signed=false): Uint8Array { if(typeof value!=="bigint"||value<(signed?-(1n<<63n):0n)||value>=(signed?1n<<63n:1n<<64n)) reject("Canonical");const out=new Uint8Array(8);const v=new DataView(out.buffer);if(signed)v.setBigInt64(0,value);else v.setBigUint64(0,value);return out; }
export function sized(value: Uint8Array): Uint8Array { return join(u32(value.length),value); }
export function width(value: Uint8Array, size: number): void { if(!(value instanceof Uint8Array)||value.length!==size) reject("Canonical"); }
export function hash(...parts: Uint8Array[]): Uint8Array { return sha256(join(...parts)); }
export function keyId(key: Uint8Array): Uint8Array { return hash(utf8.encode("heddle-key-v1"),u32(1),key); }

/** New HYBRID records ONLY. Inherits fixed numbered-field order from the owner
 * contract: counted bytes/UTF-8, BE fixed integers/enums, flattened mandatory
 * nested bodies, u32 count for lists. Protobuf wire bytes are never signed. */
export function canonicalHybridV1<S extends DescMessage>(schema: S, value: MessageShape<S>): Uint8Array {
  const layouts:Record<string,number>={AuthorizationSignature:2,ImportIdentityV1:6,ImportOwnerChainV1:3,ImportBranchLimitV1:9,ImportPermissionScopeV1:8,ImportMemberPermissionV1:12,SignedImportMemberPermissionV1:2,ImportGenesisAuthorityV1:8,SignedImportGenesisAuthorityV1:2,ImportBranchManifestV1:2,ImportJobDelegationV1:17,ImportJobPreparationV1:12,SignedImportJobDelegationV1:2,ImportCommittedSlotV1:5,ImportResultManifestV1:4,ImportJobRenewalV1:5,SignedImportJobRenewalV1:2,DelegatedImportOperationV1:19,SignedDelegatedImportOperationV1:2,ImportPublicationWitnessV1:13,HostedWitnessEntryV1:10,HostedWitnessSetV1:8,HostedWitnessStatementV1:19,HostedWitnessBoundaryAcceptanceV1:6,ImportBoundaryAcceptanceV1:5,RecordSignature:2,SignedRecord:3,ImportFrontierV1:3,ImportContentV1:2,ImportGenesisWitnessV1:5,ImportAuthorityWitnessV1:6,HostedLandingRequestProofV1:7,HostedLandingWitnessV1:6,ImportJobCasStateV1:6,NativeGenesisAuthorityV1:9,SignedNativeGenesisAuthorityV1:2,NativeGenesisWitnessV1:6};
  if(!/^heddle\.api\.(common|v1alpha2)\./.test(schema.typeName)||!layouts[schema.name])reject("Version");
  const parts:Uint8Array[]=[];let size=0;
  function put(bytes:Uint8Array){size+=bytes.length;if(size>1048576)reject("Bounds");parts.push(bytes);}
  function scalar(type: ScalarType, value: unknown) {
    switch(type){
      case ScalarType.BYTES: {const bytes=value as Uint8Array;put(u32(bytes.length));put(bytes);break;}
      case ScalarType.STRING: {const str=value as string;const bytes=utf8.encode(str);if(new TextDecoder("utf-8",{fatal:true}).decode(bytes)!==str)reject("Canonical");put(u32(bytes.length));put(bytes);break;}
      case ScalarType.UINT32: put(u32(value as number));break;
      case ScalarType.UINT64: put(integer(value as bigint));break;
      case ScalarType.INT64: put(integer(value as bigint,true));break;
      default: reject("Version");
    }
  }
  function message(schema:DescMessage,value:Message){
    if(!value)reject("Canonical");
    if(schema.fields.length!==layouts[schema.name]||schema.fields.some((f,i)=>f.number!==(schema.name==="ImportBranchLimitV1"&&i===8?10:i+1)))reject("Version");
    if(Object.keys(value).some(k=>k!=="$typeName"&&!schema.fields.some(f=>f.localName===k)))reject("Canonical");
    for(const f of [...schema.fields].sort((a,b)=>a.number-b.number)){
      const v=Reflect.get(value,f.localName);
      if(f.oneof)reject("Version");
      switch(f.fieldKind){
        case "scalar":scalar(f.scalar,v);break;
        case "enum":put(u32(v));break;
        case "message":if(f.localName==="boundaryAcceptance"){put(u32(v?1:0));if(v)message(f.message,v);}else message(f.message,v);break;
        case "list":if(v.length>4096||(f.listKind==="enum"&&v.length>4))reject("Bounds");put(u32(v.length));for(const item of v){if(f.listKind==="message")message(f.message,item);else if(f.listKind==="enum")put(u32(item));else scalar(f.scalar,item);}break;
        default:reject("Version");
      }
    }
  }
  message(schema,value);return join(...parts);
}
export function signingDigest<S extends DescMessage>(domain:string,schema:S,value:MessageShape<S>):Uint8Array { return hash(utf8.encode(domain),canonicalHybridV1(schema,value)); }
export function strictDecode<S extends DescMessage>(schema:S,bytes:Uint8Array,max=1048576):MessageShape<S>{if(!bytes.length||bytes.length>max)reject("Bounds");let value:MessageShape<S>;try{value=fromBinary(schema,bytes,{readUnknownFields:false});}catch{reject("Canonical");}if(!equal(toBinary(schema,value!),bytes))reject("Canonical");return value!;}
export async function verifySignature(publicKey:Uint8Array,input:Uint8Array,signature:Uint8Array):Promise<void>{width(publicKey,32);width(signature,64);try{const key=await crypto.subtle.importKey("raw",publicKey as BufferSource,"Ed25519",false,["verify"]);if(!await crypto.subtle.verify("Ed25519",key,signature as BufferSource,input as BufferSource))reject("Signature");}catch(error){if(error instanceof HybridContractError)throw error;reject("Signature");}}
export function canonicalHttps(value:string,origin=false):void{if(value.length>2048)reject("Bounds");const match=/^https:\/\/([a-z0-9.-]+)(?:\/(.*))?$/.exec(value);if(!match)reject("Canonical");const host=match[1]!,path=match[2];if(host.length>253||host.split(".").some(p=>!p||p.length>63||p.startsWith("-")||p.endsWith("-"))||(origin&&path!==undefined)||(!origin&&!path)||(path!==undefined&&path.split("/").some(p=>!p||p==="."||p===".."||!/^[A-Za-z0-9._~-]+$/.test(p))))reject("Canonical");}
