// Internal reference completeness. Durable trust belongs to the receiver.
import { ForeignDependencyOrigin, type ForeignDependencyV1 } from "./import_authority_pb.js";
import type { SignedRecord } from "./common_pb.js";
import { compare, equal, reject, width } from "./_hybrid-codec.js";
import { decode } from "./_collaboration-msgpack.js";
import { signedNativeDigest, verifyNativeRecord } from "./import-authority.js";
import { threadGenesisId } from "./thread-genesis.js";

export function foreignThread(record:SignedRecord):Uint8Array {
  if(record.format==="heddle-thread-genesis-v1")return threadGenesisId(record.canonicalRecord);
  if(!["heddle-thread-operation-v1","heddle-thread-ownership-claim-v1","heddle-thread-ownership-resolution-v1"].includes(record.format))reject("Version");
  let value:unknown;
  try{value=decode(record.canonicalRecord);}catch{reject("Canonical");}
  const thread=(value as {thread?:unknown})?.thread;
  if(!Array.isArray(thread)||thread.length!==32||thread.some(b=>!Number.isInteger(b)||b<0||b>255))reject("Canonical");
  return Uint8Array.from(thread);
}
export class ForeignReferences {
  private readonly used=new Set<number>();
  constructor(private readonly entries:ForeignDependencyV1[],carrier:ForeignDependencyOrigin){
    entries.forEach((entry,i)=>{
      if(entry.formatVersion!==1||![ForeignDependencyOrigin.IMPORT,ForeignDependencyOrigin.NATIVE].includes(entry.origin))reject("Version");
      if(entry.origin===carrier)reject("Scope");
      if(entry.prefixAdmissionOrder===0n)reject("Scope");
      width(entry.threadGenesisDigest,32);width(entry.signedNativeDigest,32);
      if(i&&compare(entries[i-1]!.signedNativeDigest,entry.signedNativeDigest)>=0)reject("Canonical");
    });
  }
  require(record:SignedRecord):void {
    const digest=signedNativeDigest(record),thread=foreignThread(record);
    const index=this.entries.findIndex(e=>equal(e.signedNativeDigest,digest)&&equal(e.threadGenesisDigest,thread));
    if(index<0)reject("Scope");
    this.used.add(index);
  }
  async verify(record:SignedRecord):Promise<void>{
    this.require(record);await verifyNativeRecord(record,record.format);
  }
  finish():void{if(this.used.size!==this.entries.length)reject("Scope");}
}
