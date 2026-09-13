/** Portable v2 provider consent. Protobuf carries the challenge; these
 * length-delimited bytes are the exact client signature input. */
import { EndpointKind, type EndpointRef } from "./stream_pb.js";
import { blake3 } from "@noble/hashes/blake3.js";
import { create } from "@bufbuild/protobuf";
import { ProviderPlanSchema, ProviderExtentSchema, ProviderReadTicketSchema, type ProviderOffer, type ProviderPlanChallenge, type ProviderPlan, type ProviderPhysicalRange, type ProviderAssemblyRecord } from "./sync_pb.js";
import type { ProviderPlanRegistration } from "./provider_internal_pb.js";

const utf8 = new TextEncoder();
export const PROVIDER_CONSENT_FORMAT = "heddle.provider-consent.v2";

function joined(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
}
function u32(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) throw new Error("Invalid provider length");
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value);
  return out;
}
function i64(value: bigint): Uint8Array {
  if (value <= 0n || value > 0x7fffffffffffffffn) throw new Error("Invalid provider expiry");
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigInt64(0, value);
  return out;
}
function sized(value: Uint8Array): Uint8Array { return joined(u32(value.length), value); }
function u64(value: bigint): Uint8Array {
  if (value < 0n || value > 0xffffffffffffffffn) throw new Error("Invalid provider offset");
  const out = new Uint8Array(8); new DataView(out.buffer).setBigUint64(0, value); return out;
}
function endpointKey(value: EndpointRef | undefined, kind: EndpointKind): Uint8Array {
  if (value?.kind !== kind) throw new Error("Invalid provider endpoint kind");
  return exact32(value.publicKey, "endpoint key");
}
function rangeBytes(range: ProviderPhysicalRange): Uint8Array {
  if (!range.objectEtag || utf8.encode(range.objectEtag).length > 256 || range.length <= 0n || range.offset + range.length > 0xffffffffffffffffn)
    throw new Error("Invalid provider physical range");
  return joined(sized(exact32(range.packId, "pack ID")), sized(utf8.encode(range.objectEtag)), u64(range.offset), u64(range.length));
}
const maxRecords = 4096;
const maxPackBytes = 512n * 1024n * 1024n;
const maxCapabilityBytes = 64 * 1024;
function canonicalUuid(value: string | undefined): boolean { return !!value && value !== '00000000-0000-0000-0000-000000000000' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value); }
export function providerRecordSetCommitment(range: ProviderPhysicalRange, records: ProviderAssemblyRecord[], extentIndex: number): Uint8Array {
  if (records.length > maxRecords) throw new Error("Provider record bound");
  return commitmentForRecords(range, records.filter(record => record.source.case === 'provider' && record.source.value.extentIndex === extentIndex));
}
function commitmentForRecords(range: ProviderPhysicalRange, records: ProviderAssemblyRecord[]): Uint8Array {
  const parts = [utf8.encode("heddle.provider-range.v2\0"), rangeBytes(range)];
  let next = 0n, count = 0;
  for (const record of records) {
    if (record.source.case !== "provider") throw new Error("Invalid provider record source");
    if (record.source.value.sourceOffset !== next || record.encodedLength <= 0n || record.encodedDigest?.algorithm !== "blake3")
      throw new Error("Invalid provider range tiling");
    parts.push(sized(exact32(record.encodedDigest.digest, "encoded digest")), u64(record.encodedLength));
    next += record.encodedLength; count++;
  }
  if (!count || next !== range.length) throw new Error("Invalid provider range coverage");
  parts.push(u32(count)); return blake3(joined(...parts));
}
function groupedCommitments(plan: ProviderPlan): Uint8Array[] {
  if (!plan.extents.length || plan.extents.length > maxRecords || plan.records.length > maxRecords) throw new Error("Provider extent bound");
  const groups: ProviderAssemblyRecord[][] = Array.from({ length: plan.extents.length }, () => []);
  for (const record of plan.records) {
    if (record.source.case === 'provider') {
      const group = groups[record.source.value.extentIndex];
      if (!group) throw new Error('Invalid provider extent index');
      group.push(record);
    }
  }
  return plan.extents.map((extent, index) => {
    if (!extent.range) throw new Error('Missing provider range');
    return commitmentForRecords(extent.range, groups[index]);
  });
}
export function providerExtentSetDigest(plan: ProviderPlan): Uint8Array {
  if (!plan.extents.length || plan.extents.length > maxRecords) throw new Error("Provider extent bound");
  const parts = [utf8.encode("heddle.provider-extent-set.v2\0"), u32(plan.extents.length)];
  const commitments = groupedCommitments(plan);
  let selectedRoot: Uint8Array | undefined;
  plan.extents.forEach((extent, index) => {
    const provider = endpointKey(extent.provider, EndpointKind.PROVIDER);
    const range = extent.range, ticket = extent.ticket;
    if (!range || !ticket) throw new Error("Missing provider range or ticket");
    const commitment = commitments[index];
    if (!equal(range.recordSetCommitment, commitment) || !equal(endpointKey(ticket.provider, EndpointKind.PROVIDER), provider)
      || !equal(ticket.packId, range.packId) || ticket.objectEtag !== range.objectEtag || ticket.offset !== range.offset
      || ticket.length !== range.length || !equal(ticket.recordSetCommitment, commitment)) throw new Error("Provider ticket range mismatch");
    const spool = ticket.spool?.id;
    if (!canonicalUuid(spool) || !ticket.audience || utf8.encode(ticket.audience).length > 256
      || ticket.facet !== 1 || ticket.attenuatedCapability.length > maxCapabilityBytes)
      throw new Error("Invalid provider ticket scope");
    if (selectedRoot && !equal(selectedRoot, ticket.contentRoot)) throw new Error("Provider content root mismatch");
    selectedRoot ??= ticket.contentRoot;
    parts.push(sized(provider), rangeBytes(range), sized(commitment), sized(utf8.encode(spool)), u32(ticket.facet),
      sized(utf8.encode(ticket.audience)), sized(exact32(ticket.contentRoot, "content root")));
  });
  return blake3(joined(...parts));
}
function equal(a: Uint8Array, b: Uint8Array): boolean { return a.length === b.length && a.every((value, i) => value === b[i]); }

export function providerAssemblyDigest(plan: ProviderPlan): Uint8Array {
  if (!plan.records.length || plan.records.length > maxRecords || plan.extents.length > maxRecords
    || plan.outputPackLength > maxPackBytes) throw new Error("Provider assembly bound");
  const challenge = plan.challenge;
  if (!challenge || challenge.nonce.length !== 16 || !equal(providerExtentSetDigest(plan), plan.extentSetDigest)
    || !equal(challenge.extentSetDigest, plan.extentSetDigest)) throw new Error("Invalid provider challenge or extent set");
  const issuer = endpointKey(challenge.issuer, EndpointKind.WEFT);
  const client = endpointKey(challenge.client, EndpointKind.DEVICE);
  const threadSpool = challenge.thread?.spool?.id;
  const threadId = exact32(challenge.thread?.id?.value, "Thread ID");
  const revision = challenge.revision;
  if (!threadSpool || !canonicalUuid(threadSpool) || !revision || revision.spool?.id !== threadSpool || revision.revision.case !== "state")
    throw new Error("Invalid provider source scope");
  const stateId = exact32(revision.revision.value.value, "State ID");
  const header = plan.packHeader;
  if (header.length !== 16 || !equal(header.subarray(0, 4), utf8.encode("LMPK"))
    || new DataView(header.buffer, header.byteOffset).getUint32(4) !== 4
    || new DataView(header.buffer, header.byteOffset).getBigUint64(8) !== BigInt(plan.records.length))
    throw new Error("Invalid LMPK v4 header");
  const expiry = challenge.expiresAt;
  if (!expiry || expiry.seconds <= 0n || expiry.nanos < 0 || expiry.nanos >= 1_000_000_000) throw new Error("Invalid provider expiry");
  const parts = [utf8.encode("heddle.provider-assembly.v2\0"), sized(challenge.nonce), sized(utf8.encode(threadSpool)),
    sized(threadId), sized(stateId), sized(issuer), sized(client), i64(expiry.seconds), u32(expiry.nanos),
    sized(plan.extentSetDigest), sized(header), u64(plan.outputPackLength), u32(plan.extents.length)];
  const commitments = groupedCommitments(plan);
  plan.extents.forEach((extent, index) => {
    const provider = endpointKey(extent.provider, EndpointKind.PROVIDER), range = extent.range, ticket = extent.ticket;
    if (!range || !ticket) throw new Error("Missing provider range or ticket");
    const commitment = commitments[index];
    if (!equal(range.recordSetCommitment, commitment) || !equal(endpointKey(ticket.provider, EndpointKind.PROVIDER), provider)
      || !equal(endpointKey(ticket.client, EndpointKind.DEVICE), client) || !equal(ticket.packId, range.packId)
      || ticket.objectEtag !== range.objectEtag || ticket.offset !== range.offset || ticket.length !== range.length
      || !equal(ticket.recordSetCommitment, commitment) || !equal(ticket.extentSetDigest, plan.extentSetDigest)
      || ticket.spool?.id !== threadSpool || ticket.expiresAt?.seconds !== expiry.seconds || ticket.expiresAt?.nanos !== expiry.nanos)
      throw new Error("Provider ticket binding mismatch");
    parts.push(sized(provider), rangeBytes(range), sized(commitment), sized(utf8.encode(ticket.spool?.id ?? "")), u32(ticket.facet),
      sized(utf8.encode(ticket.audience)), sized(ticket.contentRoot));
  });
  parts.push(u32(plan.records.length));
  let next = 16n;
  let decodedBytes = 0n;
  const objects = new Set<string>();
  for (const record of plan.records) {
    if (record.outputOffset !== next || record.encodedLength <= 0n) throw new Error("Invalid provider output tiling");
    next += record.encodedLength;
    const object = record.object, address = object?.address, digest = record.encodedDigest;
    if (!object || !address || !digest) throw new Error("Missing provider object or digest");
    if (address.algorithm !== 'blake3' || digest.algorithm !== 'blake3'
      || !['blob', 'tree', 'state'].includes(object.kind) || object.facet !== 1 || object.availability !== 4)
      throw new Error('Invalid provider source object descriptor');
    decodedBytes += object.size;
    if (decodedBytes > maxPackBytes || next > maxPackBytes) throw new Error('Provider assembly bound');
    const identity = `${address.algorithm}:${hexBytes(address.digest)}`;
    if (objects.has(identity)) throw new Error("Duplicate provider object");
    objects.add(identity);
    parts.push(sized(utf8.encode(address.algorithm)), sized(exact32(address.digest, "object digest")),
      sized(utf8.encode(object.kind)), u32(object.facet), u64(object.size), sized(utf8.encode(digest.algorithm)),
      sized(exact32(digest.digest, "encoded digest")), u64(record.outputOffset), u64(record.encodedLength));
    if (record.source.case === "provider" && record.source.value.extentIndex < plan.extents.length)
      parts.push(new Uint8Array([1]), u32(record.source.value.extentIndex), u64(record.source.value.sourceOffset));
    else if (record.source.case === "inline") parts.push(new Uint8Array([2]));
    else throw new Error("Invalid provider record source");
  }
  if (next + 32n !== plan.outputPackLength) throw new Error("Invalid provider output length");
  return blake3(joined(...parts));
}
function hexBytes(value: Uint8Array): string { return Array.from(value, byte => byte.toString(16).padStart(2, "0")).join(""); }
export function validateProviderPlan(plan: ProviderPlan): void {
  const digest = providerAssemblyDigest(plan);
  if (!equal(plan.assemblyDigest, digest) || !equal(plan.challenge?.assemblyDigest ?? new Uint8Array(), digest)
    || plan.extents.some(extent => !extent.ticket?.attenuatedCapability.length || !equal(extent.ticket.assemblyDigest, digest)))
    throw new Error("Provider assembly digest disagreement");
}
/** Convert an unsigned candidate to the canonical layout shared with final plans.
 * The synthetic empty capability is private and can never pass final validation. */
export function providerOfferAsPlan(offer: ProviderOffer): ProviderPlan {
  const challenge = offer.challenge;
  if (!challenge?.client || !challenge.expiresAt || !offer.extents.length || offer.extents.length > maxRecords)
    throw new Error("Invalid provider offer challenge or extent bound");
  return create(ProviderPlanSchema, {
    extentSetDigest: offer.extentSetDigest,
    extents: offer.extents.map(extent => {
      const range = extent.range;
      if (!range) throw new Error("Missing provider offer range");
      return create(ProviderExtentSchema, {
        provider: extent.provider,
        range,
        ticket: create(ProviderReadTicketSchema, {
          attenuatedCapability: new Uint8Array(),
          extentSetDigest: offer.extentSetDigest,
          spool: extent.spool,
          facet: extent.facet,
          audience: extent.audience,
          contentRoot: extent.contentRoot,
          packId: range.packId,
          objectEtag: range.objectEtag,
          offset: range.offset,
          length: range.length,
          provider: extent.provider,
          client: challenge.client,
          assemblyDigest: offer.assemblyDigest,
          expiresAt: challenge.expiresAt,
          recordSetCommitment: range.recordSetCommitment,
        }),
      });
    }),
    challenge,
    assemblyDigest: offer.assemblyDigest,
    packHeader: offer.packHeader,
    outputPackLength: offer.outputPackLength,
    records: offer.records,
  });
}
export function validateProviderOffer(offer: ProviderOffer): void {
  const layout = providerOfferAsPlan(offer);
  if (!equal(providerExtentSetDigest(layout), offer.extentSetDigest)
    || !equal(providerAssemblyDigest(layout), offer.assemblyDigest))
    throw new Error("Provider offer digest disagreement");
}
export function validatePlanForOffer(offer: ProviderOffer, plan: ProviderPlan): void {
  validateProviderOffer(offer);
  validateProviderPlan(plan);
  if (!equal(plan.extentSetDigest, offer.extentSetDigest)
    || !equal(plan.assemblyDigest, offer.assemblyDigest)
    || !equal(providerAssemblyDigest(plan), providerAssemblyDigest(providerOfferAsPlan(offer))))
    throw new Error("Issued provider plan differs from offer");
}
/** Structural validation for operator-authenticated, private R2 placement. */
export function validateProviderRegistration(registration: ProviderPlanRegistration): void {
  const plan = registration.plan;
  if (!plan) throw new Error("Missing registered provider plan");
  validateProviderPlan(plan);
  const servingProvider = endpointKey(registration.servingProvider, EndpointKind.PROVIDER);
  const selected = plan.extents.filter(extent => equal(endpointKey(extent.provider, EndpointKind.PROVIDER), servingProvider));
  if (!selected.length || !registration.packs.length || registration.packs.length > selected.length)
    throw new Error("Invalid registered pack count");
  const locations = new Set<string>();
  for (const pack of registration.packs) {
    if (pack.packId.length !== 32 || !pack.objectKey || utf8.encode(pack.objectKey).length > 1024
      || /\p{Cc}/u.test(pack.objectKey)) throw new Error("Invalid registered pack location");
    const key = hexBytes(pack.packId);
    if (locations.has(key)) throw new Error("Duplicate registered pack location");
    locations.add(key);
  }
  const referenced = new Set(selected.map(extent => hexBytes(exact32(extent.range?.packId, "pack ID"))));
  if (referenced.size !== locations.size || [...referenced].some(key => !locations.has(key)))
    throw new Error("Registered pack coverage differs from plan");
}
function exact32(value: Uint8Array | undefined, name: string): Uint8Array {
  if (value?.length !== 32) throw new Error(`Invalid provider ${name}`);
  return value;
}

export function providerConsentSigningBytes(challenge: ProviderPlanChallenge, signingIdentity: string): Uint8Array {
  if (!signingIdentity || utf8.encode(signingIdentity).length > 256 || challenge.nonce.length !== 16)
    throw new Error("Invalid provider identity or nonce");
  const thread = challenge.thread;
  const revision = challenge.revision;
  const spool = thread?.spool?.id;
  if (!thread || !spool || !canonicalUuid(spool) || !revision
    || revision.spool?.id !== spool || revision.revision.case !== "state")
    throw new Error("Invalid provider source scope");
  const threadId = exact32(thread.id?.value, "Thread ID");
  const stateId = exact32(revision.revision.value.value, "State ID");
  const issuer = challenge.issuer;
  const client = challenge.client;
  if (issuer?.kind !== EndpointKind.WEFT || client?.kind !== EndpointKind.DEVICE)
    throw new Error("Invalid provider endpoint kind");
  const issuerKey = exact32(issuer.publicKey, "issuer key");
  const clientKey = exact32(client.publicKey, "client key");
  const expiry = challenge.expiresAt;
  if (!expiry || !Number.isSafeInteger(expiry.nanos) || expiry.nanos < 0 || expiry.nanos >= 1_000_000_000)
    throw new Error("Invalid provider expiry");
  return joined(
    utf8.encode(`${PROVIDER_CONSENT_FORMAT}\0`), u32(1),
    sized(utf8.encode(signingIdentity)), sized(challenge.nonce), sized(utf8.encode(spool)),
    sized(threadId), sized(stateId), sized(issuerKey), sized(clientKey),
    i64(expiry.seconds), u32(expiry.nanos),
    sized(exact32(challenge.extentSetDigest, "extent set digest")),
    sized(exact32(challenge.assemblyDigest, "assembly digest")),
  );
}
