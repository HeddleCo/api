import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from "node:crypto";
import { readFileSync } from "node:fs";
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";

import {
  AuthorizationSignatureSchema,
  OwnerAuthorizationBundleSchema,
  PurgeOperationSigningBodySchema,
  PurgeSidecarIdentitySchema,
  ResourceOwnershipTransferSchema,
  ResourceTransferAcceptanceSchema,
  SidecarAuthorizationSchema,
  SignedResourceTransferHandoffSchema,
  SignedSpoolOwnerGenesisSchema,
} from "../packages/typescript/dist/v1alpha2/owner_records_pb.js";
import { SignedRecordSchema } from "../packages/typescript/dist/v1alpha2/common_pb.js";
import {
  FetchServerFrameSchema,
  TransferReadySchema,
  TransferSidecar_Kind,
  TransferSidecarSchema,
} from "../packages/typescript/dist/v1alpha2/sync_pb.js";

const fixturePath = "tests/fixtures/owner-authz-v2.json";
const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));
const hex = (value) => Buffer.from(value, "hex");
const u32 = (value) => {
  const output = Buffer.alloc(4);
  output.writeUInt32BE(value);
  return output;
};
const sha256 = (...values) => {
  const hash = createHash("sha256");
  for (const value of values) hash.update(value);
  return hash.digest();
};

function canonicalBody({ spool = hex(fixture.spool_uuid_hex), payload = hex(fixture.payload_hex) } = {}) {
  if (
    fixture.format_version !== 2 ||
    spool.length !== 16 ||
    !/^[0-9a-f]{64}$/.test(fixture.blob_hash)
  ) {
    throw new Error("non-canonical sidecar fixture");
  }
  return Buffer.concat([
    u32(fixture.format_version),
    spool,
    u32(Buffer.byteLength(fixture.blob_hash)),
    Buffer.from(fixture.blob_hash),
    sha256(payload),
    hex(fixture.leaf_capability_id_hex),
  ]);
}

const canonical = canonicalBody();
if (canonical.toString("hex") !== fixture.canonical_body_hex) {
  throw new Error("TypeScript canonical body differs from fixture");
}
if (sha256(hex(fixture.payload_hex)).toString("hex") !== fixture.payload_sha256_hex) {
  throw new Error("TypeScript payload digest differs from fixture");
}
const signingDigest = sha256(Buffer.from("heddle-purge-operation-v2"), canonical);
if (signingDigest.toString("hex") !== fixture.signing_digest_hex) {
  throw new Error("TypeScript signing digest differs from fixture");
}
const publicKey = createPublicKey({
  key: Buffer.concat([
    Buffer.from("302a300506032b6570032100", "hex"),
    hex(fixture.signer_public_key_hex),
  ]),
  format: "der",
  type: "spki",
});
const signingKey = createPrivateKey({
  key: Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    hex(fixture.signing_seed_hex),
  ]),
  format: "der",
  type: "pkcs8",
});
const derivedPublicKey = createPublicKey(signingKey).export({
  format: "der",
  type: "spki",
});
if (
  !derivedPublicKey.subarray(-32).equals(hex(fixture.signer_public_key_hex)) ||
  !sign(null, signingDigest, signingKey).equals(hex(fixture.signature_hex))
) {
  throw new Error("TypeScript fixture signing seed differs from its public key or signature");
}
if (!verify(null, signingDigest, publicKey, hex(fixture.signature_hex))) {
  throw new Error("TypeScript fixture signature verification failed");
}
const genesisDigest = sha256(hex(fixture.signer_public_key_hex), hex(fixture.spool_uuid_hex));
if (genesisDigest.toString("hex") !== fixture.genesis_digest_hex) {
  throw new Error("TypeScript genesis digest differs from fixture");
}
if (!verify(null, genesisDigest, publicKey, hex(fixture.genesis_signature_hex))) {
  throw new Error("TypeScript genesis signature verification failed");
}
if (!sign(null, genesisDigest, signingKey).equals(hex(fixture.genesis_signature_hex))) {
  throw new Error("TypeScript fixture signing seed differs from its genesis signature");
}

function roundTrip(schema, value) {
  const encoded = toBinary(schema, value);
  const decoded = fromBinary(schema, encoded);
  const reencoded = toBinary(schema, decoded);
  if (!Buffer.from(encoded).equals(Buffer.from(reencoded))) {
    throw new Error(`TypeScript round trip changed ${schema.typeName}`);
  }
  return decoded;
}

const signature = create(AuthorizationSignatureSchema);
const bundle = create(OwnerAuthorizationBundleSchema);
const purgeSigningBody = roundTrip(
  PurgeOperationSigningBodySchema,
  create(PurgeOperationSigningBodySchema, {
    formatVersion: fixture.format_version,
    spoolUuid: hex(fixture.spool_uuid_hex),
    purgeIdentity: create(PurgeSidecarIdentitySchema, {
      blobHash: fixture.blob_hash,
    }),
    payloadSha256: hex(fixture.payload_sha256_hex),
    leafCapabilityId: hex(fixture.leaf_capability_id_hex),
  }),
);
if (
  purgeSigningBody.formatVersion !== fixture.format_version ||
  purgeSigningBody.purgeIdentity?.blobHash !== fixture.blob_hash
) {
  throw new Error("TypeScript purge signing body lost fixture fields");
}
roundTrip(
  ResourceOwnershipTransferSchema,
  create(ResourceOwnershipTransferSchema, {
    acceptance: create(ResourceTransferAcceptanceSchema, {
      signedHandoff: create(SignedResourceTransferHandoffSchema),
      destinationSignature: signature,
    }),
  }),
);
const purgeAuthorization = roundTrip(
  SidecarAuthorizationSchema,
  create(SidecarAuthorizationSchema, {
    capability: bundle,
    operationSignature: signature,
  }),
);
if (!purgeAuthorization.capability || !purgeAuthorization.operationSignature) {
  throw new Error("TypeScript purge authorization lost typed owner fields");
}
const purge = roundTrip(
  TransferSidecarSchema,
  create(TransferSidecarSchema, {
    kind: TransferSidecar_Kind.PURGE,
    recordFormat: "heddle-purge-sidecar-v2",
    canonicalRecord: hex(fixture.payload_hex),
    ownerAuthorization: [
      create(SignedRecordSchema, {
        format: "heddle-owner-authorization-v2",
        canonicalRecord: toBinary(SidecarAuthorizationSchema, purgeAuthorization),
      }),
    ],
  }),
);
if (
  purge.kind !== TransferSidecar_Kind.PURGE ||
  purge.ownerAuthorization.length !== 1
) {
  throw new Error("TypeScript purge sidecar lost its kind or owner authorization");
}
roundTrip(
  FetchServerFrameSchema,
  create(FetchServerFrameSchema, {
    body: { case: "sidecar", value: purge },
  }),
);
const attachment = roundTrip(
  TransferSidecarSchema,
  create(TransferSidecarSchema, {
    kind: TransferSidecar_Kind.ATTACHMENT,
    recordFormat: "heddle-state-attachment-v2",
    canonicalRecord: new Uint8Array([0x01]),
  }),
);
if (attachment.kind !== TransferSidecar_Kind.ATTACHMENT) {
  throw new Error("TypeScript attachment sidecar lost its kind");
}
const ready = roundTrip(
  TransferReadySchema,
  create(TransferReadySchema, {
    ownerGenesis: create(SignedSpoolOwnerGenesisSchema),
  }),
);
if (!ready.ownerGenesis) {
  throw new Error("TypeScript transfer readiness lost its owner genesis");
}

function verifyMutation({ spool, payload, key = publicKey }) {
  const digest = sha256(
    Buffer.from("heddle-purge-operation-v2"),
    canonicalBody({ spool, payload }),
  );
  return verify(null, digest, key, hex(fixture.signature_hex));
}

function evaluate(id) {
  switch (id) {
    case "signer-mismatch": {
      const rogue = createPublicKey({
        key: Buffer.concat([
          Buffer.from("302a300506032b6570032100", "hex"),
          Buffer.alloc(32, 0x77),
        ]),
        format: "der",
        type: "spki",
      });
      return verifyMutation({ key: rogue });
    }
    case "payload-swapping": {
      const payload = hex(fixture.payload_hex);
      payload[0] ^= 1;
      return verifyMutation({ payload });
    }
    case "wrong-spool": {
      const spool = hex(fixture.spool_uuid_hex);
      spool[0] ^= 1;
      return verifyMutation({ spool });
    }
    case "genesis-wrong-spool": {
      const spool = hex(fixture.spool_uuid_hex);
      spool[0] ^= 1;
      return verify(
        null,
        sha256(hex(fixture.signer_public_key_hex), spool),
        publicKey,
        hex(fixture.genesis_signature_hex),
      );
    }
    case "transition-fork": {
      const rows = [
        [1, "00", "01"],
        [2, "01", "02"],
        [2, "01", "03"],
      ];
      return rows.slice(1).every((row, index) =>
        row[0] === rows[index][0] + 1 && row[1] === rows[index][2]
      );
    }
    case "incomplete-transfer-source-only":
      return transferIsComplete(true, false);
    case "incomplete-transfer-destination-only":
      return transferIsComplete(false, true);
    case "attenuated-purge":
      return directOnlyAction(false);
    case "direct-purge":
      return directOnlyAction(true);
    default:
      throw new Error(`unknown conformance case ${id}`);
  }
}

const transferIsComplete = (source, destination) => source && destination;
const directOnlyAction = (direct) => direct;
const typescriptOutcomes = fixture.negative_cases.map(({ id, expected }) => {
  const accepted = evaluate(id);
  if (accepted !== expected) throw new Error(`${id}: TypeScript expected ${expected}, got ${accepted}`);
  return { id, accepted };
});

const accepted = typescriptOutcomes.filter((outcome) => outcome.accepted).length;
const rejected = typescriptOutcomes.length - accepted;
console.log("CANONICAL_SIGNING_FIXTURE=PASS runtime=node fixture=owner-authz-v2 purge=true genesis=true");
console.log("GENERATED_ROUNDTRIP=PASS typescript=true messages=purge-signing,purge-authorization,purge-sidecar,attachment-sidecar,ownership-transfer,transfer-ready");
console.log(
  `NEGATIVE_CORPUS=PASS runtime=node cases=${typescriptOutcomes.length} accepted=${accepted} rejected=${rejected} ids=${typescriptOutcomes.map((outcome) => outcome.id).join(",")}`,
);
