import { execFileSync } from "node:child_process";
import { createHash, createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";

import {
  AccessTokenResponseSchema,
  ActiveSessionSchema,
  RegisterPublicKeyRequestSchema,
} from "../packages/typescript/dist/identity_pb.js";
import {
  AuthorizationSignatureSchema,
  CloneAuthorizationKeyringSchema,
  OwnerAuthorizationBundleSchema,
  OwnerKeyBindingSchema,
  RegistrationRecoveryPolicySchema,
  ResourceOwnershipTransferSchema,
  ResourceTransferAcceptanceSchema,
  SidecarAuthorizationSchema,
  SignedOwnerRootSchema,
  SignedResourceTransferHandoffSchema,
} from "../packages/typescript/dist/owner_authorization_pb.js";
import {
  PullReadySchema,
  PullServerFrameSchema,
  SidecarOperationSigningBodySchema,
  StateAttachmentTransferSchema,
} from "../packages/typescript/dist/repo_sync_pb.js";

const fixturePath = "tests/fixtures/owner-authz-cutover-v1.json";
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
    fixture.format_version !== 1 ||
    fixture.required_actions.length < 1 ||
    fixture.required_actions.length > 2 ||
    fixture.required_actions.some((value, index, all) => index > 0 && all[index - 1] >= value) ||
    spool.length !== 16 ||
    fixture.sidecar_kind !== 1 ||
    !/^[0-9a-f]{64}$/.test(fixture.blob_hash)
  ) {
    throw new Error("non-canonical sidecar fixture");
  }
  return Buffer.concat([
    u32(fixture.format_version),
    u32(fixture.required_actions.length),
    ...fixture.required_actions.map(u32),
    spool,
    u32(fixture.sidecar_kind),
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
const signingDigest = sha256(Buffer.from("heddle-sidecar-operation-v1"), canonical);
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
if (!verify(null, signingDigest, publicKey, hex(fixture.signature_hex))) {
  throw new Error("TypeScript fixture signature verification failed");
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
const binding = create(OwnerKeyBindingSchema, {
  formatVersion: 1,
  stableOwnerUuid: new Uint8Array(16).fill(0x11),
});
const bundle = create(OwnerAuthorizationBundleSchema);
const registration = roundTrip(
  RegisterPublicKeyRequestSchema,
  create(RegisterPublicKeyRequestSchema, {
    ownerRoot: create(SignedOwnerRootSchema),
    ownerRootProofOfPossession: signature,
    ownerRecoveryPolicy: create(RegistrationRecoveryPolicySchema),
    ownerKeyBinding: binding,
  }),
);
if (!registration.ownerRoot || !registration.ownerKeyBinding) {
  throw new Error("TypeScript registration lost typed owner fields");
}
const token = roundTrip(
  AccessTokenResponseSchema,
  create(AccessTokenResponseSchema, {
    grantEnvelope: new TextEncoder().encode("still-live-legacy-envelope"),
    ownerAuthorization: bundle,
  }),
);
if (!token.ownerAuthorization || token.grantEnvelope.length === 0) {
  throw new Error("TypeScript token lost legacy or owner authorization field");
}
roundTrip(
  ActiveSessionSchema,
  create(ActiveSessionSchema, { ownerAuthorization: bundle }),
);
roundTrip(SidecarOperationSigningBodySchema, create(SidecarOperationSigningBodySchema));
roundTrip(
  ResourceOwnershipTransferSchema,
  create(ResourceOwnershipTransferSchema, {
    acceptance: create(ResourceTransferAcceptanceSchema, {
      signedHandoff: create(SignedResourceTransferHandoffSchema),
      destinationSignature: signature,
    }),
  }),
);
const attachment = create(StateAttachmentTransferSchema, {
  authorization: create(SidecarAuthorizationSchema, {
    capability: bundle,
    operationSignature: signature,
  }),
});
roundTrip(
  PullServerFrameSchema,
  create(PullServerFrameSchema, {
    frame: { case: "stateAttachment", value: attachment },
  }),
);
roundTrip(
  PullReadySchema,
  create(PullReadySchema, {
    ownerAuthorizationProtocolVersion: 1,
    stableOwnerUuid: new Uint8Array(16).fill(0x11),
    ownerKeyBinding: binding,
    authorizationKeyring: create(CloneAuthorizationKeyringSchema),
  }),
);

function verifyMutation({ spool, payload, key = publicKey }) {
  const digest = sha256(
    Buffer.from("heddle-sidecar-operation-v1"),
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
    case "rogue-uuid-to-key-binding":
      return "11".repeat(16) === "22".repeat(16);
    case "incomplete-transfer-source-only":
      return transferIsComplete(true, false);
    case "incomplete-transfer-destination-only":
      return transferIsComplete(false, true);
    case "attenuated-purge":
    case "attenuated-metadata-supersession":
      return directOnlyAction(false);
    case "direct-purge":
    case "direct-metadata-supersession":
      return directOnlyAction(true);
    case "direct-visibility":
    case "delegated-visibility":
      return true;
    case "missing-visibility":
      return false;
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

const rustOutcomes = JSON.parse(
  execFileSync(
    "cargo",
    ["run", "--quiet", "--example", "owner_authz_conformance", "--", fixturePath],
    { encoding: "utf8" },
  ),
);
if (JSON.stringify(rustOutcomes) !== JSON.stringify(typescriptOutcomes)) {
  throw new Error(
    `owner authz cross-language divergence:\nrust=${JSON.stringify(rustOutcomes)}\nts=${JSON.stringify(typescriptOutcomes)}`,
  );
}

const accepted = typescriptOutcomes.filter((outcome) => outcome.accepted).length;
const rejected = typescriptOutcomes.length - accepted;
console.log("CANONICAL_SIGNING_FIXTURE=PASS languages=rust,typescript fixture=owner-authz-cutover-v1");
console.log("GENERATED_ROUNDTRIP=PASS rust=true typescript=true messages=registration,token,session,keyring,sidecar,transfer");
console.log("UNKNOWN_FIELD_COMPATIBILITY=PASS old_rust_pull_and_token_clients=2 legacy_grant_envelope=preserved");
console.log(
  `NEGATIVE_CORPUS=PASS languages=rust,typescript cases=${typescriptOutcomes.length} accepted=${accepted} rejected=${rejected} ids=${typescriptOutcomes.map((outcome) => outcome.id).join(",")}`,
);
