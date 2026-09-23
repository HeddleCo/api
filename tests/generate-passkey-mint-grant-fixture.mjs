import { create, clone, toBinary } from '@bufbuild/protobuf';
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import {
  AuthorizationKeyAlgorithm,
  AuthorizationVerificationKeySchema,
  MintRootAttachmentSchema,
  PasskeyAuthoritySchema,
  PasskeyMintDelegationSchema,
  PasskeyMintGrantSchema,
  SignedMintRootAttachmentSchema,
  SignedPasskeyAuthoritySchema,
} from '../packages/typescript/dist/v1alpha2/owner_records_pb.js';
import {
  PASSKEY_MINT_GRANT_DOMAIN,
  canonicalPasskeyAuthority,
  canonicalPasskeyMintGrant,
  mintRootAttachmentSigningDigest,
  passkeyAuthoritySigningDigest,
  passkeyMintGrantSigningDigest,
} from '../packages/typescript/dist/v1alpha2/owner-certificates.js';

const hex = value => Buffer.from(value).toString('hex');
const bytes = (value, encoding = 'hex') => new Uint8Array(Buffer.from(value, encoding));
const privateKey = seed => createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, seed)]),
  format: 'der', type: 'pkcs8',
});
const publicKey = seed => new Uint8Array(createPublicKey(privateKey(seed)).export({ format: 'der', type: 'spki' }).subarray(-32));
const key = seed => create(AuthorizationVerificationKeySchema, {
  algorithm: AuthorizationKeyAlgorithm.ED25519,
  publicKey: publicKey(seed),
});
const keyId = value => new Uint8Array(createHash('sha256')
  .update('heddle-key-v1').update(Buffer.from([0, 0, 0, value.algorithm])).update(value.publicKey).digest());
const base64url = value => Buffer.from(value).toString('base64url');
const owner = key(81);
const mint = key(83);

const authority = create(PasskeyAuthoritySchema, {
  formatVersion: 1,
  accountUuid: new Uint8Array(16).fill(0x11),
  ownerStateHash: bytes('38ced642f2d5d7e3ecae2609f735cb7b7c04193476530ef85813ae7e0ba3bf88'),
  ownerSequence: 0n,
  ownerKey: owner,
  credentialId: new Uint8Array(32).fill(0x06),
  coseAlgorithm: -8,
  publicKeySpki: new Uint8Array(createPublicKey(privateKey(82)).export({ format: 'der', type: 'spki' })),
  relyingPartyId: 'heddle.test',
  allowedOrigins: ['https://app.heddle.test'],
  maxSessionTtlSeconds: 43200,
  nonce: new Uint8Array(32).fill(0x07),
});
const signedAuthority = create(SignedPasskeyAuthoritySchema, {
  authority,
  ownerSignature: {
    signerKeyId: keyId(owner),
    signature: new Uint8Array(sign(null, passkeyAuthoritySigningDigest(authority), privateKey(81))),
  },
});
const grant = create(PasskeyMintGrantSchema, {
  formatVersion: 1,
  mintRootKey: mint,
  notBeforeUnixSeconds: 1_000_000n,
  expiresAtUnixSeconds: 1_003_600n,
  nonce: new Uint8Array(32).fill(0x09),
  relyingPartyId: 'heddle.test',
});

function assertion(statement, rp = statement.relyingPartyId, challenge = passkeyMintGrantSigningDigest(statement)) {
  const clientDataJson = new TextEncoder().encode(JSON.stringify({
    type: 'webauthn.get',
    challenge: base64url(challenge),
    origin: 'https://app.heddle.test',
    crossOrigin: false,
  }));
  const authenticatorData = new Uint8Array(37);
  authenticatorData.set(createHash('sha256').update(rp).digest(), 0);
  authenticatorData[32] = 0x05;
  const signed = Buffer.concat([
    authenticatorData,
    createHash('sha256').update(clientDataJson).digest(),
  ]);
  return create(PasskeyMintDelegationSchema, {
    authority: signedAuthority,
    clientDataJson,
    authenticatorData,
    signature: new Uint8Array(sign(null, signed, privateKey(82))),
  });
}

const attachment = create(SignedMintRootAttachmentSchema, {
  grant,
  passkeyDelegation: assertion(grant),
});
const encoded = value => hex(toBinary(SignedMintRootAttachmentSchema, value));
const altered = (id, field, mutate) => {
  const value = clone(SignedMintRootAttachmentSchema, attachment);
  mutate(value.grant);
  return { id, kind: 'tampered_grant', field, attachment_proto_hex: encoded(value) };
};

const wrongRpGrant = clone(PasskeyMintGrantSchema, grant);
wrongRpGrant.relyingPartyId = 'other.test';
const wrongRp = create(SignedMintRootAttachmentSchema, {
  grant: wrongRpGrant,
  passkeyDelegation: assertion(wrongRpGrant),
});

const legacyAttachment = create(MintRootAttachmentSchema, {
  formatVersion: 1,
  accountUuid: authority.accountUuid,
  ownerStateHash: authority.ownerStateHash,
  ownerSequence: authority.ownerSequence,
  ownerKey: owner,
  mintRootKey: mint,
  notBeforeUnixSeconds: grant.notBeforeUnixSeconds,
  expiresAtUnixSeconds: grant.expiresAtUnixSeconds,
  nonce: grant.nonce,
});
const legacyDigest = mintRootAttachmentSigningDigest(legacyAttachment);
const confused = create(SignedMintRootAttachmentSchema, {
  grant,
  passkeyDelegation: assertion(grant, grant.relyingPartyId, legacyDigest),
});

const fixture = {
  fixture_version: 1,
  canonical_encoding: {
    domain: PASSKEY_MINT_GRANT_DOMAIN,
    field_order: [
      'format_version:u32be',
      'mint_root_key.algorithm:u32be',
      'mint_root_key.public_key:u32be-length+bytes',
      'not_before_unix_seconds:i64be',
      'expires_at_unix_seconds:i64be',
      'nonce:u32be-length+bytes',
      'relying_party_id:u32be-length+utf8',
    ],
    digest: 'sha256(domain || canonical_grant)',
  },
  positive: {
    grant: {
      format_version: grant.formatVersion,
      mint_root_public_key_hex: hex(grant.mintRootKey.publicKey),
      not_before_unix_seconds: Number(grant.notBeforeUnixSeconds),
      expires_at_unix_seconds: Number(grant.expiresAtUnixSeconds),
      nonce_hex: hex(grant.nonce),
      relying_party_id: grant.relyingPartyId,
    },
    canonical_hex: hex(canonicalPasskeyMintGrant(grant)),
    signing_digest_hex: hex(passkeyMintGrantSigningDigest(grant)),
    attachment_proto_hex: encoded(attachment),
    now_unix_seconds: 1_000_001,
    expected_owner: {
      account_uuid_hex: hex(authority.accountUuid),
      owner_state_hash_hex: hex(authority.ownerStateHash),
      owner_sequence: Number(authority.ownerSequence),
      owner_public_key_hex: hex(owner.publicKey),
    },
  },
  negative_cases: [
    altered('tampered-format-version', 'format_version', value => { value.formatVersion = 2; }),
    altered('tampered-mint-root-key', 'mint_root_key', value => { value.mintRootKey.publicKey[0] ^= 1; }),
    altered('tampered-not-before', 'not_before_unix_seconds', value => { value.notBeforeUnixSeconds += 1n; }),
    altered('tampered-expires-at', 'expires_at_unix_seconds', value => { value.expiresAtUnixSeconds += 1n; }),
    altered('tampered-nonce', 'nonce', value => { value.nonce[0] ^= 1; }),
    altered('tampered-relying-party-id', 'relying_party_id', value => { value.relyingPartyId = 'heddle.example'; }),
    {
      id: 'wrong-relying-party-id',
      kind: 'authority_mismatch',
      attachment_proto_hex: encoded(wrongRp),
      now_unix_seconds: 1_000_001,
    },
    {
      id: 'expired',
      kind: 'time_window',
      source: 'positive',
      now_unix_seconds: 1_003_600,
    },
    {
      id: 'not-yet-valid',
      kind: 'time_window',
      source: 'positive',
      now_unix_seconds: 999_999,
    },
    {
      id: 'v1-attachment-domain-confusion',
      kind: 'domain_confusion',
      attachment_proto_hex: encoded(confused),
      presented_challenge_hex: hex(legacyDigest),
      expected_grant_digest_hex: hex(passkeyMintGrantSigningDigest(grant)),
      now_unix_seconds: 1_000_001,
    },
  ],
};

console.log(JSON.stringify(fixture, null, 2));
