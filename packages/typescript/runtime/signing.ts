const encoder = new TextEncoder();

/** Exact NUL-terminated domain for the dual-role WebAuthn binding challenge. */
export const IDENTITY_BINDING_CHALLENGE_V2_DOMAIN = "heddle-device-binding-v2\0";
/** Exact NUL-terminated domain owned by Weft's strict PoP-delegation verifier. */
export const POP_DELEGATION_V1_DOMAIN = "heddle-pop-delegation-v1\0";
/** Deployed Tier-1 domain; legacy v1 intentionally has no terminal NUL. */
export const TIER_1_REQUEST_SIGNING_V1_DOMAIN = "heddle-req-sig-v1";
/** Exact NUL-terminated domain for server-signed GrantEnvelope v2 payloads. */
export const GRANT_ENVELOPE_V2_DOMAIN = "heddle-grant-envelope-v2\0";
/**
 * Domain for the one-key passkey↔device-key binding challenge (weft#2047).
 * Unlike the `-v2` domains this has NO terminal NUL: the challenge framing
 * inserts an explicit `0x00` separator. Mirrors the Rust
 * `ONE_KEY_DEVICE_BINDING_CHALLENGE_DOMAIN` byte-for-byte.
 */
export const ONE_KEY_DEVICE_BINDING_CHALLENGE_DOMAIN = "heddle-one-key-device-binding-v1";
/**
 * Domain for the recovery new-device-key proof-of-possession (weft#2047 leg 2).
 * Distinct from the rotation/SA-issuance PoP domains to block cross-RPC replay.
 */
export const RECOVERY_NEW_DEVICE_POP_V1_DOMAIN = "heddle-recovery-new-device-pop-v1";
/** Exact signed/wire role label for the ephemeral Biscuit authority key. */
export const BISCUIT_AUTHORITY_PUBLIC_KEY_ROLE = "biscuit_authority_public_key\0";
/** Exact signed/wire role label for the non-extractable device proof key. */
export const DEVICE_PROOF_PUBLIC_KEY_ROLE = "device_proof_public_key\0";
/** Signed format discriminator immediately following the GrantEnvelope domain. */
export const GRANT_ENVELOPE_V2_FORMAT_VERSION = 2;

export const SIGNING_DOMAIN = TIER_1_REQUEST_SIGNING_V1_DOMAIN;
export const DEFAULT_PAGE_SIZE = 50;
export const MAX_PAGE_SIZE = 200;
export function normalizePageSize(requested: number): number {
  return requested <= 0 ? DEFAULT_PAGE_SIZE : Math.min(Math.trunc(requested), MAX_PAGE_SIZE);
}
export const SIGNING_HEADERS = {
  algorithm: "x-heddle-sig-alg",
  signatureBin: "x-heddle-sig-bin",
  timestamp: "x-heddle-sig-ts",
  nonceBin: "x-heddle-sig-nonce-bin",
  identity: "x-heddle-sig-identity",
  required: "x-heddle-sig-required",
  actionUrl: "x-heddle-sig-action-url",
} as const;

/**
 * Return the exact WebAuthn challenge bytes binding both client-minted session
 * roles. Callers base64url-encode the result without padding for
 * `clientDataJSON.challenge`.
 */
export function identityBindingChallengeV2Bytes(
  biscuitAuthorityPublicKey: Uint8Array,
  deviceProofPublicKey: Uint8Array,
): Uint8Array {
  exactEd25519PublicKey("biscuitAuthorityPublicKey", biscuitAuthorityPublicKey);
  exactEd25519PublicKey("deviceProofPublicKey", deviceProofPublicKey);
  return concat([
    encoder.encode(IDENTITY_BINDING_CHALLENGE_V2_DOMAIN),
    encoder.encode(BISCUIT_AUTHORITY_PUBLIC_KEY_ROLE),
    biscuitAuthorityPublicKey,
    encoder.encode(DEVICE_PROOF_PUBLIC_KEY_ROLE),
    deviceProofPublicKey,
  ]);
}

/**
 * Compute the one-key passkey binding challenge string (weft#2047). Returns
 * `base64urlNoPad(SHA256(ONE_KEY_DEVICE_BINDING_CHALLENGE_DOMAIN || 0x00 || deviceProofPublicKey))`,
 * used as the WebAuthn assertion `clientDataJSON.challenge`. Mirrors the Rust
 * `one_key_device_binding_challenge` byte-for-byte.
 */
export async function oneKeyDeviceBindingChallenge(
  deviceProofPublicKey: Uint8Array,
): Promise<string> {
  const input = concat([
    encoder.encode(ONE_KEY_DEVICE_BINDING_CHALLENGE_DOMAIN),
    new Uint8Array([0]),
    deviceProofPublicKey,
  ]);
  return base64urlNoPad(await digest(input));
}

/**
 * Return the 32-byte digest the NEW device key signs to prove possession during
 * recovery completion (weft#2047 leg 2):
 * `SHA256(RECOVERY_NEW_DEVICE_POP_V1_DOMAIN || 0x00 || recoveryAttemptId || 0x00 || newDevicePublicKey)`.
 * Sign these bytes with the new device Ed25519 private key; send the raw
 * 64-byte signature in `SubmitRecoveryProofRequest.newDeviceProofSignature`.
 * Mirrors the Rust `recovery_new_device_pop_digest` byte-for-byte.
 */
export async function recoveryNewDevicePopDigest(
  recoveryAttemptId: string,
  newDevicePublicKey: Uint8Array,
): Promise<Uint8Array> {
  const input = concat([
    encoder.encode(RECOVERY_NEW_DEVICE_POP_V1_DOMAIN),
    new Uint8Array([0]),
    encoder.encode(recoveryAttemptId),
    new Uint8Array([0]),
    newDevicePublicKey,
  ]);
  return digest(input);
}

/** Encode bytes as unpadded base64url (RFC 4648 §5), matching Rust `base64url_nopad`. */
function base64urlNoPad(input: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  let out = "";
  for (let offset = 0; offset < input.length; offset += 3) {
    const b0 = input[offset];
    const b1 = offset + 1 < input.length ? input[offset + 1] : 0;
    const b2 = offset + 2 < input.length ? input[offset + 2] : 0;
    const packed = (b0 << 16) | (b1 << 8) | b2;
    out += alphabet[(packed >> 18) & 0x3f];
    out += alphabet[(packed >> 12) & 0x3f];
    if (offset + 1 < input.length) out += alphabet[(packed >> 6) & 0x3f];
    if (offset + 2 < input.length) out += alphabet[packed & 0x3f];
  }
  return out;
}

export async function unarySigningBytes(
  identity: string,
  route: string,
  timestampMillis: bigint,
  nonce: Uint8Array,
  deterministicRequest: Uint8Array,
): Promise<Uint8Array> {
  return canonical("unary", [
    ["identity", encoder.encode(identity)],
    ["route", encoder.encode(route)],
    ["timestamp_ms", encoder.encode(timestampMillis.toString())],
    ["nonce", encoder.encode(hex(nonce))],
    ["request_sha256", encoder.encode(hex(await digest(deterministicRequest)))],
  ]);
}

async function digest(value: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", value));
}

function canonical(kind: string, fields: Array<readonly [string, Uint8Array]>): Uint8Array {
  const pieces = [`${SIGNING_DOMAIN}\nkind=${kind.length}:${kind}`];
  for (const [name, value] of fields) {
    pieces.push(`\n${name}=${value.length}:`);
    pieces.push(new TextDecoder().decode(value));
  }
  return encoder.encode(pieces.join(""));
}

function hex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function exactEd25519PublicKey(name: string, value: Uint8Array): void {
  if (value.length !== 32) {
    throw new RangeError(`${name} must be exactly 32 bytes, got ${value.length}`);
  }
}

function concat(parts: readonly Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}
