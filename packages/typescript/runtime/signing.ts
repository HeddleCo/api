const encoder = new TextEncoder();

/** Exact NUL-terminated domain for the dual-role WebAuthn binding challenge. */
export const IDENTITY_BINDING_CHALLENGE_V2_DOMAIN = "heddle-device-binding-v2\0";
/** Exact NUL-terminated domain owned by Weft's strict PoP-delegation verifier. */
export const POP_DELEGATION_V1_DOMAIN = "heddle-pop-delegation-v1\0";
/** Exact NUL-terminated domain for Tier-1 request signatures. */
export const TIER_1_REQUEST_SIGNING_V1_DOMAIN = "heddle-req-sig-v1\0";
/** Exact signed/wire role label for the ephemeral Biscuit authority key. */
export const BISCUIT_AUTHORITY_PUBLIC_KEY_ROLE = "biscuit_authority_public_key\0";
/** Exact signed/wire role label for the non-extractable device proof key. */
export const DEVICE_PROOF_PUBLIC_KEY_ROLE = "device_proof_public_key\0";
/** Signed format discriminator at byte zero of a GrantEnvelope v2 payload. */
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
