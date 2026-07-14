const encoder = new TextEncoder();

export const SIGNING_DOMAIN = "heddle-req-sig-v1";
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
