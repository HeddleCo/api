/** Advisory identity metadata; never authority or authenticator trust. */
import { normalizePasskeyLabel } from "./passkey-label.js";

export const MAX_SESSION_USER_AGENT_BYTES = 8192;
export const MAX_PASSKEY_CREDENTIAL_ID_BYTES = 1024;
export const HELD_NAME_REQUESTED = "HELD_NAME_REQUESTED";
export const HELD_NAME_REQUEST_LAPSED = "HELD_NAME_REQUEST_LAPSED";
const utf8 = new TextEncoder();

/** Empty clears the explicit name; observation falls back to the primary handle
 * or generated pet name while unclaimed. Same normalization as passkey labels. */
export function normalizeDisplayName(value: string): string {
  return normalizePasskeyLabel(value);
}

/** Device labels and authenticator names use NFC and the 256 UTF-8 byte limit.
 * Empty means no advisory label, without a "Passkey" fallback. */
export function normalizeAdvisoryLabel(value: string): string {
  return normalizePasskeyLabel(value);
}

export function validateAaguid(value: Uint8Array | undefined): void {
  if (value !== undefined && value.length !== 16) {
    throw new Error("AAGUID must be absent or exactly 16 bytes");
  }
}

export function validatePasskeyCredentialId(value: Uint8Array | undefined): void {
  if (value !== undefined && (value.length === 0 || value.length > MAX_PASSKEY_CREDENTIAL_ID_BYTES)) {
    throw new Error("Passkey credential ID must be absent or 1..1024 bytes");
  }
}

/** Retain verbatim. Empty means unavailable. Reject Cc and invalid UTF-16. */
export function validateSessionUserAgent(value: string): void {
  if (utf8.encode(value).length > MAX_SESSION_USER_AGENT_BYTES) {
    throw new Error("User agent exceeds 8192 UTF-8 bytes");
  }
  if (/[\p{Cc}\p{Cs}]/u.test(value)) throw new Error("User agent contains a control character or invalid Unicode");
}
