/** Passkey display labels are account metadata, outside PasskeyAuthority. */
export const DEFAULT_PASSKEY_LABEL = "Passkey";
export const MAX_PASSKEY_LABEL_BYTES = 256;
const utf8 = new TextEncoder();
const forbidden = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Zl}\p{Zp}]/u;

/** Validate and normalize a registration or rename label before storage. An empty
 * result clears the stored label so observations use the server default. */
export function normalizePasskeyLabel(label: string): string {
  const normalized = label.replace(/^\p{White_Space}+|\p{White_Space}+$/gu, "").normalize("NFC");
  if (forbidden.test(normalized)) throw new Error("Passkey label contains a forbidden Unicode character");
  if (utf8.encode(normalized).length > MAX_PASSKEY_LABEL_BYTES) {
    throw new Error("Passkey label exceeds 256 UTF-8 bytes after NFC");
  }
  return normalized;
}

/** Display the stored label, including the default for older passkeys. */
export function passkeyDisplayLabel(storedLabel: string): string {
  return storedLabel || DEFAULT_PASSKEY_LABEL;
}
