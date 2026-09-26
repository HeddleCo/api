/** Passkey display labels are account metadata, outside PasskeyAuthority. */
export const DEFAULT_PASSKEY_LABEL = "Passkey";
export const MAX_PASSKEY_LABEL_BYTES = 256;
const utf8 = new TextEncoder();

/** Validate and trim a registration or rename label before storage. An empty
 * result clears the stored label so observations use the server default. */
export function normalizePasskeyLabel(label: string): string {
  if (/[\p{Cc}]/u.test(label)) throw new Error("Passkey label contains a control character");
  const trimmed = label.replace(/^\p{White_Space}+|\p{White_Space}+$/gu, "");
  if (utf8.encode(trimmed).length > MAX_PASSKEY_LABEL_BYTES) {
    throw new Error("Passkey label exceeds 256 UTF-8 bytes after trimming");
  }
  return trimmed;
}

/** Display the stored label, including the default for older passkeys. */
export function passkeyDisplayLabel(storedLabel: string): string {
  return storedLabel || DEFAULT_PASSKEY_LABEL;
}
