import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { canonicalOwnerAction, ownerActionSigningBytes, OWNER_RECOVERY_POSSESSION, OWNER_TRANSITION_POSSESSION, signOwnerActionPossession } from "../packages/typescript/dist/v1alpha2/owner-actions.js";

const rust = JSON.parse(readFileSync(new URL("./fixtures/owner_recovery_action_v1.json", import.meta.url), "utf8"));
const bytes = (hex: string) => new Uint8Array(Buffer.from(hex, "hex"));

describe("native owner action possession", () => {
  it("matches the independently produced Rust canonical and signing bytes", () => {
    const canonical = canonicalOwnerAction(rust.account_id, rust.client_operation_id,
      { $typeName: "heddle.api.v1alpha2.RecordRef", id: rust.reference_id },
      bytes(rust.version_hex), bytes(rust.proposed_key_hex));
    expect(Buffer.from(canonical).toString("hex")).toBe(rust.canonical_hex);
    expect(Buffer.from(ownerActionSigningBytes(OWNER_RECOVERY_POSSESSION, canonical)).toString("hex"))
      .toBe(rust.signing_hex);
  });
  it("signs the exact canonical transition, rejects a mismatched signer and snapshots async inputs", async () => {
    const pair = await crypto.subtle.generateKey("Ed25519", false, ["sign", "verify"]);
    const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
    const version = Uint8Array.of(3, 4, 5);
    const reference = { id: "00000000-0000-4000-8000-000000000003" };
    const canonical = canonicalOwnerAction("00000000-0000-4000-8000-000000000001",
      "00000000-0000-4000-8000-000000000002", reference, version, publicKey);
    const decodeLength = (offset: number) => new DataView(canonical.buffer).getUint32(offset);
    expect(decodeLength(0)).toBe(1);
    expect(decodeLength(4)).toBe(36);
    const expected = canonical.slice();
    let release: (() => void) | undefined;
    const gate = new Promise<void>(resolve => { release = resolve; });
    const pending = signOwnerActionPossession(OWNER_TRANSITION_POSSESSION,
      "00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002",
      reference, version, publicKey, { publicKey, async sign(bytes) {
        await gate;
        return new Uint8Array(await crypto.subtle.sign("Ed25519", pair.privateKey, bytes));
      } });
    version.fill(9); reference.id = "changed"; publicKey.fill(7); release?.();
    const signed = await pending;
    expect(signed.canonicalRecord).toEqual(expected);
    expect(signed.signatures).toHaveLength(1);
    const key = await crypto.subtle.importKey("raw", signed.signatures[0]!.publicKey, "Ed25519", false, ["verify"]);
    const signingBytes = new Uint8Array([...new TextEncoder().encode(OWNER_TRANSITION_POSSESSION), 0, ...expected]);
    expect(await crypto.subtle.verify("Ed25519", key, signed.signatures[0]!.signature, signingBytes)).toBe(true);
    await expect(signOwnerActionPossession(OWNER_TRANSITION_POSSESSION, "account", "op", { id: "ref" },
      Uint8Array.of(1), signed.signatures[0]!.publicKey, { publicKey: signed.signatures[0]!.publicKey,
        sign: async () => new Uint8Array(64) })).rejects.toThrow("does not match");
  });
});
