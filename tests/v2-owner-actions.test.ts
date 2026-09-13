import { describe, expect, it } from "vitest";
import { canonicalOwnerAction, OWNER_TRANSITION_POSSESSION, signOwnerActionPossession } from "../packages/typescript/dist/v2alpha1/owner-actions.js";

describe("native owner action possession", () => {
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
