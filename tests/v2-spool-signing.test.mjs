import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { getOption } from "@bufbuild/protobuf";
import { SpoolService } from "@heddleco/api/v2";
import { unarySigningBytes } from "../packages/typescript/dist/common/signing.js";
import {
  rpc_contract, SigningTier, RpcEffect, RetryBehavior,
} from "../packages/typescript/dist/common/contract_pb.js";

const fixture = JSON.parse(readFileSync(new URL("./fixtures/unary-signing-human-alpha43.json", import.meta.url)));

test("Spool deletion advertises per-request human verification", () => {
  assert.equal(fixture.route, "/heddle.api.v1alpha2.SpoolService/DeleteSpool");
  assert.equal(fixture.signing_tier, "HUMAN_VERIFICATION");
  for (const name of ["deleteSpool", "putGrant", "putReviewPolicy"]) {
    const contract = getOption(SpoolService.method[name], rpc_contract);
    assert.equal(contract.signingTier, SigningTier.HUMAN_VERIFICATION, name);
    assert.equal(contract.effect, RpcEffect.DURABLE_WRITE, name);
    assert.equal(contract.retryBehavior, RetryBehavior.CLIENT_OPERATION_ID, name);
    assert.equal(contract.clientOperationIdRequired, true, name);
  }
});

test("human-tier DeleteSpool preserves the frozen canonical request bytes", async () => {
  const canonical = await unarySigningBytes(
    fixture.identity, fixture.route, BigInt(fixture.timestamp_millis),
    Buffer.from(fixture.nonce_hex, "hex"), Buffer.from(fixture.request_hex, "hex"),
  );
  assert.equal(Buffer.from(canonical).toString("hex"), fixture.canonical_hex);
  const frozen = JSON.parse(readFileSync(new URL("./fixtures/unary-signing-v1.json", import.meta.url)));
  const { signing_tier, ...vector } = fixture;
  assert.deepEqual(vector, frozen);
});
