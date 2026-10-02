import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { test } from "node:test";
import * as api from "../packages/typescript/dist/v1alpha2/index.js";
import * as common from "../packages/typescript/dist/common/index.js";

const fixture = JSON.parse(readFileSync(new URL("./fixtures/import-authority-host-witness-v1.json", import.meta.url)));

test("HYBRID conformance vectors require the additive wire messages", () => {
  assert.ok(fixture.messages.length > 0);
  for (const name of fixture.messages) {
    const schema = (name.includes(".common.") ? common : api)[`${name.split(".").at(-1)}Schema`];
    assert.ok(schema, `missing ${name}`);
    assert.equal(schema.typeName, name);
  }
});
