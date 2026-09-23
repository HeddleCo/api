import test from "node:test";
import assert from "node:assert/strict";
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { TimestampSchema } from "@bufbuild/protobuf/wkt";
import {
  DeviceIdentitySchema,
  IdentityEventSchema,
} from "../packages/typescript/dist/v1alpha2/views_pb.js";

test("owned device liveness survives an identity event round trip", () => {
  const event = create(IdentityEventSchema, {
    payload: {
      case: "device",
      value: create(DeviceIdentitySchema, {
        lastSeenAt: create(TimestampSchema, { seconds: 1_750_000_000n, nanos: 123_000_000 }),
        online: true,
      }),
    },
  });

  const decoded = fromBinary(IdentityEventSchema, toBinary(IdentityEventSchema, event));
  assert.equal(decoded.payload.case, "device");
  assert.equal(decoded.payload.value.lastSeenAt?.seconds, 1_750_000_000n);
  assert.equal(decoded.payload.value.lastSeenAt?.nanos, 123_000_000);
  assert.equal(decoded.payload.value.online, true);

  const unknown = fromBinary(
    DeviceIdentitySchema,
    toBinary(DeviceIdentitySchema, create(DeviceIdentitySchema)),
  );
  assert.equal(unknown.lastSeenAt, undefined);
  assert.equal(unknown.online, undefined);
});
