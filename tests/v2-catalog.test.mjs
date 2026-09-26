import test from "node:test";
import assert from "node:assert/strict";
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { TimestampSchema } from "@bufbuild/protobuf/wkt";
import {
  CatalogActivitySummarySchema,
  CatalogEventSchema,
  CatalogSort,
  ObserveCatalogRequestSchema,
  SpoolOverviewSchema,
} from "../packages/typescript/dist/v1alpha2/views_pb.js";
import { PublicOwnerSchema } from "../packages/typescript/dist/v1alpha2/common_pb.js";

test("public catalog fields and sort survive binary round trips", () => {
  const request = create(ObserveCatalogRequestSchema, {
    query: "spool",
    sort: CatalogSort.RECENT_ACTIVITY,
  });
  const decodedRequest = fromBinary(
    ObserveCatalogRequestSchema,
    toBinary(ObserveCatalogRequestSchema, request),
  );
  assert.equal(decodedRequest.sort, CatalogSort.RECENT_ACTIVITY);

  const row = create(SpoolOverviewSchema, {
    publicOwner: create(PublicOwnerSchema, {
      handle: "ada",
      displayName: "Ada",
    }),
    lastActivityAt: create(TimestampSchema, { seconds: 1_750_000_000n }),
    catalogActivity: create(CatalogActivitySummarySchema, {
      openThreadCount: 4n,
      landed30d: 7n,
    }),
  });
  const event = create(CatalogEventSchema, {
    payload: { case: "spool", value: row },
  });
  const decoded = fromBinary(CatalogEventSchema, toBinary(CatalogEventSchema, event));
  assert.equal(decoded.payload.case, "spool");
  assert.equal(decoded.payload.value.publicOwner?.handle, "ada");
  assert.equal(decoded.payload.value.publicOwner?.displayName, "Ada");
  assert.equal(decoded.payload.value.lastActivityAt?.seconds, 1_750_000_000n);
  assert.equal(decoded.payload.value.catalogActivity?.openThreadCount, 4n);
  assert.equal(decoded.payload.value.catalogActivity?.landed30d, 7n);
});
