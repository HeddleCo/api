import test from "node:test";
import assert from "node:assert/strict";
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { createServiceClient, describeTools, ContractClientError } from "../packages/typescript/dist/v2alpha1/client.js";
import { ThreadService, SyncService } from "../packages/typescript/dist/v2alpha1/services_pb.js";
import { StartThreadRequestSchema, ThreadMutationResponseSchema, ThreadListEventSchema } from "../packages/typescript/dist/v2alpha1/thread_pb.js";
import { ReplicateThreadResponseSchema } from "../packages/typescript/dist/v2alpha1/sync_pb.js";

const startPath = "/heddle.api.v2alpha1.ThreadService/StartThread";
const observePath = "/heddle.api.v2alpha1.ThreadService/ObserveThreads";

test("typed client transmits the original operation ID and returns the resulting Thread", async () => {
  let calls = 0;
  const transport = {
    async unary(method, bytes, options) {
      calls++;
      assert.equal(method.name, "StartThread");
      assert.equal(options.deadline.getTime(), 10000);
      const request = fromBinary(StartThreadRequestSchema, bytes);
      assert.equal(request.clientOperationId, "original-op");
      return toBinary(ThreadMutationResponseSchema, create(ThreadMutationResponseSchema, {
        receipt: { clientOperationId: request.clientOperationId, outcome: { case: "applied", value: {} } },
        thread: { name: request.name, version: new Uint8Array([9]) },
      }));
    },
  };
  const client = createServiceClient(ThreadService, transport, new Set([startPath]));
  const result = await client.startThread({ clientOperationId: "original-op", name: "intent" }, { deadline: new Date(10000) });
  assert.equal(result.thread.name, "intent");
  assert.equal(result.receipt.outcome.case, "applied");
  assert.equal(calls, 1);
});

test("compiled routes do not imply implemented handlers or idempotency identities", async () => {
  let calls = 0;
  const transport = { async unary() { calls++; throw new Error("must not send"); } };
  const unsupported = createServiceClient(ThreadService, transport, new Set());
  await assert.rejects(unsupported.startThread({ clientOperationId: "op" }), (error) => error instanceof ContractClientError && error.reason === "not_implemented");
  const supported = createServiceClient(ThreadService, transport, new Set([startPath]));
  await assert.rejects(supported.startThread({}), (error) => error instanceof ContractClientError && error.reason === "operation_id_missing");
  assert.equal(calls, 0);
});

test("ambiguous write failure is surfaced without automatically repeating it", async () => {
  let calls = 0;
  const transport = { async unary() { calls++; throw new Error("reply lost"); } };
  const client = createServiceClient(ThreadService, transport, new Set([startPath]));
  await assert.rejects(client.startThread({ clientOperationId: "recover-this-op" }), /reply lost/);
  assert.equal(calls, 1);
});

test("observation is pull-based and returns the endpoint stream on early exit", async () => {
  let messages = 0;
  let closed = false;
  const transport = {
    async *open(method, requests) {
      assert.equal(method.name, "ObserveThreads");
      const inputs = []; for await (const input of requests) inputs.push(input);
      assert.equal(inputs.length, 1);
      try {
        messages++;
        yield toBinary(ThreadListEventSchema, create(ThreadListEventSchema, { payload: { case: "thread", value: { name: "first" } } }));
        messages++;
        yield toBinary(ThreadListEventSchema, create(ThreadListEventSchema, { payload: { case: "thread", value: { name: "second" } } }));
      } finally { closed = true; }
    },
  };
  const client = createServiceClient(ThreadService, transport, new Set([observePath]));
  for await (const event of client.observeThreads({})) { assert.equal(event.payload.value.name, "first"); break; }
  assert.equal(messages, 1);
  assert.equal(closed, true);
});

test("bidirectional transfer pulls client frames as the endpoint consumes them", async () => {
  let produced = 0;
  let sourceClosed = false;
  const source = async function* () {
    try {
      produced++;
      yield { body: { case: "open", value: {} } };
      produced++;
      yield { body: { case: "have", value: {} } };
    } finally { sourceClosed = true; }
  };
  const transport = {
    async *open(_method, requests) {
      for await (const _ of requests) {
        assert.equal(produced, 1);
        yield toBinary(ReplicateThreadResponseSchema, create(ReplicateThreadResponseSchema, { body: { case: "ready", value: {} } }));
      }
    },
  };
  const client = createServiceClient(SyncService, transport, new Set(["/heddle.api.v2alpha1.SyncService/ReplicateThread"]));
  for await (const _ of client.replicateThread(source())) break;
  assert.equal(produced, 1);
  assert.equal(sourceClosed, true);
});

test("agent tool selection requires both task selection and endpoint implementation", () => {
  const tools = describeTools([ThreadService], new Set([startPath, observePath]), new Set([observePath]));
  assert.equal(tools.length, 1);
  assert.equal(tools[0].path, observePath);
  assert.equal(tools[0].streaming, "server_streaming");
  assert.equal(tools[0].input.typeName, "heddle.api.v2alpha1.ObserveThreadsRequest");
  assert.ok(tools[0].contract.retryBehavior > 0);
  assert.deepEqual(describeTools([ThreadService], new Set(), new Set([startPath])), []);
});

test("agent tools distinguish live subscriptions from finite resumable uploads", () => {
  const paths = new Set([observePath, "/heddle.api.v2alpha1.SyncService/ReplicateThread", "/heddle.api.v2alpha1.SyncService/PublishContent"]);
  const tools = describeTools([ThreadService, SyncService], paths, paths);
  assert.equal(tools.length, 3);
  for (const tool of tools) {
    assert.equal(tool.contract.liveStream, !tool.path.endsWith("/PublishContent"), tool.path);
  }
});
