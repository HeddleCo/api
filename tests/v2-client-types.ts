import { createServiceClient, type RpcTransport } from "../packages/typescript/dist/v2alpha1/client.js";
import { ThreadService } from "../packages/typescript/dist/v2alpha1/services_pb.js";
import type { ThreadListEvent, ThreadMutationResponse } from "../packages/typescript/dist/v2alpha1/thread_pb.js";

declare const transport: RpcTransport;
const client = createServiceClient(ThreadService, transport, new Set<string>());
const observation: AsyncIterable<ThreadListEvent> = client.observeThreads({ query: { spools: [{ id: "spool" }] } });
const mutation: Promise<ThreadMutationResponse> = client.startThread({ clientOperationId: "op", name: "thread" });
// @ts-expect-error Unknown agent plumbing is not an accepted product operation.
client.startThread({ manualHeartbeat: true });
// @ts-expect-error Observations are streams, not unary promises.
const wrong: Promise<ThreadListEvent> = client.observeThreads({});
void observation; void mutation; void wrong;
