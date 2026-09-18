import { createServiceClient, type RpcTransport } from "../packages/typescript/dist/v1alpha2/client.js";
import { SearchService, ThreadService } from "../packages/typescript/dist/v1alpha2/services_pb.js";
import { SearchSourceHistory } from "../packages/typescript/dist/v1alpha2/content_pb.js";
import type { ThreadListEvent, ThreadMutationResponse } from "../packages/typescript/dist/v1alpha2/thread_pb.js";

declare const transport: RpcTransport;
const client = createServiceClient(ThreadService, transport, new Set<string>());
const observation: AsyncIterable<ThreadListEvent> = client.observeThreads({ query: { spools: [{ id: "spool" }] } });
const mutation: Promise<ThreadMutationResponse> = client.startThread({ clientOperationId: "op", threadGenesis: { format: "heddle-thread-genesis-v1", canonicalRecord: new Uint8Array() } });
// @ts-expect-error Unknown agent plumbing is not an accepted product operation.
client.startThread({ manualHeartbeat: true });
// @ts-expect-error Observations are streams, not unary promises.
const wrong: Promise<ThreadListEvent> = client.observeThreads({});
void observation; void mutation; void wrong;

const search = createServiceClient(SearchService, transport, new Set<string>());
search.search({ text: "authorize", sourceScope: { case: "sourceHistory", value: SearchSourceHistory.RETAINED } });
search.search({ text: "authorize", threads: [{ spool: { id: "spool" }, id: { value: new Uint8Array(32) } }],
  sourceScope: { case: "sourceRevision", value: { spool: { id: "spool" }, revision: { case: "state", value: { value: new Uint8Array(32) } } } } });
// @ts-expect-error Exact revision and history are mutually exclusive selections.
search.search({ text: "authorize", sourceScope: { case: "sourceHistory", value: { spool: { id: "spool" } } } });
