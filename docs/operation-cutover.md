# Shared Operation cutover

## Contract status

`OperationService` is `SHIPPED` for import submit/get/batch-get/watch through
Weft's durable import worker. Atomic batches, listing, remote synchronization,
and cancellation are partial and return `UNIMPLEMENTED`. The authoritative
service and lifecycle shapes are in
[`operation.proto`](../proto/heddle/api/v1alpha1/operation.proto).

The cutover replaces import-specific lifecycle messages; it does not preserve
an alias or a second status model. The legacy migration manifest maps
`ImportService/CreateImportJob` to `OperationService/SubmitOperation` and
`ImportService/StreamImportProgress` to `OperationService/WatchOperations`.

## Import mapping

| Previous import shape | Canonical Operation shape |
| --- | --- |
| `CreateImportJobRequest` source, visibility, adoption, and target fields | `SubmitOperationRequest.import_operation` (`ImportOperationSpec`) |
| string `job_id` | typed `Operation.operation_id` |
| `ImportProgressEvent.phase` | `Operation.state` for lifecycle plus `Operation.progress.phase` for import detail |
| import byte/object/commit counters | `OperationProgress.completed`, optional `total`, and `unit` |
| `ImportOutcome` | `Operation.error` on failure or `OperationResult.import_operation` on completion |
| `StreamImportProgress` reattachment | `GetOperation`, `BatchGetOperations`, `GetOperationBatch`, `ListOperations`, and snapshot-first `WatchOperations` |
| `ImportJobSummary` in `HostedSpool` | `HostedSpool.latest_import_operation_id`, followed by canonical operation lookup |

Batch import submission uses `SubmitOperationBatch`. The batch retry key is the
authenticated subject plus the batch `client_operation_id`; every member also
has its own subject + kind + `client_operation_id` identity. Retrying either
key returns the original typed identities. A failed retryable member uses a new
member `client_operation_id`; reusing its old key returns the original failed
operation.

## Remote synchronization mapping

Durable scheduled synchronization uses `OPERATION_KIND_REMOTE_SYNC` with
`RemoteSyncOperationSpec` and `RemoteSyncOperationResult`. `RepoSyncService`
`Push` and `Pull` remain directional transfer protocols used while work runs;
their stream frames are not durable job identity or lifecycle surfaces.

The remote-sync handler and storage work is planned in
[HeddleCo/weft#578](https://github.com/HeddleCo/weft/issues/578). It must resolve
provider mappings before submission, persist acceptance and deduplication
before acknowledging the producer, and publish all durable status through
`OperationService` rather than a sync-specific job API.

## Agent Gateway distinction

`TimelineOperationReceipt` acknowledges a `CanonicalTimelineOperation` frame
inside the planned `AgentGatewayService.Connect` stream. It does not represent
an asynchronous durable `Operation`, carry `OperationState`, or participate in
`OperationService` lookup and watch.

## Coordinated adoption requirement

1. Publish the API generation containing `OperationService` and the removed
   import-specific lifecycle.
2. Implement the planned Weft `OperationService` adapter and durable store.
   Existing import rows must be exposed as the one canonical `Operation`
   snapshot, including its monotonic sequence; no separate public import
   status endpoint remains after server cutover.
3. Change Tapestry import submission, cold load, retry, and reattachment to the
   canonical submit/get/list/watch methods. The client persistence work is
   planned in
   [HeddleCo/tapestry#156](https://github.com/HeddleCo/tapestry/issues/156).
4. Change hosted-spool reads to return `latest_import_operation_id`, then fetch
   the canonical snapshot. Deploy this with the Weft handler change because
   field 7 (`latest_import_job`) is removed and reserved.
5. Enable remote-sync producers only after Weft implements the planned mapping
   in HeddleCo/weft#578.

Until steps 2–5 are deployed together, the generated surface is a contract
foundation, not shipped runtime behavior.
