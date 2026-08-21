from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parent.parent
OPERATION_PROTO = ROOT / "proto/heddle/api/v1alpha1/operation.proto"
TYPES_PROTO = ROOT / "proto/heddle/api/v1alpha1/types.proto"


def message_body(source: str, name: str) -> str:
    match = re.search(rf"(?ms)^message {re.escape(name)} \{{(.*?)^\}}", source)
    if match is None:
        raise AssertionError(f"missing message {name}")
    return match.group(1)


class SharedOperationContractTest(unittest.TestCase):
    def test_retry_submission_returns_same_operation_identity(self) -> None:
        self.assertTrue(OPERATION_PROTO.exists(), "missing canonical operation.proto")
        source = OPERATION_PROTO.read_text()

        operation = message_body(source, "Operation")
        response = message_body(source, "SubmitOperationResponse")

        self.assertRegex(operation, r"\bOperationId\s+operation_id\s*=")
        self.assertRegex(response, r"\bOperation\s+operation\s*=")
        self.assertIn(
            "same subject, operation kind, and client_operation_id returns the same operation_id",
            source,
        )

    def test_reconnect_is_snapshot_first_and_sequence_never_regresses(self) -> None:
        source = OPERATION_PROTO.read_text()
        operation = message_body(source, "Operation")
        checkpoint = message_body(source, "OperationWatchCheckpoint")
        event = message_body(source, "OperationWatchEvent")

        self.assertRegex(operation, r"\buint64\s+sequence\s*=")
        self.assertRegex(checkpoint, r"\buint64\s+after_sequence\s*=")
        self.assertRegex(event, r"\bOperation\s+operation\s*=")
        self.assertRegex(event, r"\bbool\s+snapshot\s*=")
        self.assertIn("Every connection is", source)
        self.assertIn("snapshot-first", source)
        self.assertIn("sequence >= the requested after_sequence", source)
        self.assertIn("strictly larger sequences", source)

    def test_import_commit_history_and_failure_identity_are_durable(self) -> None:
        source = OPERATION_PROTO.read_text()
        progress = message_body(source, "OperationProgress")
        commit = message_body(source, "ImportCommitProgress")
        failure = message_body(source, "ImportCommitFailure")

        self.assertRegex(
            progress,
            r"\brepeated\s+ImportCommitProgress\s+import_commits\s*=\s*6\s*;",
        )
        self.assertRegex(
            progress,
            r"\boptional\s+ImportCommitFailure\s+failed_import_commit\s*=\s*7\s*;",
        )
        self.assertIn("Snapshot-first watch reconnects", progress)
        self.assertRegex(commit, r"\buint64\s+ordinal\s*=\s*1\s*;")
        self.assertRegex(commit, r"\bstring\s+commit_hash\s*=\s*2\s*;")
        self.assertRegex(commit, r"\bstring\s+subject\s*=\s*3\s*;")
        self.assertRegex(commit, r"\boptional\s+uint64\s+additions\s*=\s*4\s*;")
        self.assertRegex(commit, r"\boptional\s+uint64\s+deletions\s*=\s*5\s*;")
        self.assertRegex(commit, r"\bstring\s+author_name\s*=\s*6\s*;")
        self.assertRegex(commit, r"\bstring\s+author_email\s*=\s*7\s*;")
        self.assertRegex(commit, r"\brepeated\s+string\s+branches\s*=\s*8\s*;")
        self.assertRegex(failure, r"\buint64\s+ordinal\s*=\s*1\s*;")
        self.assertRegex(
            failure, r"\boptional\s+string\s+commit_hash\s*=\s*2\s*;"
        )

    def test_import_observability_is_durable_actual_only_progress(self) -> None:
        source = OPERATION_PROTO.read_text()
        progress = message_body(source, "OperationProgress")
        timing = message_body(source, "PhaseTiming")
        ref_summary = message_body(source, "RefSummary")

        self.assertRegex(
            progress,
            r"\boptional\s+google\.protobuf\.Timestamp\s+started_at\s*=\s*8\s*;",
        )
        self.assertRegex(
            progress, r"\brepeated\s+PhaseTiming\s+phase_timings\s*=\s*9\s*;"
        )
        self.assertRegex(
            progress,
            r"\boptional\s+uint64\s+native_bytes_written\s*=\s*10\s*;",
        )
        self.assertRegex(
            progress,
            r"\boptional\s+uint64\s+source_pack_bytes\s*=\s*11\s*;",
        )
        self.assertRegex(
            progress, r"\boptional\s+RefSummary\s+ref_summary\s*=\s*12\s*;"
        )
        self.assertRegex(
            progress, r"\boptional\s+uint64\s+object_writes\s*=\s*13\s*;"
        )
        self.assertRegex(timing, r"\bstring\s+phase\s*=\s*1\s*;")
        self.assertRegex(
            timing,
            r"\bgoogle\.protobuf\.Timestamp\s+started_at\s*=\s*2\s*;",
        )
        self.assertRegex(
            timing,
            r"\boptional\s+google\.protobuf\.Timestamp\s+ended_at\s*=\s*3\s*;",
        )
        self.assertRegex(
            ref_summary, r"\buint32\s+advertised_branches\s*=\s*1\s*;"
        )
        self.assertRegex(ref_summary, r"\buint32\s+advertised_tags\s*=\s*2\s*;")
        self.assertRegex(
            ref_summary, r"\boptional\s+string\s+oldest_tag_name\s*=\s*3\s*;"
        )
        self.assertRegex(
            ref_summary, r"\buint32\s+published_branches\s*=\s*4\s*;"
        )
        self.assertRegex(ref_summary, r"\buint32\s+published_tags\s*=\s*5\s*;")
        self.assertIn("durable job record", progress)
        self.assertIn("snapshot-repeated", progress)
        self.assertIn("ACTUAL, never projected/estimated", progress)
        self.assertIn("Actual, never projected", progress)
        self.assertIn("Actual, not projected", progress)
        self.assertNotRegex(progress, r"(?i)reduction(_percent|_percentage|_ratio)?\s*=")

    def test_import_requested_visibility_uses_unified_enum(self) -> None:
        source = OPERATION_PROTO.read_text()
        spec = message_body(source, "ImportOperationSpec")
        self.assertRegex(spec, r"\bVisibility\s+requested_visibility\s*=\s*4\s*;")
        self.assertNotRegex(spec, r"\bSpoolVisibility\s+requested_visibility\b")

    def test_import_and_gateway_do_not_define_a_second_operation_lifecycle(self) -> None:
        source = OPERATION_PROTO.read_text()
        result = message_body(source, "OperationResult")
        self.assertRegex(result, r"\bImportOperationResult\s+import_operation\s*=")
        self.assertRegex(result, r"\bRemoteSyncOperationResult\s+remote_sync\s*=")

        proto_sources = "\n".join(
            path.read_text() for path in (ROOT / "proto/heddle/api/v1alpha1").glob("*.proto")
        )
        for removed in (
            "CreateImportJob",
            "StreamImportProgress",
            "ImportProgressEvent",
            "ImportJobSummary",
            "message OperationReceipt",
        ):
            self.assertNotIn(removed, proto_sources)

    def test_remote_link_management_is_create_first_and_exposes_honored_directions(self) -> None:
        source = OPERATION_PROTO.read_text()
        link = message_body(source, "RemoteLink")
        set_request = message_body(source, "SetRemoteLinkRequest")
        get_request = message_body(source, "GetRemoteLinkRequest")

        for field in (
            "spool_id",
            "source_url",
            "direction",
            "sync_interval",
            "next_sync_at",
            "auth_mode",
            "enabled",
            "status",
            "last_synced_at",
            "last_error",
            "diverged_refs",
        ):
            self.assertRegex(link, rf"\b{field}\s*=")
        self.assertRegex(
            link,
            r"\brepeated\s+RemoteSyncDirection\s+honored_directions\s*=\s*12\s*;",
        )
        self.assertRegex(set_request, r"\bstring\s+spool_id\s*=\s*1\s*;")
        self.assertRegex(set_request, r"\boneof\s+source\s*\{")
        self.assertRegex(set_request, r"\bRemoteSyncDirection\s+direction\s*=\s*5\s*;")
        self.assertRegex(
            set_request,
            r"\bgoogle\.protobuf\.Duration\s+sync_interval\s*=\s*6\s*;",
        )
        self.assertRegex(set_request, r"\bbool\s+enabled\s*=\s*7\s*;")
        self.assertRegex(
            set_request, r"\bstring\s+client_operation_id\s*=\s*8\s*;"
        )
        self.assertRegex(get_request, r"\bstring\s+spool_id\s*=\s*1\s*;")
        self.assertIn("missing remote_links row is the normal create path", source)
        self.assertIn("Saving PUSH_TO_REMOTE or", source)
        self.assertIn("does not activate push", source)
        self.assertIn("continues to return UNIMPLEMENTED", source)

    def test_remote_link_reuses_remote_sync_direction_with_bidirectional_configuration(self) -> None:
        source = OPERATION_PROTO.read_text()
        direction = re.search(
            r"(?ms)^enum RemoteSyncDirection \{(.*?)^\}", source
        )
        self.assertIsNotNone(direction)
        body = direction.group(1)
        self.assertRegex(
            body,
            r"\bREMOTE_SYNC_DIRECTION_BIDIRECTIONAL\s*=\s*3\s*;",
        )
        self.assertIn("Valid for RemoteLink.direction only", body)
        self.assertIn("PUSH_TO_REMOTE remains UNIMPLEMENTED until weft#387", source)

    def test_lookup_and_cancellation_do_not_create_identity_oracles(self) -> None:
        source = OPERATION_PROTO.read_text()
        batch_response = message_body(source, "BatchGetOperationsResponse")
        cancel_request = message_body(source, "CancelOperationRequest")

        self.assertIn("same NOT_FOUND status and public error shape", batch_response)
        self.assertIn("without\n  // identifying which id failed", batch_response)
        self.assertIn("authenticated subject and target", cancel_request)
        self.assertIn("operation_id", cancel_request)
        self.assertIn("different operation", cancel_request)

    def test_listing_can_select_one_repository_without_narrowing_legacy_clients(self) -> None:
        operation_source = OPERATION_PROTO.read_text()
        types_source = TYPES_PROTO.read_text()
        request = message_body(operation_source, "ListOperationsRequest")
        repository = message_body(types_source, "RepositoryRef")

        self.assertRegex(request, r"\bRepositoryRef\s+repository\s*=\s*6\s*;")
        self.assertIn("When omitted", request)
        self.assertIn("all operations owned", request)
        self.assertIn("authenticated", request)
        self.assertRegex(repository, r"\bstring\s+hosted_id\s*=\s*1\s*;")
        self.assertRegex(repository, r"\bstring\s+canonical_path\s*=\s*2\s*;")


if __name__ == "__main__":
    unittest.main()
