from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parent.parent
OPERATION_PROTO = ROOT / "proto/heddle/api/v1alpha1/operation.proto"


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

    def test_lookup_and_cancellation_do_not_create_identity_oracles(self) -> None:
        source = OPERATION_PROTO.read_text()
        batch_response = message_body(source, "BatchGetOperationsResponse")
        cancel_request = message_body(source, "CancelOperationRequest")

        self.assertIn("same NOT_FOUND status and public error shape", batch_response)
        self.assertIn("without\n  // identifying which id failed", batch_response)
        self.assertIn("authenticated subject and target", cancel_request)
        self.assertIn("operation_id", cancel_request)
        self.assertIn("different operation", cancel_request)


if __name__ == "__main__":
    unittest.main()
