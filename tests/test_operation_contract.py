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


if __name__ == "__main__":
    unittest.main()
