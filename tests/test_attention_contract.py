from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parent.parent
ACTIVITY = (ROOT / "proto/heddle/api/v1alpha2/activity.proto").read_text()
THREAD = (ROOT / "proto/heddle/api/v1alpha2/thread.proto").read_text()
VIEWS = (ROOT / "proto/heddle/api/v1alpha2/views.proto").read_text()
SERVICES = (ROOT / "proto/heddle/api/v1alpha2/services.proto").read_text()


def body(source: str, kind: str, name: str) -> str:
    match = re.search(rf"(?ms)^{kind} {re.escape(name)} \{{(.*?)^\}}", source)
    if match is None:
        raise AssertionError(f"missing {kind} {name}")
    return match.group(1)


def fields(source: str, message: str) -> list[tuple[str, str, int]]:
    return [
        (field_type, field_name, int(tag))
        for field_type, field_name, tag in re.findall(
            r"(?m)^\s*(?:optional\s+|repeated\s+)?"
            r"([A-Za-z][A-Za-z0-9_.]*)\s+([a-z][a-z0-9_]*)\s*=\s*(\d+)\s*;",
            body(source, "message", message),
        )
    ]


class AttentionContractTest(unittest.TestCase):
    def test_capture_attribution_keeps_principal_and_delegated_agent(self) -> None:
        capture = body(THREAD, "message", "CaptureSummary")
        self.assertEqual(
            fields(THREAD, "CaptureSummary"),
            [
                ("RevisionRef", "revision", 1),
                ("ThreadRef", "thread", 2),
                ("string", "summary", 3),
                ("uint64", "changed_files", 4),
                ("string", "principal_id", 5),
                ("string", "agent_id", 6),
                ("google.protobuf.Timestamp", "captured_at", 7),
            ],
        )
        item = body(ACTIVITY, "message", "AttentionItem")
        self.assertRegex(item, r"\bEntityRef\s+subject\s*=\s*3\s*;")
        self.assertRegex(item, r"\bCaptureSummary\s+capture\s*=\s*9\s*;")
        self.assertIn("string principal_id = 5", capture)
        self.assertIn("string agent_id = 6", capture)

    def test_attention_resolution_is_explicit_and_versioned(self) -> None:
        item = body(ACTIVITY, "message", "AttentionItem")
        self.assertEqual(
            re.findall(r"(?m)^\s+(RESOLUTION_[A-Z_]+)\s*=\s*(\d+)", item),
            [
                ("RESOLUTION_UNSPECIFIED", "0"),
                ("RESOLUTION_PENDING", "1"),
                ("RESOLUTION_DISMISSED", "2"),
                ("RESOLUTION_ACTED_ON", "3"),
            ],
        )
        self.assertEqual(
            fields(ACTIVITY, "SetAttentionStateRequest"),
            [
                ("string", "client_operation_id", 1),
                ("RecordRef", "item", 2),
                ("bytes", "expected_version", 3),
                ("AttentionItem.Resolution", "resolution", 4),
                ("bool", "pinned", 5),
            ],
        )

    def test_observation_and_mutations_keep_distinct_effects(self) -> None:
        event = body(VIEWS, "message", "AttentionEvent")
        self.assertRegex(event, r"\bAttentionItem\s+item\s*=\s*2\s*;")
        service = body(SERVICES, "service", "AttentionService")
        self.assertRegex(
            service,
            r"rpc ObserveAttention\(ObserveAttentionRequest\) returns "
            r"\(stream AttentionEvent\)",
        )
        observe = re.search(r"(?ms)rpc ObserveAttention\(.*?^  \}", service)
        self.assertIsNotNone(observe)
        self.assertIn("RPC_EFFECT_READ_ONLY", observe.group(0))
        self.assertIn("RETRY_BEHAVIOR_RESUMABLE_STREAM", observe.group(0))
        for name in ("RecordInteraction", "SetAttentionState"):
            rpc = re.search(rf"(?ms)rpc {name}\(.*?^  \}}", service)
            self.assertIsNotNone(rpc)
            self.assertIn("RPC_EFFECT_DURABLE_WRITE", rpc.group(0))
            self.assertIn("client_operation_id_required: true", rpc.group(0))
            self.assertIn("AUTHORIZATION_SCOPE_SOURCE_CALLER_SUBJECT", rpc.group(0))


if __name__ == "__main__":
    unittest.main()
