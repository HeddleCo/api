from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parent.parent
ATTENTION_PROTO = ROOT / "proto/heddle/api/v1alpha1/attention.proto"


def block_body(source: str, kind: str, name: str) -> str:
    match = re.search(
        rf"(?ms)^{re.escape(kind)} {re.escape(name)} \{{(.*?)^\}}", source
    )
    if match is None:
        raise AssertionError(f"missing {kind} {name}")
    return match.group(1)


class AttentionContractTest(unittest.TestCase):
    def test_feed_file_capture_attribution_is_explicit_and_honest(self) -> None:
        source = ATTENTION_PROTO.read_text()
        item = block_body(source, "message", "FeedItem")
        file_summary = block_body(source, "message", "FileChangeSummary")
        status = block_body(source, "enum", "FeedFileAttributionStatus")
        capture = block_body(source, "message", "FeedCaptureSummary")

        self.assertRegex(item, r"\bFeedCaptureSummary\s+head_capture\s*=\s*26\s*;")
        self.assertRegex(file_summary, r"\bstring\s+path\s*=\s*1\s*;")
        self.assertRegex(file_summary, r"\bFileChangeKind\s+kind\s*=\s*2\s*;")
        self.assertRegex(file_summary, r"\bstring\s+entry_id\s*=\s*3\s*;")
        self.assertRegex(
            file_summary,
            r"\bFeedFileAttributionStatus\s+attribution_status\s*=\s*4\s*;",
        )
        self.assertRegex(
            file_summary, r"\bFeedCaptureSummary\s+attribution\s*=\s*5\s*;"
        )
        self.assertRegex(
            status, r"\bFEED_FILE_ATTRIBUTION_STATUS_COMPUTED\s*=\s*1\s*;"
        )
        self.assertRegex(
            status, r"\bFEED_FILE_ATTRIBUTION_STATUS_UNAVAILABLE\s*=\s*2\s*;"
        )
        for field, tag in (
            ("StateId state_id", 1),
            ("ChangeId change_id", 2),
            ("string thread", 3),
            ("string capture_message", 4),
            ("string author_display", 5),
            ("google.protobuf.Timestamp captured_at", 6),
            ("uint32 additions", 7),
            ("uint32 deletions", 8),
        ):
            self.assertRegex(capture, rf"\b{re.escape(field)}\s*=\s*{tag}\s*;")
        self.assertIn("never a FeedItem headline", source)
        self.assertIn("never inferred from", source)
        self.assertIn("FileChangeKind or an aggregate feed diff", source)
        self.assertIn("attribution is", source)
        self.assertIn("then absent", source)

    def test_feed_attribution_keeps_root_subject_and_adds_delegation_agent_id(self) -> None:
        item = block_body(ATTENTION_PROTO.read_text(), "message", "FeedItem")

        self.assertRegex(item, r"\bstring\s+actor_subject\s*=\s*13\s*;")
        self.assertRegex(item, r"\bstring\s+actor_agent_id\s*=\s*25\s*;")
        self.assertIn("Empty for", item)
        self.assertIn("actor_subject remains the root subject", item)

    def test_feed_verification_is_an_explicit_three_state_projection(self) -> None:
        source = ATTENTION_PROTO.read_text()
        item = block_body(source, "message", "FeedItem")
        status = block_body(source, "enum", "FeedItemVerificationStatus")

        self.assertRegex(
            item,
            r"\bFeedItemVerificationStatus\s+verification_status\s*=\s*24\s*;",
        )
        self.assertIn("tests_passed", item)
        self.assertIn("tests_failed", item)
        self.assertIn("not computed", item)
        self.assertRegex(
            status,
            r"\bFEED_ITEM_VERIFICATION_STATUS_UNSPECIFIED\s*=\s*0\s*;",
        )
        self.assertRegex(status, r"\bFEED_ITEM_VERIFICATION_STATUS_VERIFIED\s*=\s*1\s*;")
        self.assertRegex(
            status,
            r"\bFEED_ITEM_VERIFICATION_STATUS_NOT_VERIFIED\s*=\s*2\s*;",
        )
        self.assertEqual(len(re.findall(r"(?m)^\s*[A-Z][A-Z0-9_]*\s*=", status)), 3)


if __name__ == "__main__":
    unittest.main()
