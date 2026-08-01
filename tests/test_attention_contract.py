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
