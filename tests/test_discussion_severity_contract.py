from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parent.parent
COLLABORATION = (
    ROOT / "proto/heddle/api/v1alpha1/collaboration.proto"
).read_text()


def body(kind: str, name: str) -> str:
    match = re.search(
        rf"(?ms)^{kind} {re.escape(name)} \{{(.*?)^\}}", COLLABORATION
    )
    if match is None:
        raise AssertionError(f"missing {kind} {name}")
    return match.group(1)


class DiscussionSeverityContractTest(unittest.TestCase):
    def test_severity_is_additive_actual_state(self) -> None:
        severity = body("enum", "DiscussionSeverity")
        self.assertEqual(
            re.findall(r"DISCUSSION_SEVERITY_(\w+)\s*=\s*(\d+)", severity),
            [("UNSPECIFIED", "0"), ("INFORMATIONAL", "1"), ("BLOCKING", "2")],
        )

        discussion = body("message", "Discussion")
        self.assertRegex(
            discussion, r"\bDiscussionSeverity\s+severity\s*=\s*13\s*;"
        )
        for required in (
            "Actual value, no inference",
            "UNSPECIFIED is treated as Informational",
            "(non-blocking); BLOCKING makes an open discussion",
            "unmet merge",
            "requirement; a Reject",
            "a Reject sets Blocking",
        ):
            self.assertIn(required, discussion)


if __name__ == "__main__":
    unittest.main()
