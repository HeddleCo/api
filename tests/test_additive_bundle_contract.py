from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parent.parent
COLLABORATION = (ROOT / "proto/heddle/api/v1alpha1/collaboration.proto").read_text()
REPOSITORY = (ROOT / "proto/heddle/api/v1alpha1/repository.proto").read_text()
STATE_REVIEW = (ROOT / "proto/heddle/api/v1alpha1/state_review.proto").read_text()


def body(source: str, kind: str, name: str) -> str:
    match = re.search(rf"(?ms)^{kind} {name} \{{(.*?)^\}}", source)
    if match is None:
        raise AssertionError(f"missing {kind} {name}")
    return match.group(1)


def fields(source: str, message: str) -> list[tuple[str, int]]:
    return [
        (name, int(tag))
        for name, tag in re.findall(
            r"(?m)^\s*(?:(?:optional|repeated)\s+)?[A-Za-z][A-Za-z0-9_.]*\s+"
            r"([a-z][a-z0-9_]*)\s*=\s*(\d+)\s*;",
            body(source, "message", message),
        )
    ]


class AdditiveBundleContractTest(unittest.TestCase):
    def test_list_discussions_by_states_is_batched_digest_read(self) -> None:
        self.assertEqual(
            fields(COLLABORATION, "ListDiscussionsByStatesRequest"),
            [("repo_path", 1), ("state_ids", 2), ("status", 3)],
        )
        self.assertEqual(
            fields(COLLABORATION, "StateDiscussionDigest"),
            [
                ("state_id", 1),
                ("discussion_count", 2),
                ("open_count", 3),
                ("resolved_count", 4),
                ("orphaned_count", 5),
                ("discussions", 6),
            ],
        )
        service = body(COLLABORATION, "service", "CollaborationService")
        self.assertIn(
            "rpc ListDiscussionsByStates(ListDiscussionsByStatesRequest) "
            "returns (ListDiscussionsByStatesResponse)",
            service,
        )
        rpc = re.search(r"(?ms)rpc ListDiscussionsByStates\(.*?\n  \}", service)
        self.assertIsNotNone(rpc)
        self.assertIn("RPC_EFFECT_READ_ONLY", rpc.group(0))
        self.assertIn("AUTHORIZATION_ACCESS_AUTHENTICATED_PRINCIPAL", rpc.group(0))

    def test_list_thread_histories_is_batched_list_states(self) -> None:
        self.assertEqual(
            fields(REPOSITORY, "ListThreadHistoriesRequest"),
            [("repo_path", 1), ("refs", 2), ("limit", 3)],
        )
        self.assertEqual(
            fields(REPOSITORY, "ThreadHistory"),
            [("ref", 1), ("states", 2)],
        )
        service = body(REPOSITORY, "service", "RepositoryService")
        self.assertIn(
            "rpc ListThreadHistories(ListThreadHistoriesRequest) "
            "returns (ListThreadHistoriesResponse)",
            service,
        )

    def test_reading_order_entries_are_additive_and_range_bearing(self) -> None:
        partition = body(STATE_REVIEW, "message", "ReadingOrderPartition")
        self.assertRegex(partition, r"repeated PathSymbolRef structural = 1")
        self.assertRegex(partition, r"repeated ReadingOrderEntry structural_entries = 4")
        self.assertRegex(partition, r"repeated ReadingOrderEntry consequence_entries = 5")
        self.assertRegex(
            partition, r"repeated ReadingOrderEntry tests_and_docs_entries = 6"
        )
        self.assertEqual(
            fields(STATE_REVIEW, "ReadingOrderEntry"),
            [("ref", 1), ("start_line", 2), ("end_line", 3)],
        )
        entry = body(STATE_REVIEW, "message", "ReadingOrderEntry")
        self.assertIn("optional uint32 start_line = 2", entry)
        self.assertIn("optional uint32 end_line = 3", entry)
        path_symbol = body(STATE_REVIEW, "message", "PathSymbolRef")
        self.assertNotRegex(path_symbol, r"start_line|end_line")


if __name__ == "__main__":
    unittest.main()
