from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parent.parent
PROTO = ROOT / "proto" / "heddle" / "api" / "v1alpha1"


def message_body(source: str, name: str) -> str:
    match = re.search(rf"(?ms)^message {re.escape(name)} \{{(.*?)^\}}", source)
    if match is None:
        raise AssertionError(f"missing message {name}")
    return match.group(1)


class RevisionAndThreadIdentityContractTest(unittest.TestCase):
    def test_state_id_is_physical_and_distinct_from_change_id(self) -> None:
        source = (PROTO / "types.proto").read_text()
        state_id = message_body(source, "StateId").lower()
        change_id = message_body(source, "ChangeId").lower()

        self.assertIn("immutable physical revision identity", state_id)
        self.assertIn("exactly 32 bytes", state_id)
        self.assertIn("not a logical changeid", state_id)
        self.assertIn("rewrite-stable logical change identity", change_id)
        self.assertIn("exactly 16 bytes", change_id)

        all_proto = "\n".join(path.read_text() for path in PROTO.glob("*.proto"))
        self.assertNotIn("16-byte ChangeIds", all_proto)
        self.assertNotIn("package-wide wire convention", all_proto)

    def test_thread_entities_and_scoped_requests_pair_ids_with_refs(self) -> None:
        expected_fields = {
            "agent.proto": {
                "ListAgentRunsRequest": ("thread_ref", "thread_id"),
                "AgentRun": ("thread_ref", "thread_id"),
            },
            "attention.proto": {
                "FeedItemAction": ("thread", "thread_id"),
            },
            "collaboration.proto": {
                "OpenDiscussionRequest": ("thread_ref", "thread_id"),
                "Discussion": ("thread_ref", "thread_id"),
            },
            "registry.proto": {
                "WorktreeSummary": ("thread", "thread_id"),
                "ActorSummary": ("thread", "thread_id"),
                "ThreadApproval": (
                    "source_thread",
                    "source_thread_id",
                    "target_thread",
                    "target_thread_id",
                ),
                "ApproveThreadRequest": (
                    "source_thread",
                    "source_thread_id",
                    "target_thread",
                    "target_thread_id",
                ),
                "ListThreadApprovalsRequest": (
                    "source_thread",
                    "source_thread_id",
                    "target_thread",
                    "target_thread_id",
                ),
                "CheckMergeEligibilityRequest": (
                    "source_thread",
                    "source_thread_id",
                    "target_thread",
                    "target_thread_id",
                ),
            },
            "repo_sync.proto": {
                "ListRefsResponse": ("head_thread", "head_thread_id"),
                "UpdateRefRequest": ("name", "thread_id"),
                "UpdateRefResponse": ("thread_id",),
                "PushRequest": ("target_thread", "target_thread_id"),
                "PushComplete": ("target_thread_id",),
                "GitCheckpointTransfer": ("thread", "thread_id"),
                "PullRequest": ("remote_thread", "remote_thread_id"),
            },
            "repository.proto": {
                "SubscribeRepoEventsRequest": ("thread", "thread_id"),
                "RepoEvent": ("thread", "thread_id"),
            },
            "search.proto": {
                "ThreadHit": ("thread_id", "thread_ref"),
            },
            "types.proto": {
                "RefEntry": ("name", "thread_id"),
            },
            "workflow.proto": {
                "ThreadSummary": (
                    "name",
                    "thread_id",
                    "target_thread",
                    "target_thread_id",
                    "parent_thread",
                    "parent_thread_id",
                    "child_threads",
                    "child_thread_ids",
                    "superseded_by",
                    "superseded_by_thread_id",
                    "supersedes",
                    "supersedes_thread_ids",
                ),
                "ThreadMetadata": (
                    "name",
                    "thread_id",
                    "target_thread",
                    "target_thread_id",
                    "parent_thread",
                    "parent_thread_id",
                ),
                "GetThreadRequest": ("name", "thread_id"),
                "WorkspaceSummary": ("current_thread", "current_thread_id"),
            },
        }

        for filename, messages in expected_fields.items():
            source = (PROTO / filename).read_text()
            for message, fields in messages.items():
                with self.subTest(message=message):
                    body = message_body(source, message)
                    for field in fields:
                        self.assertRegex(body, rf"\b{re.escape(field)}\s*=")

    def test_policy_patterns_and_local_pull_destinations_remain_refs(self) -> None:
        registry = (PROTO / "registry.proto").read_text()
        sync = (PROTO / "repo_sync.proto").read_text()

        self.assertNotIn("target_thread_pattern_id", registry)
        self.assertNotIn("local_thread_id", message_body(sync, "PullRequest"))


if __name__ == "__main__":
    unittest.main()
