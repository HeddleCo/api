from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parent.parent
COMMON_TYPES = (ROOT / "proto/heddle/api/common/types.proto").read_text()
COMMON = (ROOT / "proto/heddle/api/v1alpha2/common.proto").read_text()
THREAD = (ROOT / "proto/heddle/api/v1alpha2/thread.proto").read_text()
SYNC = (ROOT / "proto/heddle/api/v1alpha2/sync.proto").read_text()


def body(source: str, kind: str, name: str) -> str:
    match = re.search(rf"(?ms)^{kind} {re.escape(name)} \{{(.*?)^\}}", source)
    if match is None:
        raise AssertionError(f"missing {kind} {name}")
    return match.group(1)


def field_names(source: str, message: str) -> list[str]:
    return [
        name
        for name in re.findall(
            r"(?m)^\s*(?:(?:optional|repeated)\s+)?"
            r"[A-Za-z][A-Za-z0-9_.]*\s+([a-z][a-z0-9_]*)\s*=\s*\d+",
            body(source, "message", message),
        )
    ]


class RevisionAndThreadIdentityContractTest(unittest.TestCase):
    def test_state_id_is_physical_and_distinct_from_change_id(self) -> None:
        state_id = body(COMMON_TYPES, "message", "StateId").lower()
        change_id = body(COMMON_TYPES, "message", "ChangeId").lower()
        self.assertIn("immutable physical revision identity", state_id)
        self.assertIn("exactly 32 bytes", state_id)
        self.assertIn("not a logical changeid", state_id)
        self.assertIn("rewrite-stable logical change identity", change_id)
        self.assertIn("exactly 16 bytes", change_id)

    def test_thread_identity_is_one_typed_spool_scoped_reference(self) -> None:
        self.assertEqual(field_names(COMMON, "ThreadId"), ["value"])
        self.assertEqual(field_names(COMMON, "ThreadRef"), ["spool", "id"])
        thread_ref = body(COMMON, "message", "ThreadRef")
        self.assertRegex(thread_ref, r"\bSpoolRef\s+spool\s*=\s*1\s*;")
        self.assertRegex(thread_ref, r"\bThreadId\s+id\s*=\s*2\s*;")
        revision = body(COMMON, "message", "RevisionRef")
        self.assertRegex(revision, r"\bSpoolRef\s+spool\s*=\s*1\s*;")
        self.assertRegex(
            revision, r"\bheddle\.api\.common\.StateId\s+state\s*=\s*2\s*;"
        )
        self.assertRegex(revision, r"\bstring\s+git_commit_oid\s*=\s*3\s*;")

    def test_thread_list_projection_keeps_identity_status_and_decision_context(self) -> None:
        overview = body(THREAD, "message", "ThreadOverview")
        required = {
            "ref",
            "name",
            "version",
            "intent",
            "source_heads",
            "base",
            "lifecycle",
            "readiness",
            "requirements",
            "relationships",
            "updated_at",
            "ownership",
            "source_frontier",
        }
        self.assertTrue(required.issubset(field_names(THREAD, "ThreadOverview")))
        self.assertRegex(overview, r"\bThreadRef\s+ref\s*=\s*1\s*;")
        self.assertRegex(overview, r"\brepeated\s+RevisionRef\s+source_heads\s*=\s*5\s*;")
        event = body(THREAD, "message", "ThreadListEvent")
        self.assertRegex(event, r"\bThreadOverview\s+thread\s*=\s*2\s*;")

    def test_thread_queries_use_refs_instead_of_parallel_name_and_id_pairs(self) -> None:
        query = body(THREAD, "message", "ThreadQuery")
        self.assertRegex(query, r"\bThreadRef\s+parent\s*=\s*6\s*;")
        self.assertNotRegex(query, r"\bparent_thread_id\s*=")
        start = body(THREAD, "message", "StartThreadRequest")
        self.assertRegex(start, r"\bSpoolRef\s+spool\s*=\s*2\s*;")
        self.assertRegex(start, r"\bSignedRecord\s+thread_genesis\s*=\s*3\s*;")
        self.assertIn("derives\n  // the Thread ID", start)

    def test_replication_handshake_preserves_exact_thread_identity(self) -> None:
        opened = body(SYNC, "message", "ReplicationOpen")
        ready = body(SYNC, "message", "ReplicationReady")
        transfer = body(SYNC, "message", "TransferReady")
        self.assertRegex(opened, r"\bThreadRef\s+thread\s*=\s*1\s*;")
        self.assertRegex(
            opened, r"\bThreadGenesisRecord\s+thread_genesis\s*=\s*4\s*;"
        )
        self.assertRegex(ready, r"\bThreadRef\s+thread\s*=\s*2\s*;")
        self.assertRegex(transfer, r"\bThreadRef\s+thread\s*=\s*2\s*;")
        self.assertRegex(transfer, r"\bRevisionRef\s+current\s*=\s*3\s*;")
        self.assertRegex(
            transfer, r"\bThreadGenesisRecord\s+thread_genesis\s*=\s*16\s*;"
        )


if __name__ == "__main__":
    unittest.main()
