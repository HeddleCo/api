from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parent.parent
VIEWS = (ROOT / "proto/heddle/api/v1alpha2/views.proto").read_text()
SERVICES = (ROOT / "proto/heddle/api/v1alpha2/services.proto").read_text()


def body(source: str, kind: str, name: str) -> str:
    match = re.search(rf"(?ms)^{kind} {re.escape(name)} \{{(.*?)^\}}", source)
    if match is None:
        raise AssertionError(f"missing {kind} {name}")
    return match.group(1)


class ExploreContractTest(unittest.TestCase):
    def test_public_catalog_exposes_inputs_without_server_scoring_policy(self) -> None:
        request = body(VIEWS, "message", "ObserveCatalogRequest")
        self.assertRegex(request, r"\bstring\s+query\s*=\s*1\s*;")
        self.assertRegex(request, r"\bPageRequest\s+spools\s*=\s*2\s*;")
        self.assertRegex(request, r"\bObserveOptions\s+observe\s*=\s*3\s*;")
        self.assertRegex(request, r"\bCatalogSort\s+sort\s*=\s*4\s*;")

        sort = body(VIEWS, "enum", "CatalogSort")
        for value, number in (
            ("CATALOG_SORT_UNSPECIFIED", 0),
            ("CATALOG_SORT_NAME", 1),
            ("CATALOG_SORT_PATH", 2),
            ("CATALOG_SORT_RECENT_ACTIVITY", 3),
        ):
            self.assertRegex(sort, rf"\b{value}\s*=\s*{number}\s*;")

        spool = body(VIEWS, "message", "SpoolOverview")
        for field in ("ref", "name", "audience", "settings", "slug", "path_segments"):
            self.assertRegex(spool, rf"\b{field}\s*=")
        for field, number in (
            ("public_owner", 16),
            ("last_activity_at", 17),
            ("catalog_activity", 18),
        ):
            self.assertRegex(spool, rf"\b{field}\s*=\s*{number}\s*;")
        self.assertNotRegex(spool, r"\b(?:recency|score|lane)\s*=")

        owner = body(VIEWS, "message", "PublicOwner")
        self.assertRegex(owner, r"\bhandle\s*=\s*1\s*;")
        self.assertRegex(owner, r"\bdisplay_name\s*=\s*2\s*;")
        activity = body(VIEWS, "message", "CatalogActivitySummary")
        self.assertRegex(activity, r"\bopen_thread_count\s*=\s*1\s*;")
        self.assertRegex(activity, r"\blanded_30d\s*=\s*2\s*;")

        event = body(VIEWS, "message", "CatalogEvent")
        self.assertRegex(event, r"\bSpoolOverview\s+spool\s*=\s*2\s*;")
        self.assertRegex(event, r"\bSectionStatus\s+status\s*=\s*3\s*;")

        service = body(SERVICES, "service", "WorkspaceService")
        rpc = re.search(r"(?ms)rpc ObserveCatalog\(.*?^  \}", service)
        self.assertIsNotNone(rpc)
        self.assertIn("RPC_EFFECT_READ_ONLY", rpc.group(0))
        self.assertIn("AUTHORIZATION_ACCESS_PUBLIC", rpc.group(0))
        self.assertIn("RETRY_BEHAVIOR_RESUMABLE_STREAM", rpc.group(0))


if __name__ == "__main__":
    unittest.main()
