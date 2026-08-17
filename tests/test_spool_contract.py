from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parent.parent
REGISTRY = (ROOT / "proto/heddle/api/v1alpha1/registry.proto").read_text()


def body(name: str) -> str:
    match = re.search(rf"(?ms)^message {name} \{{(.*?)^\}}", REGISTRY)
    if match is None:
        raise AssertionError(f"missing message {name}")
    return match.group(1)


def fields(name: str) -> list[tuple[str, str, int]]:
    return [
        (field_type, field_name, int(number))
        for field_type, field_name, number in re.findall(
            r"(?m)^\s*(?:optional\s+)?"
            r"([A-Za-z][A-Za-z0-9_.]*)\s+([a-z][a-z0-9_]*)\s*=\s*(\d+)\s*;",
            body(name),
        )
    ]


class SpoolContractTest(unittest.TestCase):
    def test_state_visibility_rename_preserves_wire_tag(self) -> None:
        settings = body("SpoolSettings")
        self.assertIn('reserved "default_state_visibility";', settings)
        self.assertIn(
            ("Visibility", "state_visibility", 2),
            fields("SpoolSettings"),
        )
        self.assertIn(("Visibility", "visibility", 1), fields("SpoolSettings"))
        self.assertNotRegex(settings, r"\bSpoolStateVisibility default_state_visibility\b")
        self.assertNotRegex(settings, r"\benum SpoolVisibility\b")
        self.assertNotRegex(settings, r"\benum SpoolStateVisibility\b")
        self.assertIn("Spool-level baseline for state visibility", settings)

    def test_spool_summary_carries_thread_listing_fields(self) -> None:
        self.assertEqual(
            fields("SpoolSummary"),
            [
                ("string", "spool_id", 1),
                ("string", "full_path", 2),
                ("string", "kind", 3),
                ("bool", "is_repo", 4),
                ("google.protobuf.Timestamp", "last_activity_at", 5),
                ("uint32", "thread_count", 6),
                ("string", "head_thread", 7),
            ],
        )
        summary = body("SpoolSummary")
        self.assertIn("is_thread = true", summary)
        self.assertIn("GetRefs", summary)
        self.assertIn("default thread", summary)

    def test_create_spool_carries_complete_settings(self) -> None:
        self.assertEqual(
            fields("CreateSpoolRequest"),
            [
                ("string", "parent_path", 1),
                ("string", "slug", 2),
                ("bool", "is_repo", 3),
                ("string", "display_name", 4),
                ("Visibility", "visibility", 5),
                ("string", "client_operation_id", 6),
                ("SpoolSettings", "settings", 7),
                ("SignedSpoolOwnerGenesis", "owner_genesis", 8),
            ],
        )
        request = body("CreateSpoolRequest")
        self.assertIn("Complete create-time settings", request)
        self.assertIn("state-visibility", request)
        self.assertIn("rather than silently", request)
        self.assertIn("UUIDv7", request)
        self.assertIn(("SignedSpoolOwnerGenesis", "owner_genesis", 10), fields("HostedSpool"))

    def test_every_spool_creation_shape_carries_owner_genesis(self) -> None:
        self.assertIn(
            ("SignedSpoolOwnerGenesis", "owner_genesis", 7),
            fields("CreateNamespaceRequest"),
        )
        self.assertIn(
            ("SignedSpoolOwnerGenesis", "owner_genesis", 4),
            fields("CreateRepositoryRequest"),
        )
        self.assertIn(
            ("SignedSpoolOwnerGenesis", "owner_genesis", 9),
            fields("HostedNamespace"),
        )
        self.assertIn(
            ("SignedSpoolOwnerGenesis", "owner_genesis", 7),
            fields("HostedRepository"),
        )

    def test_unified_visibility_numbering(self) -> None:
        visibility = re.search(r"(?ms)^enum Visibility \{(.*?)^\}", REGISTRY)
        if visibility is None:
            raise AssertionError("missing Visibility enum")
        body = visibility.group(1)
        self.assertIn("VISIBILITY_UNSPECIFIED = 0", body)
        self.assertIn("VISIBILITY_PRIVATE = 1", body)
        self.assertIn("VISIBILITY_INTERNAL = 2", body)
        self.assertIn("VISIBILITY_PUBLIC = 3", body)
        self.assertNotRegex(REGISTRY, r"(?m)^enum SpoolVisibility \{")
        self.assertNotRegex(REGISTRY, r"(?m)^enum SpoolStateVisibility \{")
        self.assertEqual(
            fields("SetSpoolVisibilityRequest"),
            [
                ("string", "full_path", 1),
                ("Visibility", "visibility", 2),
                ("string", "client_operation_id", 3),
            ],
        )
        self.assertEqual(
            fields("SetNamespaceVisibilityRequest"),
            [
                ("string", "full_path", 1),
                ("Visibility", "visibility", 2),
                ("string", "client_operation_id", 3),
            ],
        )
        self.assertIn(("Visibility", "visibility", 8), fields("HostedNamespace"))


if __name__ == "__main__":
    unittest.main()
