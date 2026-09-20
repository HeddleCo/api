from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parent.parent
COMMON = (ROOT / "proto/heddle/api/v1alpha2/common.proto").read_text()
ADMINISTRATION = (ROOT / "proto/heddle/api/v1alpha2/administration.proto").read_text()
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


class SpoolContractTest(unittest.TestCase):
    def test_flat_spool_promotion_uses_stable_spool_identity(self) -> None:
        self.assertEqual(
            fields(ADMINISTRATION, "PromoteSpoolRequest"),
            [
                ("string", "client_operation_id", 1),
                ("SpoolRef", "spool", 2),
                ("bytes", "expected_version", 3),
            ],
        )
        service = body(SERVICES, "service", "SpoolService")
        self.assertIn(
            "rpc PromoteSpool(PromoteSpoolRequest) returns (SpoolMutationResponse)",
            service,
        )
        rpc = re.search(r"(?ms)rpc PromoteSpool\(.*?^  \}", service)
        self.assertIsNotNone(rpc)
        self.assertIn("RPC_EFFECT_DURABLE_WRITE", rpc.group(0))
        self.assertIn("client_operation_id_required: true", rpc.group(0))

    def test_spool_settings_use_one_audience_vocabulary(self) -> None:
        self.assertEqual(
            fields(ADMINISTRATION, "SpoolSettings"),
            [
                ("Audience", "audience", 1),
                ("Audience", "default_state_audience", 2),
                ("string", "description", 3),
                ("bool", "allow_child_creation", 4),
                ("bool", "require_review_to_land", 5),
                ("google.protobuf.Duration", "abandoned_thread_retention", 6),
                ("RecordRef", "default_review_policy", 7),
                ("HoldLifecycle", "hold_lifecycle", 8),
            ],
        )
        audience = body(COMMON, "enum", "Audience")
        self.assertEqual(
            re.findall(r"(?m)^\s*(AUDIENCE_[A-Z_]+)\s*=\s*(\d+)", audience),
            [
                ("AUDIENCE_UNSPECIFIED", "0"),
                ("AUDIENCE_PRIVATE", "1"),
                ("AUDIENCE_MEMBERS", "2"),
                ("AUDIENCE_PUBLIC", "3"),
            ],
        )
        self.assertNotRegex(ADMINISTRATION, r"(?m)^enum (?:Spool)?Visibility \{")

    def test_spool_listing_carries_thread_summary_fields(self) -> None:
        self.assertEqual(
            fields(ADMINISTRATION, "ListedSpool"),
            [
                ("SpoolRef", "ref", 1),
                ("string", "path_segments", 2),
                ("bool", "is_repo", 3),
                ("google.protobuf.Timestamp", "last_activity_at", 4),
                ("uint32", "thread_count", 5),
                ("string", "head_thread", 6),
            ],
        )
        self.assertEqual(
            fields(ADMINISTRATION, "ListSpoolsResponse"),
            [("ListedSpool", "spools", 1)],
        )

    def test_create_spool_carries_complete_settings_and_ownership(self) -> None:
        self.assertEqual(
            fields(ADMINISTRATION, "CreateSpoolRequest"),
            [
                ("string", "client_operation_id", 1),
                ("SpoolRef", "parent", 2),
                ("string", "slug", 3),
                ("SpoolSettings", "settings", 4),
                ("SignedSpoolOwnerGenesis", "owner_genesis", 5),
                ("SpoolRef", "custodial_spool", 7),
                ("string", "display_name", 6),
            ],
        )
        request = body(ADMINISTRATION, "message", "CreateSpoolRequest")
        self.assertIn("stable new spool UUID comes only from genesis", request)
        self.assertIn("Retry the original signed genesis and operation ID", request)
        self.assertIn("never establishes\n    // a root", request)

    def test_live_spool_projection_carries_owner_genesis_and_canonical_path(self) -> None:
        overview = fields(VIEWS, "SpoolOverview")
        self.assertIn(("SignedSpoolOwnerGenesis", "owner_genesis", 10), overview)
        self.assertIn(("string", "path_segments", 12), overview)
        response = fields(VIEWS, "SpoolMutationResponse")
        self.assertEqual(
            response,
            [
                ("MutationReceipt", "receipt", 1),
                ("SpoolOverview", "spool", 2),
                ("OwnerState", "ownership", 3),
            ],
        )


if __name__ == "__main__":
    unittest.main()
