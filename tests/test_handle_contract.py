from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
IDENTITY = (ROOT / "proto/heddle/api/v1alpha2/identity.proto").read_text()
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
            r"(?m)^\s*(?:(?:optional|repeated)\s+)?"
            r"([A-Za-z][A-Za-z0-9_.]*)\s+([a-z][a-z0-9_]*)\s*=\s*(\d+)\s*;",
            body(source, "message", message),
        )
    ]


def rpc(service: str, name: str) -> tuple[str, str, str]:
    match = re.search(
        rf"(?ms)^\s*rpc {re.escape(name)}\((\w+)\) returns \((\w+)\) "
        rf"\{{(.*?)^\s*\}}",
        service,
    )
    if match is None:
        raise AssertionError(f"missing rpc {name}")
    return match.group(1), match.group(2), match.group(3)


class SharedHandleContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.service = body(SERVICES, "service", "IdentityService")

    def test_handle_availability_was_replaced_by_explicit_resolution_status(self) -> None:
        resolution = body(IDENTITY, "message", "HandleResolution")
        self.assertEqual(
            re.findall(r"(?m)^\s+(STATUS_[A-Z_]+)\s*=\s*(\d+)", resolution),
            [
                ("STATUS_UNSPECIFIED", "0"),
                ("STATUS_AVAILABLE", "1"),
                ("STATUS_CLAIMED", "2"),
                ("STATUS_HELD", "3"),
                ("STATUS_UNAVAILABLE", "4"),
                ("STATUS_RESERVED", "5"),
                ("STATUS_CONFUSABLE", "6"),
            ],
        )
        self.assertRegex(resolution, r"\bStatus\s+status\s*=\s*3\s*;")
        self.assertRegex(
            resolution, r"\brepeated\s+Requirement\s+requirements\s*=\s*4\s*;"
        )
        self.assertRegex(
            resolution, r"\bbool\s+held_for_verified_owner\s*=\s*7\s*;"
        )
        self.assertIn("Never disclose\n  // the holder identity", resolution)

    def test_public_handle_projection_contains_no_stable_subject_identifier(self) -> None:
        record = body(IDENTITY, "message", "PublicHandleRecord")
        self.assertEqual(
            fields(IDENTITY, "PublicHandleRecord"),
            [
                ("string", "display_name", 1),
                ("string", "handle", 2),
                ("string", "primary_handle", 3),
                ("HandleKind", "kind", 4),
                ("bool", "verified", 5),
                ("string", "discriminator", 6),
            ],
        )
        self.assertNotRegex(record, r"\b(?:subject|account_id|principal_id)\s*=")
        self.assertIn("no stable subject/account identifiers", IDENTITY)

    def test_batched_resolution_preserves_status_and_tombstone_semantics(self) -> None:
        self.assertEqual(
            fields(IDENTITY, "ResolveHandlesRequest"),
            [("string", "handles", 1), ("ReadBudget", "budget", 2)],
        )
        self.assertEqual(
            fields(IDENTITY, "ResolveHandlesResponse"),
            [("HandleResolution", "handles", 1)],
        )
        resolution = body(IDENTITY, "message", "HandleResolution")
        self.assertRegex(resolution, r"\bPublicHandleRecord\s+public_handle\s*=\s*5\s*;")
        self.assertRegex(resolution, r"\bbool\s+tombstoned\s*=\s*6\s*;")

    def test_handle_mutations_keep_exact_retry_and_proof_shapes(self) -> None:
        self.assertEqual(
            fields(IDENTITY, "ClaimHandleRequest"),
            [
                ("string", "client_operation_id", 1),
                ("string", "handle", 2),
                ("SignedRecord", "entitlement_proof", 3),
            ],
        )
        self.assertEqual(
            fields(IDENTITY, "RequestHeldHandleRequest"),
            [
                ("string", "client_operation_id", 1),
                ("string", "handle", 2),
            ],
        )
        self.assertEqual(
            fields(IDENTITY, "RequestHeldHandleResponse"),
            [
                ("MutationReceipt", "receipt", 1),
                (
                    "google.protobuf.Timestamp",
                    "right_of_first_refusal_deadline",
                    2,
                ),
            ],
        )
        self.assertEqual(
            fields(IDENTITY, "ClaimHandleResponse"),
            [
                ("MutationReceipt", "receipt", 1),
                ("PublicHandleRecord", "public_handle", 2),
            ],
        )

    def test_all_handle_operations_have_descriptor_owned_contracts(self) -> None:
        expected = {
            "ResolveHandles": (
                "ResolveHandlesRequest",
                "ResolveHandlesResponse",
                "RPC_EFFECT_READ_ONLY",
                "RETRY_BEHAVIOR_SAFE",
                False,
            ),
            "ClaimHandle": (
                "ClaimHandleRequest",
                "ClaimHandleResponse",
                "RPC_EFFECT_DURABLE_WRITE",
                "RETRY_BEHAVIOR_CLIENT_OPERATION_ID",
                True,
            ),
            "RequestHeldHandle": (
                "RequestHeldHandleRequest",
                "RequestHeldHandleResponse",
                "RPC_EFFECT_DURABLE_WRITE",
                "RETRY_BEHAVIOR_CLIENT_OPERATION_ID",
                True,
            ),
        }
        for name, (request, response, effect, retry, operation_id) in expected.items():
            with self.subTest(name=name):
                actual_request, actual_response, contract = rpc(self.service, name)
                self.assertEqual((actual_request, actual_response), (request, response))
                self.assertIn(effect, contract)
                self.assertIn(retry, contract)
                self.assertEqual(
                    "client_operation_id_required: true" in contract, operation_id
                )
                self.assertIn(
                    "capability: CAPABILITY_AREA_IDENTITY_AND_CREDENTIALS", contract
                )

    def test_handle_operations_have_one_canonical_service_owner(self) -> None:
        all_sources = "\n".join(
            path.read_text()
            for path in sorted((ROOT / "proto/heddle/api/v1alpha2").glob("*.proto"))
        )
        service_blocks = re.findall(r"(?ms)^service (\w+) \{(.*?)^\}", all_sources)
        for method in ("ResolveHandles", "ClaimHandle", "RequestHeldHandle"):
            owners = [
                service_name
                for service_name, service_body in service_blocks
                if re.search(rf"(?m)^\s*rpc {method}\(", service_body)
            ]
            self.assertEqual(owners, ["IdentityService"], method)


if __name__ == "__main__":
    unittest.main()
