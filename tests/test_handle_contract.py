from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

from tools.build_contract import REPLACED_METHODS


ROOT = Path(__file__).resolve().parent.parent
PROTO = ROOT / "proto/heddle/api/v1alpha1/identity.proto"
FIXTURE = ROOT / "tests/fixtures/handle-contract-v1.json"
PACKAGE = "heddle.api.v1alpha1"


def named_body(source: str, kind: str, name: str) -> str:
    match = re.search(
        rf"(?ms)^{re.escape(kind)} {re.escape(name)} \{{(.*?)^\}}",
        source,
    )
    if match is None:
        raise AssertionError(f"missing {kind} {name}")
    return match.group(1)


def rpc_body(service: str, name: str) -> tuple[str, str, str]:
    match = re.search(
        rf"(?ms)^\s*rpc {re.escape(name)}\((\w+)\) returns \((\w+)\) \{{(.*?)^\s*\}}",
        service,
    )
    if match is None:
        raise AssertionError(f"missing rpc {name}")
    return match.group(1), match.group(2), match.group(3)


class SharedHandleContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = PROTO.read_text()
        cls.fixture = json.loads(FIXTURE.read_text())

    def test_all_handle_operations_have_descriptor_owned_contracts(self) -> None:
        service = named_body(self.source, "service", "IdentityService")
        for name, expected in self.fixture.items():
            request, response, body = rpc_body(service, name)
            self.assertEqual(request, expected["request"])
            self.assertEqual(response, expected["response"])
            self.assertIn(
                "signing_identity: STABLE_SIGNING_IDENTITY_AUTHENTICATED_PRINCIPAL",
                body,
            )
            self.assertIn(
                f"signing_tier: SIGNING_TIER_{expected['signing_tier']}", body
            )
            self.assertIn(f"effect: RPC_EFFECT_{expected['effect']}", body)
            self.assertIn(
                f"retry_behavior: RETRY_BEHAVIOR_{expected['retry_behavior']}", body
            )
            required = "client_operation_id_required: true" in body
            self.assertEqual(required, expected["client_operation_id_required"])
            self.assertIn("capability: CAPABILITY_AREA_IDENTITY_AND_CREDENTIALS", body)

    def test_handle_wire_shapes_preserve_live_semantics(self) -> None:
        availability = named_body(self.source, "enum", "HandleAvailability")
        for value in (
            "AVAILABLE",
            "HELD",
            "TAKEN",
            "RESERVED",
            "CONFUSABLE",
        ):
            self.assertIn(f"HANDLE_AVAILABILITY_{value}", availability)

        principal = named_body(self.source, "message", "HandlePrincipal")
        self.assertNotRegex(principal, r"\bsubject\s*=")
        for field in (
            "display_name",
            "handle",
            "resolved",
            "primary_handle",
            "kind",
            "verified",
            "discriminator",
        ):
            self.assertRegex(principal, rf"\b{field}\s*=")

        status = named_body(self.source, "message", "GetHandleStatusResponse")
        self.assertRegex(status, r"\bHandleAvailability\s+availability\s*=")
        self.assertRegex(status, r"\bbool\s+held_for_verified_owner\s*=")

        request = named_body(self.source, "message", "RequestHeldNameRequest")
        self.assertRegex(request, r"\bstring\s+name\s*=")
        self.assertRegex(request, r"\bstring\s+client_operation_id\s*=")
        response = named_body(self.source, "message", "RequestHeldNameResponse")
        self.assertRegex(response, r"\bgoogle\.protobuf\.Timestamp\s+rfr_deadline\s*=")

        request = named_body(self.source, "message", "ClaimHandleRequest")
        self.assertRegex(request, r"\bstring\s+name\s*=")
        self.assertRegex(request, r"\bstring\s+client_operation_id\s*=")
        response = named_body(self.source, "message", "ClaimHandleResponse")
        self.assertRegex(response, r"\bbool\s+claimed\s*=")
        self.assertRegex(response, r"\bstring\s+canonical_handle\s*=")

        response = named_body(self.source, "message", "ResolveHandleResponse")
        self.assertRegex(response, r"\bHandlePrincipal\s+principal\s*=")
        self.assertRegex(response, r"\bbool\s+tombstoned\s*=")

    def test_comments_lock_existence_hiding_and_retry_semantics(self) -> None:
        for fragment in (
            "MUST NOT expose the holder subject",
            "same NOT_FOUND status and public error shape",
            "MUST NOT expose an underlying subject",
            "same authenticated subject, RPC, and client_operation_id",
            "same response without repeating the mutation",
            "reuse with a different normalized name MUST fail",
        ):
            self.assertIn(fragment, self.source)

    def test_migration_manifest_preserves_all_four_operations(self) -> None:
        methods = {
            entry["old_rpc"]: entry
            for entry in json.loads((ROOT / "migration-manifest.json").read_text())[
                "methods"
            ]
        }
        for method in self.fixture:
            legacy = f"heddle.v1.HostedUserService/{method}"
            entry = methods[legacy]
            expected = self.fixture[method]
            self.assertEqual(entry["classification"], "renamed")
            self.assertEqual(
                entry["new_rpc"], f"{PACKAGE}.IdentityService/{method}"
            )
            for evidence in ("production_callsite", "production_implementation"):
                self.assertEqual(entry.get(evidence), expected.get(evidence))

    def test_extraction_aid_cannot_reclassify_handles_as_dropped(self) -> None:
        for method in self.fixture:
            self.assertEqual(
                REPLACED_METHODS[("HostedUserService", method)],
                f"IdentityService/{method}",
            )

    def test_every_consumer_declares_each_handle_operation(self) -> None:
        for consumer in ("heddle", "tapestry", "weft"):
            declaration = json.loads(
                (ROOT / f"capabilities/declarations/{consumer}.json").read_text()
            )
            rpcs = {row["rpc"] for row in declaration["rpc_mappings"]}
            for method in self.fixture:
                self.assertIn(f"{PACKAGE}.IdentityService/{method}", rpcs)


if __name__ == "__main__":
    unittest.main()
