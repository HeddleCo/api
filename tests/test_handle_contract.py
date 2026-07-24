from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

from tools.build_contract import REPLACED_METHODS


ROOT = Path(__file__).resolve().parent.parent
PROTO = ROOT / "proto/heddle/api/v1alpha1/identity.proto"
FIXTURE = ROOT / "tests/fixtures/handle-contract-v1.json"
WIRE_FIXTURE = ROOT / "tests/fixtures/handle-wire-v1.json"
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


def rpc_comment(service: str, name: str) -> str:
    match = re.search(
        rf"(?m)((?:^[ \t]*//[^\n]*\n)+)[ \t]*rpc {re.escape(name)}\(",
        service,
    )
    if match is None:
        raise AssertionError(f"missing documentation for rpc {name}")
    return " ".join(
        re.sub(r"^[ \t]*//[ ]?", "", line).strip()
        for line in match.group(1).splitlines()
    )


def named_comment(source: str, kind: str, name: str) -> str:
    match = re.search(
        rf"(?m)((?:^//[^\n]*\n)+){re.escape(kind)} {re.escape(name)} \{{",
        source,
    )
    if match is None:
        raise AssertionError(f"missing documentation for {kind} {name}")
    return " ".join(
        re.sub(r"^//[ ]?", "", line).strip()
        for line in match.group(1).splitlines()
    )


def enum_value_comment(enum_body: str, name: str) -> str:
    match = re.search(
        rf"(?m)((?:^[ \t]*//[^\n]*\n)+)[ \t]*HANDLE_AVAILABILITY_{re.escape(name)}\s*=",
        enum_body,
    )
    if match is None:
        raise AssertionError(f"missing documentation for HANDLE_AVAILABILITY_{name}")
    return " ".join(
        re.sub(r"^[ \t]*//[ ]?", "", line).strip()
        for line in match.group(1).splitlines()
    )


class SharedHandleContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = PROTO.read_text()
        cls.all_proto_sources = "\n".join(
            path.read_text()
            for path in sorted((ROOT / "proto/heddle/api/v1alpha1").glob("*.proto"))
        )
        cls.fixture = json.loads(FIXTURE.read_text())
        cls.wire_fixture = json.loads(WIRE_FIXTURE.read_text())

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
        self.assertRegex(principal, r'\breserved\s+1\s*;')
        self.assertRegex(principal, r'\breserved\s+"subject"\s*;')
        public_field_tags = {
            field: int(tag)
            for field, tag in re.findall(
                r"(?m)^\s*(?:string|bool)\s+(\w+)\s*=\s*(\d+)\s*;",
                principal,
            )
        }
        self.assertEqual(
            public_field_tags,
            self.wire_fixture["public_field_tags"],
        )

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

    def test_resolve_preserves_legacy_subject_route_without_a_subject_response(self) -> None:
        request = named_body(self.source, "message", "ResolveHandleRequest")
        for request_form in self.wire_fixture["request_forms"]:
            self.assertIn(f"`{request_form}`", request)
        self.assertIn("MUST preserve `/u:<subject>` request lookup compatibility", request)
        self.assertIn("subject-free HandlePrincipal projection", request)

        principal = named_body(self.source, "message", "HandlePrincipal")
        reserved = self.wire_fixture["reserved_legacy_field"]
        self.assertRegex(principal, rf"\breserved\s+{reserved['tag']}\s*;")
        self.assertRegex(principal, rf'\breserved\s+"{reserved["name"]}"\s*;')
        self.assertNotRegex(principal, r"\bsubject\s*=")

    def test_available_native_names_have_explicit_successful_paths(self) -> None:
        availability = named_body(self.source, "enum", "HandleAvailability")
        for method in self.wire_fixture["available_native_paths"][
            "genuinely_free_new_account"
        ]:
            self.assertIn(method, availability)

        service = named_body(self.source, "service", "IdentityService")
        claim_comment = rpc_comment(service, "ClaimHandle")
        for method in self.wire_fixture["available_native_paths"][
            "caller_owned_hold"
        ]:
            self.assertIn(method, claim_comment)
        self.assertIn("held_for_verified_owner = true", claim_comment)
        self.assertIn("genuinely free AVAILABLE names", claim_comment)
        self.assertIn("same NOT_FOUND status and public error shape", claim_comment)

        request_comment = rpc_comment(service, "RequestHeldName")
        self.assertIn("held by another verified owner", request_comment)
        self.assertIn("same NOT_FOUND status and public error shape", request_comment)

    def test_every_availability_state_names_its_actual_next_operation(self) -> None:
        availability = named_body(self.source, "enum", "HandleAvailability")
        for state, operations in self.wire_fixture[
            "availability_next_operations"
        ].items():
            comment = enum_value_comment(availability, state)
            for operation in operations:
                self.assertIn(operation, comment, state)

        for state in self.wire_fixture["states_without_current_candidate_mutation"]:
            comment = enum_value_comment(availability, state)
            self.assertRegex(
                comment,
                r"(?:[Nn]o .*mutation|MUST NOT infer that a mutation)",
                state,
            )

    def test_each_rpc_locks_its_own_existence_hiding_and_retry_semantics(self) -> None:
        status = named_body(self.source, "message", "GetHandleStatusResponse")
        self.assertIn("MUST NOT expose the holder subject", status)

        service = named_body(self.source, "service", "IdentityService")
        claim_comment = rpc_comment(service, "ClaimHandle")
        self.assertIn("same NOT_FOUND status and public error shape", claim_comment)
        request_comment = rpc_comment(service, "RequestHeldName")
        self.assertIn("same NOT_FOUND status and public error shape", request_comment)
        resolve_comment = rpc_comment(service, "ResolveHandle")
        self.assertIn("subject-free projection", resolve_comment)
        self.assertIn("never-claimed names return", resolve_comment)

        self.assertIn(
            "MUST NOT expose an underlying subject",
            named_comment(self.source, "message", "HandlePrincipal"),
        )
        for request_name in ("ClaimHandleRequest", "RequestHeldNameRequest"):
            request = named_body(self.source, "message", request_name)
            for fragment in (
                "same authenticated subject, RPC, and client_operation_id",
                "same response without repeating the mutation",
                "reuse with a different normalized name MUST fail",
            ):
                self.assertIn(fragment, request, request_name)

    def test_handle_operations_have_one_canonical_service_owner(self) -> None:
        service_blocks = re.findall(
            r"(?ms)^service (\w+) \{(.*?)^\}", self.all_proto_sources
        )
        for method in self.fixture:
            owners = [
                service_name
                for service_name, body in service_blocks
                if re.search(rf"(?m)^\s*rpc {re.escape(method)}\(", body)
            ]
            self.assertEqual(owners, ["IdentityService"], method)

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

        for method in self.wire_fixture["available_native_paths"][
            "genuinely_free_new_account"
        ]:
            legacy = f"heddle.v1.AuthService/{method}"
            entry = methods[legacy]
            self.assertEqual(entry["classification"], "renamed")
            self.assertEqual(
                entry["new_rpc"], f"{PACKAGE}.IdentityService/{method}"
            )
            self.assertEqual(
                entry["production_implementation"],
                "HeddleCo/weft:crates/weft-server/src/server/hosted/auth.rs",
            )

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
