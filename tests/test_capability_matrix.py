#!/usr/bin/env python3
"""Failure-mode tests for the public descriptor-derived capability matrix."""

from __future__ import annotations

import copy
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.capability_matrix import (
    AuditError,
    audit_declarations,
    audit_provenance,
    build_inventory,
    check_report,
    descriptor_inventory,
    render_report,
)


ROOT = Path(__file__).resolve().parent.parent
RPC = "heddle.api.v1alpha1.RepositoryService/GetCompare"
PLANNED_RPC = "heddle.api.v1alpha1.AgentService/GetAgentRun"
PUBLIC_RPC = "heddle.api.v1alpha1.IdentityService/BeginWebAuthnAuthentication"
ID_SCOPED_RPCS = tuple(
    f"heddle.api.v1alpha1.WorkflowService/{method}"
    for method in (
        "AddApprovalGroupMember",
        "AddPolicyGroupRequirement",
        "DeleteApprovalGroup",
        "DeleteThreadPolicy",
        "RemoveApprovalGroupMember",
        "RemovePolicyGroupRequirement",
        "RevokeApproval",
    )
)
EVENTS_RPC = "heddle.api.v1alpha1.RepositoryService/SubscribeRepoEvents"
STREAMING_RPC = "heddle.api.v1alpha1.RepoSyncService/Pull"
CREDENTIAL_READ_CONTRACTS = {
    "heddle.api.v1alpha1.IdentityService/IntrospectCredential": (
        "AUTHENTICATED_PRINCIPAL",
        "CALLER_BOUND",
        "REQUEST_RESOURCE",
        "HIDE",
    ),
    "heddle.api.v1alpha1.IdentityService/ListServiceAccounts": (
        "AUTHENTICATED_PRINCIPAL",
        "RESOURCE_ADMINISTRATOR",
        "CALLER_GRANTS",
        "HIDE",
    ),
}
IDENTITY_CREDENTIAL_CONTRACTS = {
    "heddle.api.v1alpha1.IdentityService/CreateServiceAccount": (
        "AUTHENTICATED_PRINCIPAL",
        "RESOURCE_ADMINISTRATOR",
        "REQUEST_RESOURCE",
        "HIDE",
        (("scope", "RESOURCE_ADMINISTRATOR"),),
    ),
    "heddle.api.v1alpha1.IdentityService/IssueServiceAccountCredential": (
        "AUTHENTICATED_PRINCIPAL",
        "RESOURCE_ADMINISTRATOR",
        "REQUEST_RESOURCE",
        "DISCLOSE",
        (
            ("service_account_id", "RESOURCE_ADMINISTRATOR"),
            ("scope", "RESOURCE_ADMINISTRATOR"),
        ),
    ),
    "heddle.api.v1alpha1.IdentityService/IntrospectCredential": (
        "AUTHENTICATED_PRINCIPAL",
        "CALLER_BOUND",
        "REQUEST_RESOURCE",
        "HIDE",
        (("credential_id", "CALLER_BOUND"),),
    ),
    "heddle.api.v1alpha1.IdentityService/ListServiceAccounts": (
        "AUTHENTICATED_PRINCIPAL",
        "RESOURCE_ADMINISTRATOR",
        "CALLER_GRANTS",
        "HIDE",
        (),
    ),
    "heddle.api.v1alpha1.IdentityService/RevokeCredential": (
        "AUTHENTICATED_PRINCIPAL",
        "CALLER_OR_RESOURCE_ADMINISTRATOR",
        "REQUEST_RESOURCE",
        "DISCLOSE",
        (("credential_id", "CALLER_OR_RESOURCE_ADMINISTRATOR"),),
    ),
    "heddle.api.v1alpha1.IdentityService/RevokeServiceAccount": (
        "AUTHENTICATED_PRINCIPAL",
        "RESOURCE_ADMINISTRATOR",
        "REQUEST_RESOURCE",
        "DISCLOSE",
        (("service_account_id", "RESOURCE_ADMINISTRATOR"),),
    ),
    "heddle.api.v1alpha1.IdentityService/RotateCredential": (
        "AUTHENTICATED_PRINCIPAL",
        "CALLER_BOUND",
        "REQUEST_RESOURCE",
        "DISCLOSE",
        (("credential_id", "CALLER_BOUND"),),
    ),
}
REVIEW_ANALYSIS_CONTRACTS = {
    "heddle.api.v1alpha1.PullRequestReviewService/GetReviewAnalysisResult": (
        "PUBLIC",
        "CALLER_BOUND",
        "CALLER_SUBJECT",
        "HIDE",
    ),
    "heddle.api.v1alpha1.PullRequestReviewService/GetReviewAnalysisStatus": (
        "PUBLIC",
        "CALLER_BOUND",
        "CALLER_SUBJECT",
        "HIDE",
    ),
    "heddle.api.v1alpha1.PullRequestReviewService/StartReviewAnalysis": (
        "PUBLIC",
        "CALLER_BOUND",
        "CALLER_SUBJECT",
        "DISCLOSE",
    ),
}
REGISTRY_AUTHORIZATION_CONTRACTS = {
    "AttachChild": ("RESOURCE_WRITER", "REQUEST_RESOURCE", ("parent_path", "child_path")),
    "CreateGrant": ("RESOURCE_ADMINISTRATOR", "REQUEST_RESOURCE", ("target",)),
    "CreateInvitation": ("RESOURCE_ADMINISTRATOR", "REQUEST_RESOURCE", ("namespace_path",)),
    "CreateNamespace": ("RESOURCE_ADMINISTRATOR", "REQUEST_RESOURCE", ("parent_path",)),
    "CreateRepository": ("RESOURCE_MAINTAINER", "REQUEST_RESOURCE", ("namespace_path",)),
    "DeleteBookmark": ("CALLER_BOUND", "CALLER_SUBJECT", ()),
    "DeleteGrant": ("RESOURCE_ADMINISTRATOR", "REQUEST_RESOURCE", ("target",)),
    "DeleteNamespace": ("RESOURCE_OWNER", "REQUEST_RESOURCE", ("full_path",)),
    "DeleteRepository": ("RESOURCE_ADMINISTRATOR", "REQUEST_RESOURCE", ("full_path",)),
    "DetachChild": ("RESOURCE_WRITER", "REQUEST_RESOURCE", ("parent_path",)),
    "GetCurrentUserNamespace": ("CALLER_BOUND", "CALLER_SUBJECT", ()),
    "GetSpool": ("RESOURCE_READER", "REQUEST_RESOURCE", ("full_path",)),
    "GrantSupportAccess": ("RESOURCE_ADMINISTRATOR", "REQUEST_RESOURCE", ("target",)),
    "ListActors": ("GLOBAL_ADMINISTRATOR", "NONE", ()),
    "ListBookmarks": ("CALLER_BOUND", "CALLER_SUBJECT", ()),
    "ListChildren": ("RESOURCE_READER", "REQUEST_RESOURCE", ("parent_path",)),
    "ListGrants": ("RESOURCE_ADMINISTRATOR", "CALLER_GRANTS", ()),
    "ListInvitations": ("RESOURCE_READER", "REQUEST_RESOURCE", ("namespace_path",)),
    "ListMembers": ("RESOURCE_READER", "REQUEST_RESOURCE", ("namespace_path",)),
    "ListSpools": ("RESOURCE_READER", "CALLER_GRANTS", ()),
    "ListSupportAccessGrants": ("RESOURCE_ADMINISTRATOR", "REQUEST_RESOURCE", ("target",)),
    "ListWorktrees": ("GLOBAL_ADMINISTRATOR", "NONE", ()),
    "ResolveMonorepo": ("RESOURCE_READER", "REQUEST_RESOURCE", ("root_path",)),
    "ResolveSubjects": ("RESOURCE_READER", "CALLER_GRANTS", ()),
    "RevokeInvitation": ("RESOURCE_ADMINISTRATOR", "REQUEST_RESOURCE", ("id",)),
    "RevokeSupportAccess": ("RESOURCE_ADMINISTRATOR", "REQUEST_RESOURCE", ("id",)),
    "SetNamespaceVisibility": ("RESOURCE_ADMINISTRATOR", "REQUEST_RESOURCE", ("full_path",)),
    "SetSpoolVisibility": ("RESOURCE_ADMINISTRATOR", "REQUEST_RESOURCE", ("full_path",)),
    "UpdateGrant": ("RESOURCE_ADMINISTRATOR", "REQUEST_RESOURCE", ("target",)),
    "UpdateNamespace": ("RESOURCE_OWNER", "REQUEST_RESOURCE", ("full_path",)),
    "UpdateRepository": ("RESOURCE_MAINTAINER", "REQUEST_RESOURCE", ("full_path",)),
    "UpdateSpoolSettings": ("RESOURCE_ADMINISTRATOR", "REQUEST_RESOURCE", ("full_path",)),
    "UpsertBookmark": ("CALLER_BOUND", "CALLER_SUBJECT", ()),
}
DIRECTORY_READ_CONTRACTS = {
    "heddle.api.v1alpha1.IdentityService/GetHandleStatus": (
        "AUTHENTICATED_PRINCIPAL",
        "NONE",
        "NONE",
        "DISCLOSE",
    ),
    "heddle.api.v1alpha1.IdentityService/ResolveHandle": (
        "AUTHENTICATED_PRINCIPAL",
        "NONE",
        "NONE",
        "DISCLOSE",
    ),
    "heddle.api.v1alpha1.RegistryService/ResolveSubjects": (
        "AUTHENTICATED_PRINCIPAL",
        "RESOURCE_READER",
        "CALLER_GRANTS",
        "HIDE",
    ),
}
AUTHORIZATION_FIELDS = (
    "authorization_access",
    "authorization_role",
    "authorization_scope_source",
    "authorization_existence",
)


def replace_rpc_authorization(
    text: str,
    method: str,
    access: str,
    role: str,
    scope: str,
    existence: str,
) -> str:
    replacements = (
        ("authorization_access", "AUTHORIZATION_ACCESS", access),
        ("authorization_role", "AUTHORIZATION_ROLE", role),
        ("authorization_scope_source", "AUTHORIZATION_SCOPE_SOURCE", scope),
        ("authorization_existence", "AUTHORIZATION_EXISTENCE", existence),
    )
    for field, prefix, value in replacements:
        text, count = re.subn(
            rf"(rpc {method}\b.*?{field}:) {prefix}_[A-Z_]+",
            rf"\1 {prefix}_{value}",
            text,
            count=1,
            flags=re.DOTALL,
        )
        if count != 1:
            raise AssertionError(f"could not replace {method} {field}")
    if scope not in {"REQUEST_REPOSITORY", "REQUEST_NAMESPACE", "REQUEST_RESOURCE"}:
        text = re.sub(
            rf"(rpc {method}\b.*?authorization_scope_source: "
            rf"AUTHORIZATION_SCOPE_SOURCE_{scope}\n)"
            r'(?:\s+authorization_request_targets: \{\n'
            r'\s+path: "[^"]+"\n'
            r"\s+role: AUTHORIZATION_ROLE_[A-Z_]+\n"
            r"\s+\}\n)+",
            r"\1",
            text,
            count=1,
            flags=re.DOTALL,
        )
    return text


def inventory() -> dict[str, dict[str, object]]:
    common = {
        "service": "heddle.api.v1alpha1.RepositoryService",
        "capability": "state comparison",
        "deployment_targets": ["WEFT"],
        "signing_identity": "AUTHENTICATED_PRINCIPAL",
        "signing_tier": "NONE",
        "effect": "READ_ONLY",
        "retry_behavior": "SAFE",
        "client_operation_id_required": False,
        "authorization_access": "AUTHENTICATED_PRINCIPAL",
        "authorization_role": "RESOURCE_READER",
        "authorization_scope_source": "REQUEST_REPOSITORY",
        "authorization_existence": "HIDE",
        "authorization_request_targets": [
            {"path": "repo_path", "role": "RESOURCE_READER"}
        ],
        "authorization_multi_target": False,
    }
    return {
        RPC: {**common, "rpc": RPC, "method": "GetCompare", "maturity": "SHIPPED"},
        PLANNED_RPC: {
            **common,
            "rpc": PLANNED_RPC,
            "service": "heddle.api.v1alpha1.AgentService",
            "method": "GetAgentRun",
            "capability": "run history/details",
            "maturity": "PLANNED",
        },
    }


def row(rpc: str, status: str) -> dict[str, object]:
    return {
        "rpc": rpc,
        "layers": {"first": {"status": status}, "second": {"status": status}},
    }


def declarations() -> dict[str, dict[str, object]]:
    result = {
        name: {
            "schema_version": 2,
            "consumer": name,
            "rpc_mappings": [row(RPC, "shipped"), row(PLANNED_RPC, "planned")],
        }
        for name in ("heddle", "tapestry", "weft")
    }
    names = {
        "heddle": ("client", "cli"),
        "tapestry": ("server_adapter", "ui"),
        "weft": ("implementation", "registration"),
    }
    for consumer, layer_names in names.items():
        for mapping in result[consumer]["rpc_mappings"]:  # type: ignore[index]
            layers = mapping["layers"]  # type: ignore[index]
            mapping["layers"] = {  # type: ignore[index]
                layer_names[0]: layers["first"],  # type: ignore[index]
                layer_names[1]: layers["second"],  # type: ignore[index]
            }
    return result


class CapabilityMatrixAuditTests(unittest.TestCase):
    def build_descriptor(self, root: Path, output: Path) -> None:
        subprocess.run(
            ["buf", "build", "-o", str(output)],
            cwd=root,
            check=True,
            capture_output=True,
        )

    def assert_audit_fails(self, data: dict[str, dict[str, object]], match: str) -> None:
        with self.assertRaisesRegex(AuditError, match):
            audit_declarations(inventory(), data)

    def test_missing_descriptor_rpc_fails(self) -> None:
        data = declarations()
        data["heddle"]["rpc_mappings"].pop()  # type: ignore[index,union-attr]
        self.assert_audit_fails(data, "missing descriptor RPC")

    def test_nonexistent_declared_rpc_fails(self) -> None:
        data = declarations()
        missing = copy.deepcopy(data["tapestry"]["rpc_mappings"][0])  # type: ignore[index]
        missing["rpc"] = "heddle.api.v1alpha1.MissingService/NoSuchRpc"
        data["tapestry"]["rpc_mappings"].append(missing)  # type: ignore[index,union-attr]
        self.assert_audit_fails(data, "nonexistent RPC")

    def test_missing_weft_registration_status_fails(self) -> None:
        data = declarations()
        data["weft"]["rpc_mappings"][0]["layers"]["registration"]["status"] = "planned"  # type: ignore[index]
        self.assert_audit_fails(data, "lacks Weft registration")

    def test_partial_weft_implementation_is_explicitly_valid(self) -> None:
        data = declarations()
        data["weft"]["rpc_mappings"][0]["layers"]["implementation"]["status"] = "partial"  # type: ignore[index]
        audit_declarations(inventory(), data)

    def test_partial_weft_registration_is_explicitly_valid(self) -> None:
        data = declarations()
        data["weft"]["rpc_mappings"][0]["layers"]["registration"]["status"] = "partial"  # type: ignore[index]
        audit_declarations(inventory(), data)

    def test_private_evidence_field_fails_public_schema(self) -> None:
        data = declarations()
        data["weft"]["rpc_mappings"][0]["layers"]["implementation"]["evidence"] = [  # type: ignore[index]
            "private/path.rs:handler"
        ]
        self.assert_audit_fails(data, "invalid weft implementation layer")

    def test_consumer_capability_copy_fails(self) -> None:
        data = declarations()
        data["heddle"]["rpc_mappings"][0]["capability"] = "state comparison"  # type: ignore[index]
        self.assert_audit_fails(data, "invalid mapping row")

    def test_capability_is_owned_by_descriptor_not_consumers(self) -> None:
        audit_declarations(inventory(), declarations())

    def test_report_separates_signing_from_authorization(self) -> None:
        rendered = render_report(inventory(), audit_declarations(inventory(), declarations()))
        self.assertIn("| Signing contract | Authorization contract metadata |", rendered)
        self.assertIn("signing is not authorization", rendered)
        self.assertIn(
            "AUTHENTICATED_PRINCIPAL / RESOURCE_READER / "
            "REQUEST_REPOSITORY[repo_path:RESOURCE_READER] / HIDE",
            rendered,
        )

    def test_authorization_metadata_does_not_change_signing_metadata(self) -> None:
        baseline = inventory()
        changed = copy.deepcopy(baseline)
        changed[RPC]["authorization_role"] = "RESOURCE_WRITER"
        self.assertEqual(
            baseline[RPC]["signing_identity"], changed[RPC]["signing_identity"]
        )
        self.assertEqual(baseline[RPC]["signing_tier"], changed[RPC]["signing_tier"])

        changed = copy.deepcopy(baseline)
        changed[RPC]["signing_tier"] = "PROOF_OF_POSSESSION"
        self.assertEqual(
            baseline[RPC]["authorization_role"], changed[RPC]["authorization_role"]
        )

    def test_descriptor_keeps_signing_and_authorization_orthogonal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(ROOT / "proto", root / "proto")
            shutil.copy2(ROOT / "buf.yaml", root / "buf.yaml")
            source = root / "proto/heddle/api/v1alpha1/repository.proto"
            original = source.read_text()
            baseline_descriptor = root / "baseline.binpb"
            self.build_descriptor(root, baseline_descriptor)
            baseline = descriptor_inventory(baseline_descriptor)[RPC]

            role_changed, count = re.subn(
                r"(rpc GetCompare\b.*?authorization_role:) AUTHORIZATION_ROLE_RESOURCE_READER",
                r"\1 AUTHORIZATION_ROLE_RESOURCE_WRITER",
                original,
                count=1,
                flags=re.DOTALL,
            )
            self.assertEqual(count, 1)
            role_changed, count = re.subn(
                r"(rpc GetCompare\b.*?authorization_request_targets: \{.*?role:) "
                r"AUTHORIZATION_ROLE_RESOURCE_READER",
                r"\1 AUTHORIZATION_ROLE_RESOURCE_WRITER",
                role_changed,
                count=1,
                flags=re.DOTALL,
            )
            self.assertEqual(count, 1)
            source.write_text(role_changed)
            role_descriptor = root / "role.binpb"
            self.build_descriptor(root, role_descriptor)
            role_contract = descriptor_inventory(role_descriptor)[RPC]
            self.assertEqual(
                (baseline["signing_identity"], baseline["signing_tier"]),
                (role_contract["signing_identity"], role_contract["signing_tier"]),
            )

            signing_changed, count = re.subn(
                r"(rpc GetCompare\b.*?signing_tier:) SIGNING_TIER_NONE",
                r"\1 SIGNING_TIER_PROOF_OF_POSSESSION",
                original,
                count=1,
                flags=re.DOTALL,
            )
            self.assertEqual(count, 1)
            source.write_text(signing_changed)
            signing_descriptor = root / "signing.binpb"
            self.build_descriptor(root, signing_descriptor)
            signing_contract = descriptor_inventory(signing_descriptor)[RPC]
            self.assertEqual(
                (
                    baseline["authorization_access"],
                    baseline["authorization_role"],
                    baseline["authorization_scope_source"],
                    baseline["authorization_existence"],
                ),
                (
                    signing_contract["authorization_access"],
                    signing_contract["authorization_role"],
                    signing_contract["authorization_scope_source"],
                    signing_contract["authorization_existence"],
                ),
            )

    def test_every_authorization_contract_is_explicit(self) -> None:
        actual = build_inventory()
        shipped = [row for row in actual.values() if row["maturity"] == "SHIPPED"]
        planned = [row for row in actual.values() if row["maturity"] == "PLANNED"]
        self.assertEqual(len(shipped), 138)
        self.assertEqual(len(planned), 12)
        authorization_fields = (
            "authorization_access",
            "authorization_role",
            "authorization_scope_source",
            "authorization_existence",
        )
        for contract in shipped:
            self.assertNotIn(
                "UNSPECIFIED", [contract[field] for field in authorization_fields]
            )
        for contract in planned:
            self.assertEqual(
                [contract[field] for field in authorization_fields],
                ["PLANNED_UNDECIDED"] * len(authorization_fields),
            )
            self.assertEqual(contract["authorization_request_targets"], [])
            self.assertFalse(contract["authorization_multi_target"])

    def test_planned_rpc_cannot_fall_back_to_unspecified_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(ROOT / "proto", root / "proto")
            shutil.copy2(ROOT / "buf.yaml", root / "buf.yaml")
            source = root / "proto/heddle/api/v1alpha1/agent.proto"
            changed, count = re.subn(
                r"\n\s+authorization_access: AUTHORIZATION_ACCESS_PLANNED_UNDECIDED",
                "",
                source.read_text(),
                count=1,
            )
            self.assertEqual(count, 1)
            source.write_text(changed)
            descriptor = root / "planned-unspecified.binpb"
            self.build_descriptor(root, descriptor)
            with self.assertRaisesRegex(
                AuditError,
                "missing authorization access/role/scope/existence",
            ):
                descriptor_inventory(descriptor)

    def test_report_detects_descriptor_metadata_drift(self) -> None:
        checked = render_report(inventory(), audit_declarations(inventory(), declarations()))
        changed = inventory()
        changed[RPC]["signing_tier"] = "PROOF_OF_POSSESSION"
        regenerated = render_report(changed, audit_declarations(changed, declarations()))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.md"
            path.write_text(checked)
            with self.assertRaisesRegex(AuditError, "generated report drift"):
                check_report(path, regenerated)

    def test_descriptor_inventory_ignores_formatting_and_comments(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(ROOT / "proto", root / "proto")
            shutil.copy2(ROOT / "buf.yaml", root / "buf.yaml")
            baseline = root / "baseline.binpb"
            formatted = root / "formatted.binpb"
            self.build_descriptor(root, baseline)

            source = root / "proto/heddle/api/v1alpha1/repository.proto"
            source.write_text(
                "// Formatting and comments are not contract metadata.\n\n"
                + source.read_text().replace(
                    "service RepositoryService {",
                    "service RepositoryService /* descriptor traversal */ {",
                )
            )
            subprocess.run(["buf", "format", "-w"], cwd=root, check=True)
            self.build_descriptor(root, formatted)

            self.assertEqual(
                descriptor_inventory(baseline), descriptor_inventory(formatted)
            )

    def test_descriptor_inventory_fails_closed_when_capability_option_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(ROOT / "proto", root / "proto")
            shutil.copy2(ROOT / "buf.yaml", root / "buf.yaml")
            source = root / "proto/heddle/api/v1alpha1/repository.proto"
            text = source.read_text()
            changed, count = re.subn(
                r"\n\s+capability: CAPABILITY_AREA_[A-Z_]+",
                "",
                text,
                count=1,
            )
            self.assertEqual(count, 1)
            source.write_text(changed)
            descriptor = root / "missing.binpb"
            self.build_descriptor(root, descriptor)
            with self.assertRaisesRegex(AuditError, "capability"):
                descriptor_inventory(descriptor)

    def test_descriptor_inventory_fails_closed_when_shipped_authorization_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(ROOT / "proto", root / "proto")
            shutil.copy2(ROOT / "buf.yaml", root / "buf.yaml")
            source = root / "proto/heddle/api/v1alpha1/repository.proto"
            text = source.read_text()
            changed, count = re.subn(
                r"\n\s+authorization_access: AUTHORIZATION_ACCESS_[A-Z_]+",
                "",
                text,
                count=1,
            )
            self.assertEqual(count, 1)
            source.write_text(changed)
            descriptor = root / "missing-authz.binpb"
            self.build_descriptor(root, descriptor)
            with self.assertRaisesRegex(AuditError, "authorization access"):
                descriptor_inventory(descriptor)

    def test_descriptor_inventory_rejects_invalid_authorization_combination(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(ROOT / "proto", root / "proto")
            shutil.copy2(ROOT / "buf.yaml", root / "buf.yaml")
            source = root / "proto/heddle/api/v1alpha1/repository.proto"
            text = source.read_text()
            changed, count = re.subn(
                r"authorization_role: AUTHORIZATION_ROLE_RESOURCE_READER",
                "authorization_role: AUTHORIZATION_ROLE_NONE",
                text,
                count=1,
            )
            self.assertEqual(count, 1)
            source.write_text(changed)
            descriptor = root / "invalid-authz.binpb"
            self.build_descriptor(root, descriptor)
            with self.assertRaisesRegex(AuditError, "invalid authorization combination"):
                descriptor_inventory(descriptor)

    def test_public_access_roles_are_allowlisted_and_future_roles_fail_closed(self) -> None:
        contract = (ROOT / "proto/heddle/api/v1alpha1/contract.proto").read_text()
        roles = re.findall(r"AUTHORIZATION_ROLE_([A-Z_]+)\s*=", contract)
        allowed = {"NONE", "CALLER_BOUND"}

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(ROOT / "proto", root / "proto")
            shutil.copy2(ROOT / "buf.yaml", root / "buf.yaml")
            source = root / "proto/heddle/api/v1alpha1/identity.proto"
            original = source.read_text()

            for role in roles:
                with self.subTest(role=role):
                    changed, count = re.subn(
                        r"(rpc BeginWebAuthnAuthentication\b.*?authorization_role:) "
                        r"AUTHORIZATION_ROLE_[A-Z_]+",
                        rf"\1 AUTHORIZATION_ROLE_{role}",
                        original,
                        count=1,
                        flags=re.DOTALL,
                    )
                    self.assertEqual(count, 1)
                    scope = (
                        "REQUEST_RESOURCE"
                        if role not in {"NONE", "GLOBAL_ADMINISTRATOR", "UNSPECIFIED"}
                        else "NONE"
                    )
                    changed, count = re.subn(
                        r"(rpc BeginWebAuthnAuthentication\b.*?authorization_scope_source:) "
                        r"AUTHORIZATION_SCOPE_SOURCE_[A-Z_]+",
                        rf"\1 AUTHORIZATION_SCOPE_SOURCE_{scope}",
                        changed,
                        count=1,
                        flags=re.DOTALL,
                    )
                    self.assertEqual(count, 1)
                    if scope == "REQUEST_RESOURCE":
                        changed, count = re.subn(
                            r"(rpc BeginWebAuthnAuthentication\b.*?"
                            r"authorization_scope_source: "
                            r"AUTHORIZATION_SCOPE_SOURCE_REQUEST_RESOURCE\n)",
                            r"\1      authorization_request_targets: {\n"
                            r'        path: "username"\n'
                            r"        role: AUTHORIZATION_ROLE_CALLER_BOUND\n"
                            r"      }\n",
                            changed,
                            count=1,
                            flags=re.DOTALL,
                        )
                        self.assertEqual(count, 1)
                    source.write_text(changed)
                    descriptor = root / f"public-{role.lower()}.binpb"
                    self.build_descriptor(root, descriptor)

                    if role in allowed:
                        self.assertEqual(
                            descriptor_inventory(descriptor)[PUBLIC_RPC][
                                "authorization_role"
                            ],
                            role,
                        )
                    else:
                        with self.assertRaisesRegex(
                            AuditError,
                            "authorization access/role/scope/existence|"
                            "invalid authorization combination|"
                            "invalid planned-undecided authorization contract",
                        ):
                            descriptor_inventory(descriptor)

    def test_request_scope_paths_are_validated_against_input_descriptors(self) -> None:
        cases = (
            (
                "repository.proto",
                r'(rpc GetCompare\b.*?path:) "repo_path"',
                r'\1 "missing.path"',
                "does not exist",
            ),
            (
                "attention.proto",
                r'(rpc UpdateFeedItem\b.*?path:) "item_id"',
                r'\1 "item_id.value"',
                "traverses non-message field",
            ),
            (
                "repository.proto",
                r'(rpc GetDiff\b.*?path:) "repo_path"',
                r'\1 "id"',
                "must target RepositoryRef fields",
            ),
            (
                "registry.proto",
                r'(rpc CreateInvitation\b.*?authorization_scope_source:) '
                r'AUTHORIZATION_SCOPE_SOURCE_REQUEST_RESOURCE'
                r'(.*?path:) "namespace_path"',
                r'\g<1> AUTHORIZATION_SCOPE_SOURCE_REQUEST_NAMESPACE'
                r'\g<2> "expires_at"',
                "must target string fields",
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(ROOT / "proto", root / "proto")
            shutil.copy2(ROOT / "buf.yaml", root / "buf.yaml")

            for filename, pattern, replacement, error in cases:
                with self.subTest(filename=filename, error=error):
                    source = root / "proto/heddle/api/v1alpha1" / filename
                    original = (ROOT / "proto/heddle/api/v1alpha1" / filename).read_text()
                    changed, count = re.subn(
                        pattern,
                        replacement,
                        original,
                        count=1,
                        flags=re.DOTALL,
                    )
                    self.assertEqual(count, 1)
                    source.write_text(changed)
                    descriptor = root / "invalid-request-path.binpb"
                    self.build_descriptor(root, descriptor)
                    with self.assertRaisesRegex(
                        AuditError,
                        error,
                    ):
                        descriptor_inventory(descriptor)
                    source.write_text(original)

    def test_request_scope_paths_are_required_and_unique(self) -> None:
        cases = (
            (
                r'\n\s+authorization_request_targets: \{\n'
                r'\s+path: "repo_path"\n'
                r"\s+role: AUTHORIZATION_ROLE_RESOURCE_READER\n"
                r"\s+\}",
                "",
                "authorization request targets missing",
            ),
            (
                r'(rpc GetCompare\b.*?authorization_request_targets: \{\n'
                r'\s+path: "repo_path"\n'
                r"\s+role: AUTHORIZATION_ROLE_RESOURCE_READER\n"
                r"\s+\}\n)",
                r"\1      authorization_request_targets: {\n"
                r'        path: "repo_path"\n'
                r"        role: AUTHORIZATION_ROLE_RESOURCE_READER\n"
                r"      }\n",
                "duplicate authorization request path",
            ),
            (
                r'(rpc GetCompare\b.*?authorization_scope_source:) '
                r'AUTHORIZATION_SCOPE_SOURCE_REQUEST_REPOSITORY',
                r'\1 AUTHORIZATION_SCOPE_SOURCE_CALLER_GRANTS',
                "request targets require a request-derived scope source",
            ),
            (
                r'(rpc GetCompare\b.*?authorization_request_targets: \{.*?role:) '
                r'AUTHORIZATION_ROLE_RESOURCE_READER',
                r'\1 AUTHORIZATION_ROLE_RESOURCE_WRITER',
                "invalid authorization request target role",
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(ROOT / "proto", root / "proto")
            shutil.copy2(ROOT / "buf.yaml", root / "buf.yaml")
            source = root / "proto/heddle/api/v1alpha1/repository.proto"
            original = source.read_text()
            for pattern, replacement, error in cases:
                with self.subTest(error=error):
                    changed, count = re.subn(
                        pattern,
                        replacement,
                        original,
                        count=1,
                        flags=re.DOTALL,
                    )
                    self.assertEqual(count, 1)
                    source.write_text(changed)
                    descriptor = root / "invalid-request-paths.binpb"
                    self.build_descriptor(root, descriptor)
                    with self.assertRaisesRegex(AuditError, error):
                        descriptor_inventory(descriptor)
                    source.write_text(original)

    def test_multi_resource_rule_cannot_collapse_to_one_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(ROOT / "proto", root / "proto")
            shutil.copy2(ROOT / "buf.yaml", root / "buf.yaml")
            source = root / "proto/heddle/api/v1alpha1/registry.proto"
            changed, count = re.subn(
                r'\n\s+authorization_request_targets: \{\n'
                r'\s+path: "child_path"\n'
                r"\s+role: AUTHORIZATION_ROLE_RESOURCE_READER\n"
                r"\s+\}",
                "",
                source.read_text(),
                count=1,
            )
            self.assertEqual(count, 1)
            source.write_text(changed)
            descriptor = root / "collapsed-attach-child.binpb"
            self.build_descriptor(root, descriptor)
            with self.assertRaisesRegex(
                AuditError,
                "authorization multi-target declaration mismatch",
            ):
                descriptor_inventory(descriptor)

    def test_shipped_scope_sources_match_request_shapes(self) -> None:
        actual = build_inventory()
        for rpc in ID_SCOPED_RPCS:
            with self.subTest(rpc=rpc):
                self.assertEqual(
                    actual[rpc]["authorization_scope_source"],
                    "REQUEST_RESOURCE",
                )
        self.assertEqual(
            actual[EVENTS_RPC]["authorization_scope_source"],
            "REQUEST_RESOURCE",
        )
        self.assertEqual(
            actual[STREAMING_RPC]["authorization_scope_source"],
            "REQUEST_REPOSITORY",
        )
        self.assertEqual(
            actual["heddle.api.v1alpha1.RegistryService/AttachChild"][
                "authorization_request_targets"
            ],
            [
                {"path": "parent_path", "role": "RESOURCE_WRITER"},
                {"path": "child_path", "role": "RESOURCE_READER"},
            ],
        )
        self.assertEqual(
            actual[STREAMING_RPC]["authorization_request_targets"],
            [
                {"path": "open.repository", "role": "RESOURCE_READER"},
                {"path": "request.repo_path", "role": "RESOURCE_READER"},
            ],
        )

    def test_sensitive_read_classes_have_grounded_authorization(self) -> None:
        actual = build_inventory()
        for rpc, expected in {
            **CREDENTIAL_READ_CONTRACTS,
            **DIRECTORY_READ_CONTRACTS,
        }.items():
            with self.subTest(rpc=rpc):
                self.assertEqual(
                    tuple(actual[rpc][field] for field in AUTHORIZATION_FIELDS),
                    expected,
                )

    def test_identity_credential_and_service_account_class_matches_weft_guards(self) -> None:
        actual = build_inventory()
        for rpc, (*authorization, paths) in IDENTITY_CREDENTIAL_CONTRACTS.items():
            with self.subTest(rpc=rpc):
                self.assertEqual(
                    tuple(actual[rpc][field] for field in AUTHORIZATION_FIELDS),
                    tuple(authorization),
                )
                self.assertEqual(
                    tuple(
                        (target["path"], target["role"])
                        for target in actual[rpc]["authorization_request_targets"]
                    ),
                    tuple(paths),
                )

    def test_review_analysis_work_selectors_are_not_authorization_targets(self) -> None:
        actual = build_inventory()
        for rpc, expected in REVIEW_ANALYSIS_CONTRACTS.items():
            with self.subTest(rpc=rpc):
                self.assertEqual(
                    tuple(actual[rpc][field] for field in AUTHORIZATION_FIELDS),
                    expected,
                )
                self.assertEqual(actual[rpc]["authorization_request_targets"], [])
                self.assertFalse(actual[rpc]["authorization_multi_target"])

    def test_registry_authorization_role_table_matches_weft_guards(self) -> None:
        actual = build_inventory()
        prefix = "heddle.api.v1alpha1.RegistryService/"
        registry = {
            rpc.removeprefix(prefix): contract
            for rpc, contract in actual.items()
            if rpc.startswith(prefix)
        }
        self.assertEqual(set(registry), set(REGISTRY_AUTHORIZATION_CONTRACTS))
        for method, (role, scope, paths) in REGISTRY_AUTHORIZATION_CONTRACTS.items():
            with self.subTest(method=method):
                contract = registry[method]
                self.assertEqual(contract["authorization_role"], role)
                self.assertEqual(contract["authorization_scope_source"], scope)
                self.assertEqual(
                    tuple(
                        target["path"]
                        for target in contract["authorization_request_targets"]
                    ),
                    paths,
                )

    def test_credential_information_responses_fail_closed_as_a_class(self) -> None:
        methods = ("IntrospectCredential", "ListServiceAccounts")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(ROOT / "proto", root / "proto")
            shutil.copy2(ROOT / "buf.yaml", root / "buf.yaml")
            source = root / "proto/heddle/api/v1alpha1/identity.proto"
            original = source.read_text()

            for method in methods:
                with self.subTest(method=method):
                    source.write_text(
                        replace_rpc_authorization(
                            original,
                            method,
                            "AUTHENTICATED_PRINCIPAL",
                            "NONE",
                            "NONE",
                            "DISCLOSE",
                        )
                    )
                    descriptor = root / f"unsafe-{method}.binpb"
                    self.build_descriptor(root, descriptor)
                    with self.assertRaisesRegex(
                        AuditError,
                        "credential information requires scoped, existence-hiding authorization",
                    ):
                        descriptor_inventory(descriptor)

    def test_directory_responses_fail_closed_as_a_class(self) -> None:
        cases = (
            ("identity.proto", "GetHandleStatus", "handle directory"),
            ("identity.proto", "ResolveHandle", "handle directory"),
            ("registry.proto", "ResolveSubjects", "subject directory"),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(ROOT / "proto", root / "proto")
            shutil.copy2(ROOT / "buf.yaml", root / "buf.yaml")

            for filename, method, error in cases:
                with self.subTest(method=method):
                    source = root / "proto/heddle/api/v1alpha1" / filename
                    original = (ROOT / "proto/heddle/api/v1alpha1" / filename).read_text()
                    source.write_text(
                        replace_rpc_authorization(
                            original,
                            method,
                            "PUBLIC",
                            "NONE",
                            "NONE",
                            "DISCLOSE",
                        )
                    )
                    descriptor = root / f"public-{method}.binpb"
                    self.build_descriptor(root, descriptor)
                    with self.assertRaisesRegex(AuditError, error):
                        descriptor_inventory(descriptor)
                    source.write_text(original)

    def test_descriptor_inventory_rejects_unknown_authorization_enum_value(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(ROOT / "proto", root / "proto")
            shutil.copy2(ROOT / "buf.yaml", root / "buf.yaml")
            source = root / "proto/heddle/api/v1alpha1/repository.proto"
            text = source.read_text()
            changed, count = re.subn(
                r"authorization_role: AUTHORIZATION_ROLE_RESOURCE_READER",
                "authorization_role: 99",
                text,
                count=1,
            )
            self.assertEqual(count, 1)
            source.write_text(changed)
            descriptor = root / "unknown-authz.binpb"
            self.build_descriptor(root, descriptor)
            with self.assertRaisesRegex(AuditError, "unknown authorization role"):
                descriptor_inventory(descriptor)

    def test_descriptor_inventory_fails_closed_when_rpc_contract_schema_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(ROOT / "proto", root / "proto")
            shutil.copy2(ROOT / "buf.yaml", root / "buf.yaml")
            source = root / "proto/heddle/api/v1alpha1/contract.proto"
            text = source.read_text()
            changed, count = re.subn(
                r"(\n  bool authorization_multi_target = 12;)",
                r"\1\n  string required_permission = 13;",
                text,
                count=1,
            )
            self.assertEqual(count, 1)
            source.write_text(changed)
            descriptor = root / "changed.binpb"
            self.build_descriptor(root, descriptor)
            with self.assertRaisesRegex(AuditError, "RpcContract schema changed"):
                descriptor_inventory(descriptor)

    def test_public_attestation_detects_content_drift_and_has_no_revision(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            attestations: dict[str, object] = {}
            for consumer in ("heddle", "tapestry", "weft"):
                content = json.dumps(declarations()[consumer], sort_keys=True).encode()
                (root / f"{consumer}.json").write_bytes(content)
                attestations[consumer] = {
                    "kind": "consumer-derived-sanitized-declaration",
                    "snapshot": f"capabilities/declarations/{consumer}.json",
                    "sha256": hashlib.sha256(content).hexdigest(),
                }
            manifest = root / "sources.json"
            manifest.write_text(json.dumps({"schema_version": 2, "attestations": attestations}))
            audit_provenance(root, manifest)
            manifest_data = json.loads(manifest.read_text())
            manifest_data["attestations"]["weft"]["revision"] = "a" * 40
            manifest.write_text(json.dumps(manifest_data))
            with self.assertRaisesRegex(AuditError, "public attestation mismatch"):
                audit_provenance(root, manifest)

    def test_checked_in_public_artifacts_do_not_leak_private_details(self) -> None:
        files = [
            *sorted((ROOT / "capabilities/declarations").glob("*.json")),
            ROOT / "capabilities/sources.json",
            ROOT / "capabilities/MATRIX.md",
        ]
        text = "\n".join(path.read_text() for path in files)
        for forbidden in (
            '"capability"',
            '"evidence"',
            '"follow_up"',
            '"revision"',
            "HeddleCo/weft/issues/",
            "HeddleCo/tapestry/issues/",
            "crates/weft-server/",
            "src/routes/",
        ):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
