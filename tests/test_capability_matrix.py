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
    check_report,
    descriptor_inventory,
    render_report,
)


ROOT = Path(__file__).resolve().parent.parent
RPC = "heddle.api.v1alpha1.RepositoryService/GetCompare"
PLANNED_RPC = "heddle.api.v1alpha1.AgentService/GetAgentRun"


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
            "AUTHENTICATED_PRINCIPAL / RESOURCE_READER / REQUEST_REPOSITORY / HIDE",
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

    def test_descriptor_inventory_fails_closed_when_rpc_contract_schema_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(ROOT / "proto", root / "proto")
            shutil.copy2(ROOT / "buf.yaml", root / "buf.yaml")
            source = root / "proto/heddle/api/v1alpha1/contract.proto"
            text = source.read_text()
            changed, count = re.subn(
                r"(\n  CapabilityArea capability = 6;)",
                r"\1\n  string required_permission = 7;",
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
