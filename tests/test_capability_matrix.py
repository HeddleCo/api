#!/usr/bin/env python3
"""Failure-mode tests for the public descriptor-derived capability matrix."""

from __future__ import annotations

import copy
import hashlib
import json
import re
import tempfile
import unittest
from pathlib import Path

from tools.capability_matrix import (
    AuditError,
    audit_authorization_metadata_absence,
    audit_declarations,
    audit_provenance,
    check_report,
    render_report,
)


ROOT = Path(__file__).resolve().parent.parent
RPC = "heddle.api.v1alpha1.RepositoryService/GetCompare"
PLANNED_RPC = "heddle.api.v1alpha1.AgentService/GetAgentRun"


def inventory() -> dict[str, dict[str, object]]:
    common = {
        "service": "heddle.api.v1alpha1.RepositoryService",
        "deployment_targets": ["WEFT"],
        "signing_identity": "AUTHENTICATED_PRINCIPAL",
        "signing_tier": "NONE",
        "effect": "READ_ONLY",
        "retry_behavior": "SAFE",
        "client_operation_id_required": False,
    }
    return {
        RPC: {**common, "rpc": RPC, "method": "GetCompare", "maturity": "SHIPPED"},
        PLANNED_RPC: {
            **common,
            "rpc": PLANNED_RPC,
            "service": "heddle.api.v1alpha1.AgentService",
            "method": "GetAgentRun",
            "maturity": "PLANNED",
        },
    }


def row(rpc: str, status: str) -> dict[str, object]:
    return {
        "rpc": rpc,
        "capability": "state comparison" if rpc == RPC else "run history/details",
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

    def test_private_evidence_field_fails_public_schema(self) -> None:
        data = declarations()
        data["weft"]["rpc_mappings"][0]["layers"]["implementation"]["evidence"] = [  # type: ignore[index]
            "private/path.rs:handler"
        ]
        self.assert_audit_fails(data, "invalid weft implementation layer")

    def test_capability_mismatch_fails(self) -> None:
        data = declarations()
        data["heddle"]["rpc_mappings"][0]["capability"] = "different"  # type: ignore[index]
        self.assert_audit_fails(data, "capability mismatch")

    def test_report_separates_signing_from_unavailable_authorization(self) -> None:
        rendered = render_report(inventory(), audit_declarations(inventory(), declarations()))
        self.assertIn("| Signing contract | Authorization contract metadata |", rendered)
        self.assertIn("signing is not authorization", rendered)
        self.assertIn("unavailable (no descriptor authorization role/scope option)", rendered)

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

    def test_authorization_unavailable_claim_is_tied_to_option_absence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            contract = Path(directory) / "contract.proto"
            contract.write_text("message RpcContract {\n  string authorization_scope = 1;\n}\n")
            with self.assertRaisesRegex(AuditError, "metadata now exists"):
                audit_authorization_metadata_absence(contract)

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
