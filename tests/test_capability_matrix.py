#!/usr/bin/env python3
"""Failure-mode tests for the descriptor-derived capability matrix."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.capability_matrix import AuditError, audit_declarations, render_report


RPC = "heddle.api.v1alpha1.RepositoryService/GetCompare"
PLANNED_RPC = "heddle.api.v1alpha1.AgentService/GetAgentRun"


def inventory() -> dict[str, dict[str, object]]:
    return {
        RPC: {
            "rpc": RPC,
            "service": "heddle.api.v1alpha1.RepositoryService",
            "method": "GetCompare",
            "deployment_targets": ["WEFT"],
            "maturity": "SHIPPED",
            "signing_identity": "NONE",
            "signing_tier": "NONE",
            "effect": "READ_ONLY",
            "retry_behavior": "SAFE",
            "client_operation_id_required": False,
        },
        PLANNED_RPC: {
            "rpc": PLANNED_RPC,
            "service": "heddle.api.v1alpha1.AgentService",
            "method": "GetAgentRun",
            "deployment_targets": ["WEFT"],
            "maturity": "PLANNED",
            "signing_identity": "NONE",
            "signing_tier": "NONE",
            "effect": "READ_ONLY",
            "retry_behavior": "SAFE",
            "client_operation_id_required": False,
        },
    }


def row(rpc: str, status: str, **extra: object) -> dict[str, object]:
    result: dict[str, object] = {
        "rpc": rpc,
        "capability": "state comparison" if rpc == RPC else "run history/details",
        "status": status,
        "evidence": ["path/to/source.rs:handler"],
        "follow_up": None,
    }
    result.update(extra)
    return result


def declarations() -> dict[str, dict[str, object]]:
    return {
        "heddle": {
            "schema_version": 1,
            "consumer": "heddle",
            "source_repository": "HeddleCo/heddle",
            "rpc_mappings": [row(RPC, "unsupported"), row(PLANNED_RPC, "planned")],
        },
        "tapestry": {
            "schema_version": 1,
            "consumer": "tapestry",
            "source_repository": "HeddleCo/tapestry",
            "rpc_mappings": [row(RPC, "shipped"), row(PLANNED_RPC, "planned")],
        },
        "weft": {
            "schema_version": 1,
            "consumer": "weft",
            "source_repository": "HeddleCo/weft",
            "rpc_mappings": [
                row(
                    RPC,
                    "shipped",
                    implementation="crates/weft-server/src/server/grpc_hosted_impl/content.rs:get_compare",
                    registration="crates/weft-server/src/serve.rs:ContentServiceServer",
                ),
                row(PLANNED_RPC, "planned"),
            ],
        },
    }


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
        data["tapestry"]["rpc_mappings"].append(  # type: ignore[index,union-attr]
            row("heddle.api.v1alpha1.MissingService/NoSuchRpc", "planned")
        )
        self.assert_audit_fails(data, "nonexistent RPC")

    def test_missing_weft_registration_on_shipped_rpc_fails(self) -> None:
        data = declarations()
        data["weft"]["rpc_mappings"][0]["registration"] = ""  # type: ignore[index,union-attr]
        self.assert_audit_fails(data, "missing Weft registration")

    def test_duplicate_mapping_fails(self) -> None:
        data = declarations()
        data["heddle"]["rpc_mappings"].append(row(RPC, "unsupported"))  # type: ignore[index,union-attr]
        self.assert_audit_fails(data, "duplicate mapping")

    def test_blank_status_fails(self) -> None:
        data = declarations()
        data["heddle"]["rpc_mappings"][0]["status"] = ""  # type: ignore[index,union-attr]
        self.assert_audit_fails(data, "blank status")

    def test_generated_report_detects_metadata_drift(self) -> None:
        checked = render_report(inventory(), audit_declarations(inventory(), declarations()))
        changed = inventory()
        changed[RPC]["signing_tier"] = "PROOF_OF_POSSESSION"
        regenerated = render_report(changed, audit_declarations(changed, declarations()))
        self.assertNotEqual(checked, regenerated)

    def test_checked_in_report_is_exact_deterministic_output(self) -> None:
        audited = audit_declarations(inventory(), declarations())
        first = render_report(inventory(), audited)
        second = render_report(inventory(), audited)
        self.assertEqual(first, second)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.md"
            path.write_text(first)
            self.assertEqual(path.read_text(), second)

    def test_json_round_trip_does_not_change_report(self) -> None:
        data = json.loads(json.dumps(declarations(), sort_keys=True))
        self.assertEqual(
            render_report(inventory(), audit_declarations(inventory(), declarations())),
            render_report(inventory(), audit_declarations(inventory(), data)),
        )


if __name__ == "__main__":
    unittest.main()
