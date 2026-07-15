#!/usr/bin/env python3
"""Failure-mode tests for the descriptor-derived capability matrix."""

from __future__ import annotations

import json
import copy
import hashlib
import tempfile
import unittest
from pathlib import Path

from tools.capability_matrix import (
    AuditError,
    audit_declarations,
    audit_provenance,
    check_report,
    render_report,
)


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
    layer = {"status": status, "evidence": ["path/to/source.rs:handler"], "follow_up": None}
    result: dict[str, object] = {
        "rpc": rpc,
        "capability": "state comparison" if rpc == RPC else "run history/details",
        "layers": {"first": dict(layer), "second": dict(layer)},
    }
    result.update(extra)
    return result


def declarations() -> dict[str, dict[str, object]]:
    return with_layer_names({
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
                row(RPC, "shipped"),
                row(PLANNED_RPC, "planned"),
            ],
        },
    })


def with_layer_names(data: dict[str, dict[str, object]]) -> dict[str, dict[str, object]]:
    names = {
        "heddle": ("client", "cli"),
        "tapestry": ("server_adapter", "ui"),
        "weft": ("implementation", "registration"),
    }
    for consumer, layer_names in names.items():
        for mapping in data[consumer]["rpc_mappings"]:  # type: ignore[index,union-attr]
            layers = mapping["layers"]
            mapping["layers"] = {
                layer_names[0]: layers["first"],
                layer_names[1]: layers["second"],
            }
    return data


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

    def test_missing_weft_registration_on_shipped_rpc_fails(self) -> None:
        data = declarations()
        data["weft"]["rpc_mappings"][0]["layers"]["registration"]["evidence"] = []  # type: ignore[index,union-attr]
        self.assert_audit_fails(data, "missing Weft registration")

    def test_duplicate_mapping_fails(self) -> None:
        data = declarations()
        data["heddle"]["rpc_mappings"].append(  # type: ignore[index,union-attr]
            copy.deepcopy(data["heddle"]["rpc_mappings"][0])  # type: ignore[index]
        )
        self.assert_audit_fails(data, "duplicate mapping")

    def test_blank_status_fails(self) -> None:
        data = declarations()
        data["heddle"]["rpc_mappings"][0]["layers"]["client"]["status"] = ""  # type: ignore[index,union-attr]
        self.assert_audit_fails(data, "blank status")

    def test_capability_mismatch_fails(self) -> None:
        data = declarations()
        data["heddle"]["rpc_mappings"][0]["capability"] = "different"  # type: ignore[index,union-attr]
        self.assert_audit_fails(data, "capability mismatch")

    def test_generated_report_detects_metadata_drift(self) -> None:
        checked = render_report(inventory(), audit_declarations(inventory(), declarations()))
        changed = inventory()
        changed[RPC]["signing_tier"] = "PROOF_OF_POSSESSION"
        regenerated = render_report(changed, audit_declarations(changed, declarations()))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.md"
            path.write_text(checked)
            with self.assertRaisesRegex(AuditError, "generated report drift"):
                check_report(path, regenerated)

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

    def test_consumer_snapshot_provenance_detects_content_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources: dict[str, object] = {"schema_version": 1, "sources": {}}
            for consumer in ("heddle", "tapestry", "weft"):
                content = json.dumps(declarations()[consumer], sort_keys=True).encode()
                (root / f"{consumer}.json").write_bytes(content)
                sources["sources"][consumer] = {  # type: ignore[index]
                    "repository": f"HeddleCo/{consumer}",
                    "revision": "a" * 40,
                    "path": f"api-capabilities/{consumer}.json",
                    "sha256": hashlib.sha256(content).hexdigest(),
                }
            manifest = root / "sources.json"
            manifest.write_text(json.dumps(sources))
            audit_provenance(root, manifest)
            (root / "heddle.json").write_text("{}")
            with self.assertRaisesRegex(AuditError, "content hash mismatch"):
                audit_provenance(root, manifest)


if __name__ == "__main__":
    unittest.main()
