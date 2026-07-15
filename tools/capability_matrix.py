#!/usr/bin/env python3
"""Generate and audit the descriptor-derived client capability matrix."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
CONSUMERS = ("heddle", "tapestry", "weft")
LAYERS = {
    "heddle": ("client", "cli"),
    "tapestry": ("server_adapter", "ui"),
    "weft": ("implementation", "registration"),
}
STATUSES = {
    "shipped",
    "partial",
    "planned",
    "intentionally-unsupported",
    "blocked",
}
AUTHORIZATION_METADATA = "unavailable (no descriptor authorization role/scope option)"


class AuditError(ValueError):
    """A declaration or generated artifact drifted from the descriptor."""


def _run(*args: str) -> bytes:
    return subprocess.run(args, cwd=ROOT, check=True, capture_output=True).stdout


def descriptor_inventory(descriptor: Path) -> dict[str, dict[str, object]]:
    """Read contract options directly from a compiled FileDescriptorSet."""
    try:
        rendered = _run(
            "node", str(ROOT / "tools/descriptor-inventory.mjs"), str(descriptor)
        )
    except subprocess.CalledProcessError as error:
        message = error.stderr.decode().strip() or "descriptor inventory failed"
        raise AuditError(message) from error
    return json.loads(rendered)


def load_declarations(directory: Path) -> dict[str, dict[str, object]]:
    declarations: dict[str, dict[str, object]] = {}
    for consumer in CONSUMERS:
        path = directory / f"{consumer}.json"
        if not path.is_file():
            raise AuditError(f"missing declaration: {path}")
        declarations[consumer] = json.loads(path.read_text())
    return declarations


def audit_provenance(directory: Path, manifest_path: Path) -> None:
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("schema_version") != 2 or set(manifest) != {
        "schema_version",
        "attestations",
    }:
        raise AuditError("unsupported provenance schema")
    sources = manifest.get("attestations")
    if not isinstance(sources, dict) or set(sources) != set(CONSUMERS):
        raise AuditError("provenance consumer set mismatch")
    for consumer in CONSUMERS:
        source = sources[consumer]
        expected = {
            "kind": "consumer-derived-sanitized-declaration",
            "snapshot": f"capabilities/declarations/{consumer}.json",
        }
        if not isinstance(source, dict) or set(source) != set(expected) | {"sha256"} or any(
            source.get(key) != value for key, value in expected.items()
        ):
            raise AuditError(f"public attestation mismatch for {consumer}")
        content_hash = source.get("sha256")
        actual = hashlib.sha256((directory / f"{consumer}.json").read_bytes()).hexdigest()
        if content_hash != actual:
            raise AuditError(f"attested content hash mismatch for {consumer}")


def audit_declarations(
    inventory: dict[str, dict[str, object]],
    declarations: dict[str, dict[str, object]],
) -> dict[str, dict[str, dict[str, object]]]:
    """Validate complete, explicit consumer rows against the descriptor inventory."""
    descriptor_rpcs = set(inventory)
    audited: dict[str, dict[str, dict[str, object]]] = {}
    for consumer in CONSUMERS:
        declaration = declarations.get(consumer)
        if not isinstance(declaration, dict):
            raise AuditError(f"missing declaration for {consumer}")
        if declaration.get("schema_version") != 2 or set(declaration) != {
            "schema_version",
            "consumer",
            "rpc_mappings",
        }:
            raise AuditError(f"unsupported declaration schema for {consumer}")
        if declaration.get("consumer") != consumer:
            raise AuditError(f"consumer name mismatch for {consumer}")
        rows = declaration.get("rpc_mappings")
        if not isinstance(rows, list):
            raise AuditError(f"rpc_mappings must be a list for {consumer}")
        by_rpc: dict[str, dict[str, object]] = {}
        for row in rows:
            if (
                not isinstance(row, dict)
                or set(row) != {"rpc", "layers"}
                or not isinstance(row.get("rpc"), str)
            ):
                raise AuditError(f"invalid mapping row for {consumer}")
            rpc = str(row["rpc"])
            if rpc in by_rpc:
                raise AuditError(f"duplicate mapping for {consumer}: {rpc}")
            if rpc not in descriptor_rpcs:
                raise AuditError(f"nonexistent RPC declared by {consumer}: {rpc}")
            layers = row.get("layers")
            if not isinstance(layers, dict) or set(layers) != set(LAYERS[consumer]):
                raise AuditError(f"layer set mismatch for {consumer}: {rpc}")
            for layer_name in LAYERS[consumer]:
                layer = layers[layer_name]
                if not isinstance(layer, dict) or set(layer) != {"status"}:
                    raise AuditError(f"invalid {consumer} {layer_name} layer: {rpc}")
                status = layer.get("status")
                if status == "" or status is None:
                    raise AuditError(f"blank status for {consumer} {layer_name}: {rpc}")
                if status not in STATUSES:
                    raise AuditError(
                        f"invalid status for {consumer} {layer_name}: {rpc}: {status}"
                    )
            by_rpc[rpc] = row
        missing = descriptor_rpcs - set(by_rpc)
        if missing:
            raise AuditError(
                f"missing descriptor RPC in {consumer}: {', '.join(sorted(missing))}"
            )
        audited[consumer] = by_rpc

    for rpc, contract in inventory.items():
        if contract["maturity"] != "SHIPPED" or "WEFT" not in contract[
            "deployment_targets"
        ]:
            continue
        layers = audited["weft"][rpc]["layers"]
        if layers["implementation"]["status"] not in {"shipped", "partial"}:
            raise AuditError(f"shipped descriptor RPC lacks Weft implementation: {rpc}")
        if layers["registration"]["status"] not in {"shipped", "partial"}:
            raise AuditError(f"shipped descriptor RPC lacks Weft registration: {rpc}")
    return audited


def _cell(layer: dict[str, object]) -> str:
    return str(layer["status"])


def render_report(
    inventory: dict[str, dict[str, object]],
    audited: dict[str, dict[str, dict[str, object]]],
) -> str:
    """Render a stable report; all contract metadata comes from the descriptor."""
    lines = [
        "# Generated capability, signing, and authorization-metadata parity matrix",
        "",
        "Generated by `tools/capability_matrix.py` from the compiled descriptor and the checked-in consumer declarations. Do not edit this report by hand.",
        "",
        f"Descriptor inventory: {len(inventory)} RPCs across {len({row['service'] for row in inventory.values()})} services.",
        "",
        "Status vocabulary: `shipped` is fully supported; `partial` implements only part of the contract; `planned` tracks future work; `intentionally-unsupported` is an explicit layer boundary; `blocked` names an external prerequisite. Detailed evidence and follow-up links remain in each owning consumer repository.",
        "",
        "Signing identity/tier is descriptor metadata. Authorization role/scope metadata is rendered separately and is currently unavailable because `RpcContract` defines no authorization role/scope option; signing is not authorization.",
        "",
    ]
    capabilities = sorted(
        {str(contract["capability"]) for contract in inventory.values()}
    )
    for capability in capabilities:
        rpcs = [
            rpc
            for rpc in inventory
            if inventory[rpc]["capability"] == capability
        ]
        if not rpcs:
            continue
        lines.extend(
            [
                f"## {capability}",
                "",
                "| RPC | Target / maturity | Signing contract | Authorization contract metadata | Effect / retry contract | Heddle client | Heddle CLI | Tapestry adapter | Tapestry UI | Weft implementation | Weft registration |",
                "|---|---|---|---|---|---|---|---|---|---|---|",
            ]
        )
        for rpc in rpcs:
            contract = inventory[rpc]
            target = f"{', '.join(contract['deployment_targets'])} / {contract['maturity']}"
            signing = f"{contract['signing_identity']} / {contract['signing_tier']}"
            retry = (
                f"{contract['effect']}; {contract['retry_behavior']}; "
                f"client operation id: {'required' if contract['client_operation_id_required'] else 'not required'}"
            )
            lines.append(
                "| `" + rpc + "` | " + target + " | " + signing + " | "
                + AUTHORIZATION_METADATA
                + " | "
                + retry
                + " | "
                + " | ".join(
                    _cell(audited[name][rpc]["layers"][layer])
                    for name in CONSUMERS
                    for layer in LAYERS[name]
                )
                + " |"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def check_report(path: Path, rendered: str) -> None:
    if not path.is_file() or path.read_text() != rendered:
        raise AuditError(f"generated report drift: run {Path(__file__).relative_to(ROOT)}")


def build_inventory() -> dict[str, dict[str, object]]:
    with tempfile.TemporaryDirectory() as directory:
        descriptor = Path(directory) / "api.binpb"
        _run("buf", "build", "-o", str(descriptor))
        return descriptor_inventory(descriptor)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--declarations",
        type=Path,
        default=ROOT / "capabilities/declarations",
    )
    parser.add_argument(
        "--report", type=Path, default=ROOT / "capabilities/MATRIX.md"
    )
    parser.add_argument(
        "--provenance", type=Path, default=ROOT / "capabilities/sources.json"
    )
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    inventory = build_inventory()
    audit_provenance(args.declarations, args.provenance)
    audited = audit_declarations(inventory, load_declarations(args.declarations))
    rendered = render_report(inventory, audited)
    if args.check:
        check_report(args.report, rendered)
    else:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(rendered)


if __name__ == "__main__":
    main()
