#!/usr/bin/env python3
"""Generate and audit the descriptor-derived client capability matrix."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
PACKAGE = "heddle.api.v1alpha1"
CONSUMERS = ("heddle", "tapestry", "weft")
LAYERS = {
    "heddle": ("client", "cli"),
    "tapestry": ("server_adapter", "ui"),
    "weft": ("implementation", "registration"),
}
STATUSES = {"shipped", "planned", "unsupported", "blocked"}


class AuditError(ValueError):
    """A declaration or generated artifact drifted from the descriptor."""


def _run(*args: str, stdin: bytes | None = None) -> bytes:
    return subprocess.run(
        args, cwd=ROOT, input=stdin, check=True, capture_output=True
    ).stdout


def _blocks(lines: list[str], opener: str) -> list[list[str]]:
    found: list[list[str]] = []
    for start, line in enumerate(lines):
        if line != opener:
            continue
        depth = 0
        for end in range(start, len(lines)):
            depth += lines[end].count("{") - lines[end].count("}")
            if depth == 0:
                found.append(lines[start : end + 1])
                break
    return found


def _required(pattern: str, text: str, context: str) -> str:
    match = re.search(pattern, text, re.MULTILINE)
    if not match:
        raise AuditError(f"descriptor metadata missing {context}")
    return match.group(1)


def _enum_value(prefix: str, pattern: str, text: str, context: str) -> str:
    return _required(pattern, text, context).removeprefix(prefix)


def descriptor_inventory(descriptor: Path) -> dict[str, dict[str, object]]:
    """Read the complete service/RPC inventory and contract options from an FDS."""
    decoded = _run(
        "protoc",
        "-I",
        "proto",
        "--decode=google.protobuf.FileDescriptorSet",
        "google/protobuf/descriptor.proto",
        "proto/heddle/api/v1alpha1/contract.proto",
        stdin=descriptor.read_bytes(),
    ).decode()
    inventory: dict[str, dict[str, object]] = {}
    for file_block in _blocks(decoded.splitlines(), "file {"):
        file_text = "\n".join(file_block)
        package = re.search(r'^  package: "(.+)"$', file_text, re.MULTILINE)
        if not package or package.group(1) != PACKAGE:
            continue
        for service_block in _blocks(file_block, "  service {"):
            service_text = "\n".join(service_block)
            service_name = _required(
                r'^    name: "(.+)"$', service_text, "service name"
            )
            service_fqn = f"{PACKAGE}.{service_name}"
            targets = sorted(
                value.removeprefix("DEPLOYMENT_TARGET_")
                for value in re.findall(
                    r"deployment_targets: (DEPLOYMENT_TARGET_[A-Z_]+)", service_text
                )
            )
            if not targets:
                raise AuditError(f"descriptor metadata missing deployment target: {service_fqn}")
            maturity = _enum_value(
                "SERVICE_MATURITY_",
                r"maturity: (SERVICE_MATURITY_[A-Z_]+)",
                service_text,
                f"service maturity: {service_fqn}",
            )
            for method_block in _blocks(service_block, "    method {"):
                method_text = "\n".join(method_block)
                method_name = _required(
                    r'^      name: "(.+)"$', method_text, "method name"
                )
                rpc = f"{service_fqn}/{method_name}"
                if rpc in inventory:
                    raise AuditError(f"descriptor contains duplicate RPC: {rpc}")
                inventory[rpc] = {
                    "rpc": rpc,
                    "service": service_fqn,
                    "method": method_name,
                    "deployment_targets": targets,
                    "maturity": maturity,
                    "signing_identity": _enum_value(
                        "STABLE_SIGNING_IDENTITY_",
                        r"signing_identity: (STABLE_SIGNING_IDENTITY_[A-Z_]+)",
                        method_text,
                        f"signing identity: {rpc}",
                    ),
                    "signing_tier": _enum_value(
                        "SIGNING_TIER_",
                        r"signing_tier: (SIGNING_TIER_[A-Z_]+)",
                        method_text,
                        f"signing tier: {rpc}",
                    ),
                    "effect": _enum_value(
                        "RPC_EFFECT_",
                        r"effect: (RPC_EFFECT_[A-Z_]+)",
                        method_text,
                        f"effect: {rpc}",
                    ),
                    "retry_behavior": _enum_value(
                        "RETRY_BEHAVIOR_",
                        r"retry_behavior: (RETRY_BEHAVIOR_[A-Z_]+)",
                        method_text,
                        f"retry behavior: {rpc}",
                    ),
                    "client_operation_id_required": (
                        "client_operation_id_required: true" in method_text
                    ),
                    "client_streaming": "client_streaming: true" in method_text,
                    "server_streaming": "server_streaming: true" in method_text,
                }
    if not inventory:
        raise AuditError(f"descriptor contains no RPCs in {PACKAGE}")
    return dict(sorted(inventory.items()))


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
    if manifest.get("schema_version") != 1:
        raise AuditError("unsupported provenance schema")
    sources = manifest.get("sources")
    if not isinstance(sources, dict) or set(sources) != set(CONSUMERS):
        raise AuditError("provenance consumer set mismatch")
    for consumer in CONSUMERS:
        source = sources[consumer]
        expected = {
            "repository": f"HeddleCo/{consumer}",
            "path": f"api-capabilities/{consumer}.json",
        }
        if not isinstance(source, dict) or any(
            source.get(key) != value for key, value in expected.items()
        ):
            raise AuditError(f"provenance source mismatch for {consumer}")
        revision = source.get("revision")
        if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise AuditError(f"invalid provenance revision for {consumer}")
        content_hash = source.get("sha256")
        actual = hashlib.sha256((directory / f"{consumer}.json").read_bytes()).hexdigest()
        if content_hash != actual:
            raise AuditError(f"provenance content hash mismatch for {consumer}")


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
        if declaration.get("schema_version") != 1:
            raise AuditError(f"unsupported declaration schema for {consumer}")
        if declaration.get("consumer") != consumer:
            raise AuditError(f"consumer name mismatch for {consumer}")
        if declaration.get("source_repository") != f"HeddleCo/{consumer}":
            raise AuditError(f"source repository mismatch for {consumer}")
        rows = declaration.get("rpc_mappings")
        if not isinstance(rows, list):
            raise AuditError(f"rpc_mappings must be a list for {consumer}")
        by_rpc: dict[str, dict[str, object]] = {}
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("rpc"), str):
                raise AuditError(f"invalid mapping row for {consumer}")
            rpc = str(row["rpc"])
            if rpc in by_rpc:
                raise AuditError(f"duplicate mapping for {consumer}: {rpc}")
            if rpc not in descriptor_rpcs:
                raise AuditError(f"nonexistent RPC declared by {consumer}: {rpc}")
            capability = row.get("capability")
            if not isinstance(capability, str) or not capability.strip():
                raise AuditError(f"blank capability for {consumer}: {rpc}")
            layers = row.get("layers")
            if not isinstance(layers, dict) or set(layers) != set(LAYERS[consumer]):
                raise AuditError(f"layer set mismatch for {consumer}: {rpc}")
            for layer_name in LAYERS[consumer]:
                layer = layers[layer_name]
                if not isinstance(layer, dict):
                    raise AuditError(f"invalid {consumer} {layer_name} layer: {rpc}")
                status = layer.get("status")
                if status == "" or status is None:
                    raise AuditError(f"blank status for {consumer} {layer_name}: {rpc}")
                if status not in STATUSES:
                    raise AuditError(
                        f"invalid status for {consumer} {layer_name}: {rpc}: {status}"
                    )
                evidence = layer.get("evidence")
                if not isinstance(evidence, list) or any(
                    not isinstance(item, str) or not item.strip() for item in evidence
                ):
                    raise AuditError(f"invalid evidence for {consumer} {layer_name}: {rpc}")
                if status == "shipped" and not evidence:
                    if consumer == "weft" and layer_name == "registration":
                        raise AuditError(f"missing Weft registration for shipped RPC: {rpc}")
                    raise AuditError(
                        f"shipped mapping lacks evidence for {consumer} {layer_name}: {rpc}"
                    )
                follow_up = layer.get("follow_up")
                if follow_up is not None and not re.fullmatch(
                    r"https://github\.com/HeddleCo/[a-z-]+/issues/[1-9][0-9]*",
                    str(follow_up),
                ):
                    raise AuditError(
                        f"invalid follow-up URL for {consumer} {layer_name}: {rpc}"
                    )
            by_rpc[rpc] = row
        missing = descriptor_rpcs - set(by_rpc)
        if missing:
            raise AuditError(
                f"missing descriptor RPC in {consumer}: {', '.join(sorted(missing))}"
            )
        audited[consumer] = by_rpc

    for rpc, contract in inventory.items():
        capabilities = {audited[name][rpc]["capability"] for name in CONSUMERS}
        if len(capabilities) != 1:
            raise AuditError(f"capability mismatch across declarations: {rpc}")
        if contract["maturity"] != "SHIPPED" or "WEFT" not in contract[
            "deployment_targets"
        ]:
            continue
        layers = audited["weft"][rpc]["layers"]
        if layers["implementation"]["status"] != "shipped":
            raise AuditError(f"shipped descriptor RPC lacks Weft implementation: {rpc}")
        if layers["registration"]["status"] != "shipped":
            raise AuditError(f"shipped descriptor RPC lacks Weft registration: {rpc}")
    return audited


def _cell(layer: dict[str, object]) -> str:
    status = str(layer["status"])
    follow_up = layer.get("follow_up")
    if follow_up:
        return f"{status} ([follow-up]({follow_up}))"
    return status


def render_report(
    inventory: dict[str, dict[str, object]],
    audited: dict[str, dict[str, dict[str, object]]],
) -> str:
    """Render a stable report; all contract metadata comes from the descriptor."""
    lines = [
        "# Generated capability and authorization parity matrix",
        "",
        "Generated by `tools/capability_matrix.py` from the compiled descriptor and the checked-in consumer declarations. Do not edit this report by hand.",
        "",
        f"Descriptor inventory: {len(inventory)} RPCs across {len({row['service'] for row in inventory.values()})} services.",
        "",
        "Status vocabulary: `shipped` has grounded layer evidence; `planned` is future work (linked when it is an accidental gap); `unsupported` is an intentional layer boundary; `blocked` names an external prerequisite.",
        "",
    ]
    capabilities = sorted(
        {str(row["capability"]) for rows in audited.values() for row in rows.values()}
    )
    for capability in capabilities:
        rpcs = [
            rpc
            for rpc in inventory
            if any(rows[rpc]["capability"] == capability for rows in audited.values())
        ]
        if not rpcs:
            continue
        lines.extend(
            [
                f"## {capability}",
                "",
                "| RPC | Target / maturity | Authorization and retry contract | Heddle client | Heddle CLI | Tapestry adapter | Tapestry UI | Weft implementation | Weft registration |",
                "|---|---|---|---|---|---|---|---|---|",
            ]
        )
        for rpc in rpcs:
            contract = inventory[rpc]
            target = f"{', '.join(contract['deployment_targets'])} / {contract['maturity']}"
            authorization = (
                f"{contract['signing_identity']} / {contract['signing_tier']}; "
                f"{contract['effect']}; {contract['retry_behavior']}; "
                f"client operation id: {'required' if contract['client_operation_id_required'] else 'not required'}"
            )
            lines.append(
                "| `" + rpc + "` | " + target + " | " + authorization + " | "
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
