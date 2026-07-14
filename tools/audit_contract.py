#!/usr/bin/env python3
"""Audit compiled descriptors and the frozen v1 migration manifest."""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
PACKAGE = "heddle.api.v1alpha1"


def run(*args: str, stdin: bytes | None = None) -> bytes:
    return subprocess.run(args, cwd=ROOT, input=stdin, check=True, capture_output=True).stdout


def blocks(lines: list[str], opener: str) -> list[list[str]]:
    found: list[list[str]] = []
    for start, line in enumerate(lines):
        if line != opener:
            continue
        depth = 0
        for end in range(start, len(lines)):
            depth += lines[end].count("{") - lines[end].count("}")
            if depth == 0:
                found.append(lines[start:end + 1])
                break
    return found


def decoded_descriptor(descriptor: Path, register_contract: bool) -> str:
    args = [
        "protoc", "-I", "proto", "--decode=google.protobuf.FileDescriptorSet",
        "google/protobuf/descriptor.proto",
    ]
    if register_contract:
        args.append("proto/heddle/api/v1alpha1/contract.proto")
    return run(*args, stdin=descriptor.read_bytes()).decode()


def legacy_inventory(decoded: str) -> set[str]:
    methods: set[str] = set()
    for file_block in blocks(decoded.splitlines(), "file {"):
        package_match = next((re.match(r'  package: "(.+)"', line) for line in file_block if line.startswith("  package:")), None)
        if not package_match or package_match.group(1) != "heddle.v1":
            continue
        for service_block in blocks(file_block, "  service {"):
            service_name = re.search(r'^    name: "(.+)"$', "\n".join(service_block), re.MULTILINE).group(1)
            for method_block in blocks(service_block, "    method {"):
                method_name = re.search(r'^      name: "(.+)"$', "\n".join(method_block), re.MULTILINE).group(1)
                methods.add(f"heddle.v1.{service_name}/{method_name}")
    return methods


def audit_new_descriptor(decoded: str) -> None:
    proto_sources = "\n".join(path.read_text() for path in (ROOT / "proto").rglob("*.proto"))
    service_count = len(re.findall(r"(?m)^service \w+", proto_sources))
    rpc_count = len(re.findall(r"(?m)^\s*rpc \w+", proto_sources))
    assert decoded.count(f"[{PACKAGE}.service_contract]") == service_count
    assert decoded.count(f"[{PACKAGE}.rpc_contract]") == rpc_count
    assert decoded.count("maturity: SERVICE_MATURITY_SHIPPED") == 10
    assert decoded.count("maturity: SERVICE_MATURITY_PLANNED") == 2
    assert "google.protobuf.Any" not in decoded
    assert "google.protobuf.Struct" not in decoded
    assert "google.protobuf.Value" not in decoded

    messages: dict[str, list[tuple[str, str]]] = {}
    for file_block in blocks(decoded.splitlines(), "file {"):
        package = re.search(r'^  package: "(.+)"$', "\n".join(file_block), re.MULTILINE)
        if not package or package.group(1) != PACKAGE:
            continue
        for message_block in blocks(file_block, "  message_type {"):
            name = re.search(r'^    name: "(.+)"$', "\n".join(message_block), re.MULTILINE).group(1)
            fields: list[tuple[str, str]] = []
            for field_block in blocks(message_block, "    field {"):
                field_text = "\n".join(field_block)
                field_name = re.search(r'^      name: "(.+)"$', field_text, re.MULTILINE).group(1)
                label = re.search(r'^      label: (.+)$', field_text, re.MULTILINE)
                fields.append((field_name, label.group(1) if label else "LABEL_OPTIONAL"))
            messages[f".{PACKAGE}.{name}"] = fields
        for service_block in blocks(file_block, "  service {"):
            for method_block in blocks(service_block, "    method {"):
                method_text = "\n".join(method_block)
                if "effect: RPC_EFFECT_DURABLE_WRITE" not in method_text:
                    continue
                input_type = re.search(r'^      input_type: "(.+)"$', method_text, re.MULTILINE).group(1)
                retry_fields = [field for field in messages[input_type] if field[0] == "client_operation_id"]
                assert retry_fields == [("client_operation_id", "LABEL_OPTIONAL")], input_type


def main() -> None:
    with tempfile.TemporaryDirectory() as directory:
        descriptor = Path(directory) / "api.binpb"
        run("buf", "build", "-o", str(descriptor))
        audit_new_descriptor(decoded_descriptor(descriptor, register_contract=True))

    legacy = ROOT / "legacy/heddle-v1-0.23.binpb"
    inventory = legacy_inventory(decoded_descriptor(legacy, register_contract=False))
    manifest = json.loads((ROOT / "migration-manifest.json").read_text())["methods"]
    classified = {entry["old_rpc"] for entry in manifest}
    assert classified == inventory, f"unclassified={inventory - classified}, unknown={classified - inventory}"
    for entry in manifest:
        if entry["classification"] == "renamed":
            assert entry.get("production_callsite"), entry["old_rpc"]
            assert entry.get("new_rpc"), entry["old_rpc"]
        else:
            assert entry.get("reason"), entry["old_rpc"]


if __name__ == "__main__":
    main()
