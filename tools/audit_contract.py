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
    assert decoded.count("maturity: SERVICE_MATURITY_SHIPPED") == 11
    assert decoded.count("maturity: SERVICE_MATURITY_PLANNED") == 2
    assert "google.protobuf.Any" not in decoded
    assert "google.protobuf.Struct" not in decoded
    assert "google.protobuf.Value" not in decoded

    byte_field_pattern = re.compile(
        r"(?m)^\s*(?:optional |repeated )?bytes\s+(\w+)\s*="
    )
    allowed_byte_field = re.compile(
        r"^(?:value|digest|hash|parent_id|parents|source_hash|base_root|"
        r"salt|argon2id_hash|"
        r".*(?:public_key|pubkey|signature|proof|client_data_json|attestation.*|assertion|"
        r"authenticator_data|user_handle|biscuit|bootstrap_token|grant_envelope|nonce)|"
        r"checkpoint|data|redactions_blob|state_visibility_blob|attachment_object|pack_chunk|pack_id|"
        r"capability_context|canonical_envelope|encrypted_.*)$"
    )
    unaudited_bytes = sorted(
        name for name in byte_field_pattern.findall(proto_sources) if not allowed_byte_field.fullmatch(name)
    )
    assert not unaudited_bytes, f"unaudited bytes fields: {unaudited_bytes}"

    operation_state_contracts = {
        "OPERATION_STATE_UNSPECIFIED": (False, False, False),
        "OPERATION_STATE_QUEUED": (False, False, False),
        "OPERATION_STATE_RUNNING": (False, False, False),
        "OPERATION_STATE_COMPLETED": (True, False, False),
        "OPERATION_STATE_FAILED": (True, True, False),
        "OPERATION_STATE_CANCELED": (True, False, True),
    }
    operation_state = next(
        enum_block
        for file_block in blocks(decoded.splitlines(), "file {")
        for enum_block in blocks(file_block, "  enum_type {")
        if '    name: "OperationState"' in enum_block
    )
    values = {
        re.search(r'^      name: "(.+)"$', "\n".join(value), re.MULTILINE).group(1): "\n".join(value)
        for value in blocks(operation_state, "    value {")
    }
    assert values.keys() == operation_state_contracts.keys()
    for name, (terminal, error_required, cancellation_succeeded) in operation_state_contracts.items():
        value = values[name]
        assert f"[{PACKAGE}.operation_state_contract]" in value, name
        assert ("terminal: true" in value) is terminal, name
        assert ("error_required: true" in value) is error_required, name
        assert ("cancellation_succeeded: true" in value) is cancellation_succeeded, name

    operation_service = next(
        service_block
        for file_block in blocks(decoded.splitlines(), "file {")
        for service_block in blocks(file_block, "  service {")
        if '    name: "OperationService"' in service_block
    )
    operation_methods = {
        re.search(r'^      name: "(.+)"$', "\n".join(method), re.MULTILINE).group(1): "\n".join(method)
        for method in blocks(operation_service, "    method {")
    }
    operation_rpc_contracts = {
        "SubmitOperation": ("PROOF_OF_POSSESSION", "DURABLE_WRITE", "CLIENT_OPERATION_ID", True),
        "SubmitOperationBatch": ("PROOF_OF_POSSESSION", "DURABLE_WRITE", "CLIENT_OPERATION_ID", True),
        "GetOperation": ("NONE", "READ_ONLY", "SAFE", False),
        "BatchGetOperations": ("NONE", "READ_ONLY", "SAFE", False),
        "GetOperationBatch": ("NONE", "READ_ONLY", "SAFE", False),
        "ListOperations": ("NONE", "READ_ONLY", "SAFE", False),
        "WatchOperations": ("NONE", "READ_ONLY", "RESUMABLE_STREAM", False),
        "CancelOperation": ("PROOF_OF_POSSESSION", "DURABLE_WRITE", "CLIENT_OPERATION_ID", True),
    }
    assert operation_methods.keys() == operation_rpc_contracts.keys()
    for name, (tier, effect, retry, client_operation_id_required) in operation_rpc_contracts.items():
        method = operation_methods[name]
        assert "signing_identity: STABLE_SIGNING_IDENTITY_AUTHENTICATED_PRINCIPAL" in method, name
        assert f"signing_tier: SIGNING_TIER_{tier}" in method, name
        assert f"effect: RPC_EFFECT_{effect}" in method, name
        assert f"retry_behavior: RETRY_BEHAVIOR_{retry}" in method, name
        required = "client_operation_id_required: true" in method
        assert required is client_operation_id_required, name
    assert "server_streaming: true" in operation_methods["WatchOperations"]

    for removed in (
        "CreateImportJob",
        "StreamImportProgress",
        "ImportProgressEvent",
        "ImportJobSummary",
        'name: "OperationReceipt"',
    ):
        assert removed not in decoded

    messages: dict[str, list[tuple[str, str, int]]] = {}
    for file_block in blocks(decoded.splitlines(), "file {"):
        package = re.search(r'^  package: "(.+)"$', "\n".join(file_block), re.MULTILINE)
        if not package or package.group(1) != PACKAGE:
            continue
        for message_block in blocks(file_block, "  message_type {"):
            name = re.search(r'^    name: "(.+)"$', "\n".join(message_block), re.MULTILINE).group(1)
            fields: list[tuple[str, str, int]] = []
            for field_block in blocks(message_block, "    field {"):
                field_text = "\n".join(field_block)
                field_name = re.search(r'^      name: "(.+)"$', field_text, re.MULTILINE).group(1)
                label = re.search(r'^      label: (.+)$', field_text, re.MULTILINE)
                number = int(re.search(r'^      number: (\d+)$', field_text, re.MULTILINE).group(1))
                fields.append((field_name, label.group(1) if label else "LABEL_OPTIONAL", number))
            reserved_numbers: set[int] = set()
            for reserved_block in blocks(message_block, "    reserved_range {"):
                reserved_text = "\n".join(reserved_block)
                start = int(re.search(r'^      start: (\d+)$', reserved_text, re.MULTILINE).group(1))
                end = int(re.search(r'^      end: (\d+)$', reserved_text, re.MULTILINE).group(1))
                reserved_numbers.update(range(start, end))
            reserved_names = set(
                re.findall(r'^    reserved_name: "(.+)"$', "\n".join(message_block), re.MULTILINE)
            )
            field_numbers = {field[2] for field in fields}
            highest = max(field_numbers | reserved_numbers, default=0)
            assert field_numbers == set(range(1, highest + 1)) - reserved_numbers, name
            if name == "HandlePrincipal":
                assert reserved_numbers == {1}, name
                assert reserved_names == {"subject"}, name
                assert [(field[0], field[2]) for field in fields] == [
                    ("display_name", 2),
                    ("handle", 3),
                    ("resolved", 4),
                    ("primary_handle", 5),
                    ("kind", 6),
                    ("verified", 7),
                    ("discriminator", 8),
                ], name
            messages[f".{PACKAGE}.{name}"] = fields
        for enum_block in blocks(file_block, "  enum_type {"):
            enum_text = "\n".join(enum_block)
            first_value = next(iter(blocks(enum_block, "    value {")), None)
            assert first_value is not None
            first_text = "\n".join(first_value)
            first_name = re.search(r'^      name: "(.+)"$', first_text, re.MULTILINE).group(1)
            first_number = int(re.search(r'^      number: (\d+)$', first_text, re.MULTILINE).group(1))
            assert first_number == 0 and first_name.endswith("_UNSPECIFIED"), enum_text
        for service_block in blocks(file_block, "  service {"):
            for method_block in blocks(service_block, "    method {"):
                method_text = "\n".join(method_block)
                if "effect: RPC_EFFECT_DURABLE_WRITE" not in method_text:
                    continue
                input_type = re.search(r'^      input_type: "(.+)"$', method_text, re.MULTILINE).group(1)
                retry_fields = [field[:2] for field in messages[input_type] if field[0] == "client_operation_id"]
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
            assert entry.get("production_callsite") or entry.get(
                "production_implementation"
            ), entry["old_rpc"]
            assert entry.get("new_rpc"), entry["old_rpc"]
        else:
            assert entry.get("reason"), entry["old_rpc"]


if __name__ == "__main__":
    main()
