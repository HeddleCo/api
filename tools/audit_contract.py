#!/usr/bin/env python3
"""Audit the compiled v1alpha2 descriptor and frozen v1 migration manifest."""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
PACKAGE = "heddle.api.v1alpha2"
CONTRACT_PACKAGE = "heddle.api.common"


def run(*args: str, stdin: bytes | None = None) -> bytes:
    return subprocess.run(
        args, cwd=ROOT, input=stdin, check=True, capture_output=True
    ).stdout


def blocks(lines: list[str], opener: str) -> list[list[str]]:
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


def decoded_descriptor(descriptor: Path, register_contract: bool) -> str:
    args = [
        "protoc",
        "-I",
        "proto",
        "--decode=google.protobuf.FileDescriptorSet",
        "google/protobuf/descriptor.proto",
    ]
    if register_contract:
        args.append("proto/heddle/api/common/contract.proto")
    return run(*args, stdin=descriptor.read_bytes()).decode()


def package_files(decoded: str, package: str) -> list[list[str]]:
    return [
        block
        for block in blocks(decoded.splitlines(), "file {")
        if f'  package: "{package}"' in block
    ]


def block_name(block: list[str], indent: int) -> str:
    match = re.search(
        rf'^{" " * indent}name: "(.+)"$', "\n".join(block), re.MULTILINE
    )
    if match is None:
        raise AssertionError("unnamed descriptor block")
    return match.group(1)


def descriptor_messages(
    files: list[list[str]], package: str
) -> dict[str, tuple[list[tuple[str, str, int]], set[int], set[str], list[str]]]:
    messages = {}
    for file_block in files:
        for message_block in blocks(file_block, "  message_type {"):
            name = block_name(message_block, 4)
            fields: list[tuple[str, str, int]] = []
            for field_block in blocks(message_block, "    field {"):
                field_text = "\n".join(field_block)
                field_name = re.search(
                    r'^      name: "(.+)"$', field_text, re.MULTILINE
                ).group(1)
                label = re.search(r"^      label: (.+)$", field_text, re.MULTILINE)
                number = int(
                    re.search(r"^      number: (\d+)$", field_text, re.MULTILINE).group(
                        1
                    )
                )
                fields.append(
                    (field_name, label.group(1) if label else "LABEL_OPTIONAL", number)
                )
            reserved_numbers: set[int] = set()
            for reserved_block in blocks(message_block, "    reserved_range {"):
                reserved_text = "\n".join(reserved_block)
                start = int(
                    re.search(
                        r"^      start: (\d+)$", reserved_text, re.MULTILINE
                    ).group(1)
                )
                end = int(
                    re.search(
                        r"^      end: (\d+)$", reserved_text, re.MULTILINE
                    ).group(1)
                )
                reserved_numbers.update(range(start, end))
            reserved_names = set(
                re.findall(
                    r'^    reserved_name: "(.+)"$',
                    "\n".join(message_block),
                    re.MULTILINE,
                )
            )
            messages[f".{package}.{name}"] = (
                fields,
                reserved_numbers,
                reserved_names,
                message_block,
            )
    return messages


def legacy_inventory(decoded: str) -> set[str]:
    methods: set[str] = set()
    for file_block in package_files(decoded, "heddle.v1"):
        for service_block in blocks(file_block, "  service {"):
            service_name = block_name(service_block, 4)
            for method_block in blocks(service_block, "    method {"):
                methods.add(f"heddle.v1.{service_name}/{block_name(method_block, 6)}")
    return methods


def audit_metadata(decoded: str, files: list[list[str]]) -> None:
    proto_sources = "\n".join(
        path.read_text()
        for path in (ROOT / "proto/heddle/api/v1alpha2").glob("*.proto")
    )
    service_count = len(re.findall(r"(?m)^service \w+", proto_sources))
    rpc_count = len(re.findall(r"(?m)^\s*rpc \w+", proto_sources))
    package_descriptor = "\n".join("\n".join(block) for block in files)
    assert package_descriptor.count(
        f"[{CONTRACT_PACKAGE}.service_contract]"
    ) == service_count
    assert package_descriptor.count(f"[{CONTRACT_PACKAGE}.rpc_contract]") == rpc_count
    assert service_count == 19
    assert rpc_count == 137
    assert package_descriptor.count("maturity: SERVICE_MATURITY_PLANNED") == 19
    assert "maturity: SERVICE_MATURITY_SHIPPED" not in package_descriptor
    for dynamic_type in (
        'type_name: ".google.protobuf.Any"',
        "google.protobuf.Struct",
        "google.protobuf.Value",
    ):
        assert dynamic_type not in package_descriptor


def audit_operation_contract(files: list[list[str]]) -> None:
    messages = descriptor_messages(files, PACKAGE)
    operation = messages[f".{PACKAGE}.OperationRecord"][3]
    state = next(
        enum
        for enum in blocks(operation, "    enum_type {")
        if '      name: "State"' in enum
    )
    values = [
        (block_name(value, 8), int(re.search(r"^        number: (\d+)$", "\n".join(value), re.MULTILINE).group(1)))
        for value in blocks(state, "      value {")
    ]
    assert values == [
        ("STATE_UNSPECIFIED", 0),
        ("STATE_QUEUED", 1),
        ("STATE_RUNNING", 2),
        ("STATE_COMPLETED", 3),
        ("STATE_FAILED", 4),
        ("STATE_CANCELED", 5),
        ("STATE_WAITING_FOR_HUMAN", 6),
        ("STATE_PAUSED", 7),
    ]

    operation_service = next(
        service
        for file_block in files
        for service in blocks(file_block, "  service {")
        if '    name: "OperationService"' in service
    )
    methods = {
        block_name(method, 6): "\n".join(method)
        for method in blocks(operation_service, "    method {")
    }
    assert methods.keys() == {"ObserveOperations", "CancelOperation"}
    assert "server_streaming: true" in methods["ObserveOperations"]
    assert "effect: RPC_EFFECT_READ_ONLY" in methods["ObserveOperations"]
    assert "retry_behavior: RETRY_BEHAVIOR_RESUMABLE_STREAM" in methods[
        "ObserveOperations"
    ]
    cancel = methods["CancelOperation"]
    assert "effect: RPC_EFFECT_DURABLE_WRITE" in cancel
    assert "retry_behavior: RETRY_BEHAVIOR_CLIENT_OPERATION_ID" in cancel
    assert "client_operation_id_required: true" in cancel

    package_descriptor = "\n".join("\n".join(block) for block in files)
    for removed in (
        'name: "OperationState"',
        'name: "SubmitOperation"',
        'name: "SubmitOperationBatch"',
        'name: "WatchOperations"',
        'name: "ImportCommitProgress"',
    ):
        assert removed not in package_descriptor


def audit_message_and_enum_shapes(files: list[list[str]]) -> None:
    messages = descriptor_messages(files, PACKAGE)
    approved_unreserved_gaps = {
        "AuthenticationResponse": {3},
        "RevokeDeviceRequest": {3},
        "ApprovePairingRequest": {3},
        "HandleResolution": {2},
        "SubmitOwnerTransitionRequest": {3},
        "TransferOwnershipRequest": {3},
    }
    for qualified_name, (fields, reserved, _, _) in messages.items():
        name = qualified_name.rsplit(".", 1)[-1]
        field_numbers = {field[2] for field in fields}
        highest = max(field_numbers | reserved, default=0)
        gaps = set(range(1, highest + 1)) - field_numbers - reserved
        assert gaps == approved_unreserved_gaps.get(name, set()), (name, gaps)

    for file_block in files:
        for enum_block in blocks(file_block, "  enum_type {"):
            first_value = next(iter(blocks(enum_block, "    value {")), None)
            assert first_value is not None
            first_name = block_name(first_value, 6)
            first_number = int(
                re.search(
                    r"^      number: (\d+)$",
                    "\n".join(first_value),
                    re.MULTILINE,
                ).group(1)
            )
            assert first_number == 0 and first_name.endswith("_UNSPECIFIED"), (
                block_name(enum_block, 4),
                first_name,
            )


def audit_failure_shapes(decoded: str) -> None:
    common_files = package_files(decoded, CONTRACT_PACKAGE)
    messages = descriptor_messages(common_files, CONTRACT_PACKAGE)
    expected = {
        "CallFailure": ([('code', 'LABEL_OPTIONAL', 1), ('message', 'LABEL_OPTIONAL', 2), ('error', 'LABEL_OPTIONAL', 4)], {3}, {"details"}),
        "StreamFailure": ([('code', 'LABEL_OPTIONAL', 1), ('message', 'LABEL_OPTIONAL', 2), ('error', 'LABEL_OPTIONAL', 5)], {3, 4}, {"retry", "cursor"}),
    }
    for name, (expected_fields, expected_numbers, expected_names) in expected.items():
        actual_fields, reserved_numbers, reserved_names, _ = messages[
            f".{CONTRACT_PACKAGE}.{name}"
        ]
        assert actual_fields == expected_fields, name
        assert reserved_numbers == expected_numbers, name
        assert reserved_names == expected_names, name


def audit_retry_contracts(files: list[list[str]]) -> None:
    messages = descriptor_messages(files, PACKAGE)
    for file_block in files:
        for service_block in blocks(file_block, "  service {"):
            for method_block in blocks(service_block, "    method {"):
                method_text = "\n".join(method_block)
                input_type = re.search(
                    r'^      input_type: "(.+)"$', method_text, re.MULTILINE
                ).group(1)
                fields = messages[input_type][0]
                operation_id_fields = [
                    field for field in fields if field[0] == "client_operation_id"
                ]
                requires_id = "client_operation_id_required: true" in method_text
                client_retry = (
                    "retry_behavior: RETRY_BEHAVIOR_CLIENT_OPERATION_ID"
                    in method_text
                )
                if client_retry:
                    assert requires_id, block_name(method_block, 6)
                if requires_id:
                    assert operation_id_fields == [
                        ("client_operation_id", "LABEL_OPTIONAL", 1)
                    ], input_type


def audit_new_descriptor(decoded: str) -> None:
    files = package_files(decoded, PACKAGE)
    audit_metadata(decoded, files)
    audit_operation_contract(files)
    audit_message_and_enum_shapes(files)
    audit_failure_shapes(decoded)
    audit_retry_contracts(files)


def audit_manifest(decoded: str) -> None:
    inventory = legacy_inventory(decoded)
    manifest = json.loads((ROOT / "migration-manifest.json").read_text())["methods"]
    classified = {entry["old_rpc"] for entry in manifest}
    assert classified == inventory, (
        f"unclassified={inventory - classified}, unknown={classified - inventory}"
    )
    for entry in manifest:
        if entry["classification"] == "renamed":
            assert entry.get("production_callsite") or entry.get(
                "production_implementation"
            ), entry["old_rpc"]
            assert entry.get("new_rpc"), entry["old_rpc"]
        else:
            assert entry.get("reason"), entry["old_rpc"]


def main() -> None:
    with tempfile.TemporaryDirectory() as directory:
        descriptor = Path(directory) / "api.binpb"
        run("buf", "build", "-o", str(descriptor))
        audit_new_descriptor(decoded_descriptor(descriptor, register_contract=True))

    legacy = ROOT / "legacy/heddle-v1-0.23.binpb"
    audit_manifest(decoded_descriptor(legacy, register_contract=False))


if __name__ == "__main__":
    main()
