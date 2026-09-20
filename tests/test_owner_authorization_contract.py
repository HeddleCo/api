from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parent.parent
OWNER = (ROOT / "proto/heddle/api/v1alpha2/owner_records.proto").read_text()
OWNERSHIP = (ROOT / "proto/heddle/api/v1alpha2/ownership.proto").read_text()
SERVICES = (ROOT / "proto/heddle/api/v1alpha2/services.proto").read_text()


def body(source: str, kind: str, name: str) -> str:
    match = re.search(rf"(?ms)^{kind} {re.escape(name)} \{{(.*?)^\}}", source)
    if match is None:
        raise AssertionError(f"missing {kind} {name}")
    return match.group(1)


def fields(source: str, message: str) -> list[tuple[str, str, str, int]]:
    return [
        (qualifier or "", field_type, field_name, int(tag))
        for qualifier, field_type, field_name, tag in re.findall(
            r"(?m)^\s*(?:(optional|repeated)\s+)?"
            r"([A-Za-z][A-Za-z0-9_.]*)\s+([a-z][a-z0-9_]*)\s*=\s*(\d+)\s*;",
            body(source, "message", message),
        )
    ]


def enum_values(source: str, name: str) -> list[tuple[str, int]]:
    return [
        (value, int(tag))
        for value, tag in re.findall(
            r"(?m)^\s*([A-Z][A-Z0-9_]*)\s*=\s*(\d+)\s*;",
            body(source, "enum", name),
        )
    ]


class OwnerAuthorizationContractTest(unittest.TestCase):
    def test_foundational_owner_records_keep_exact_wire_shapes(self) -> None:
        expected = {
            "AuthorizationVerificationKey": [
                ("", "AuthorizationKeyAlgorithm", "algorithm", 1),
                ("", "bytes", "public_key", 2),
            ],
            "AuthorizationSignature": [
                ("", "bytes", "signer_key_id", 1),
                ("", "bytes", "signature", 2),
            ],
            "RecoveryGuardian": [
                ("", "RecoveryGuardianKind", "kind", 1),
                ("", "AuthorizationVerificationKey", "key", 2),
            ],
            "RecoveryPolicy": [
                ("", "uint32", "threshold", 1),
                ("repeated", "RecoveryGuardian", "guardians", 2),
                ("optional", "uint64", "window_secs", 3),
            ],
            "OwnerRoot": [
                ("", "uint32", "format_version", 1),
                ("", "bytes", "owner_id", 2),
                ("", "bytes", "account_uuid", 3),
                ("", "AuthorizationVerificationKey", "authority_key", 4),
                ("", "RecoveryPolicy", "recovery_policy", 5),
                ("", "bool", "claimable_deferred_human", 6),
                ("", "bytes", "nonce", 7),
                ("", "int64", "claimable_until_unix_seconds", 8),
            ],
            "SignedOwnerRoot": [
                ("", "OwnerRoot", "root", 1),
                ("", "AuthorizationSignature", "authority_proof", 2),
                ("repeated", "AuthorizationSignature", "recovery_key_proofs", 3),
            ],
            "SpoolOwnerGenesis": [
                ("", "bytes", "spool_uuid", 1),
                ("", "AuthorizationVerificationKey", "owner_public_key", 2),
            ],
            "SignedSpoolOwnerGenesis": [
                ("", "SpoolOwnerGenesis", "genesis", 1),
                ("", "AuthorizationSignature", "owner_signature", 2),
                ("", "SpoolCreationProof", "delegated_creation", 3),
            ],
        }
        for message, expected_fields in expected.items():
            with self.subTest(message=message):
                self.assertEqual(fields(OWNER, message), expected_fields)

    def test_recovery_guardians_remain_distinguishable_on_the_wire(self) -> None:
        self.assertEqual(
            enum_values(OWNER, "RecoveryGuardianKind"),
            [
                ("RECOVERY_GUARDIAN_KIND_UNSPECIFIED", 0),
                ("RECOVERY_GUARDIAN_KIND_PAPER", 1),
                ("RECOVERY_GUARDIAN_KIND_SOCIAL", 2),
                ("RECOVERY_GUARDIAN_KIND_WEFT", 3),
            ],
        )
        policy = body(OWNER, "message", "RecoveryPolicy")
        self.assertIn("604800", policy)
        self.assertRegex(policy, r"optional\s+uint64\s+window_secs\s*=\s*3\s*;")

    def test_owner_identity_is_self_rooted_and_genesis_is_tofu_pinned(self) -> None:
        binding = body(OWNER, "message", "OwnerKeyBinding")
        self.assertNotIn("registry_attestation", binding)
        self.assertRegex(
            binding,
            r"AuthorizationSignature\s+root_proof_of_possession\s*=\s*8\s*;",
        )
        self.assertIn(
            "SHA-256(genesis.owner_public_key.public_key || genesis.spool_uuid)",
            OWNER,
        )
        self.assertIn("TOFU-pins spool_uuid -> owner_public_key", OWNER)

    def test_owner_capability_is_portable_and_purge_only(self) -> None:
        self.assertEqual(
            enum_values(OWNER, "SpoolCapabilityAction"),
            [
                ("SPOOL_CAPABILITY_ACTION_UNSPECIFIED", 0),
                ("SPOOL_CAPABILITY_ACTION_PURGE", 1),
            ],
        )
        self.assertEqual(
            fields(OWNER, "OwnerAuthorizationBundle"),
            [
                ("", "SignedOwnerRoot", "owner_root", 1),
                ("repeated", "SignedOwnerKeyTransition", "owner_state_chain", 2),
                ("repeated", "SignedOwnerCapability", "capability_chain", 3),
                ("", "bytes", "subject_biscuit", 4),
            ],
        )
        purge = body(OWNER, "message", "PurgeOperationSigningBody")
        self.assertRegex(purge, r"\bPurgeSidecarIdentity\s+purge_identity\s*=\s*3\s*;")
        self.assertIn("heddle-purge-operation-v2", OWNER)

    def test_signed_policy_merge_semantics_are_explicit(self) -> None:
        self.assertEqual(
            enum_values(OWNER, "SignedPolicyMergeSemantics"),
            [
                ("SIGNED_POLICY_MERGE_SEMANTICS_UNSPECIFIED", 0),
                ("SIGNED_POLICY_MERGE_SEMANTICS_LAST_WRITER_WINS", 1),
                ("SIGNED_POLICY_MERGE_SEMANTICS_GROW_ONLY_SET_UNION", 2),
            ],
        )
        self.assertEqual(
            fields(OWNER, "SignedSpoolPolicy"),
            [
                ("repeated", "bytes", "revoked_key_ids", 1),
                ("optional", "Audience", "max_audience", 2),
            ],
        )
        self.assertEqual(
            fields(OWNER, "SignedPolicyMergeRule"),
            [
                ("", "string", "setting_key", 1),
                ("", "SignedPolicyMergeSemantics", "semantics", 2),
            ],
        )
        signed = body(OWNER, "message", "SignedSpoolPolicyRecord")
        self.assertRegex(signed, r"\bSignedPolicyBody\s+body\s*=\s*1\s*;")
        self.assertRegex(
            signed, r"\bAuthorizationSignature\s+owner_signature\s*=\s*2\s*;"
        )
        self.assertIn("Weft never constructs or signs this record", OWNER)

    def test_owner_messages_are_reachable_from_typed_rpcs(self) -> None:
        expected_requests = {
            "BootstrapOwnership": "BootstrapOwnershipRequest",
            "SubmitOwnerTransition": "SubmitOwnerTransitionRequest",
            "CompleteOwnerTransition": "CompleteOwnerTransitionRequest",
            "VetoOwnerTransition": "VetoOwnerTransitionRequest",
            "SubmitOwnerCapability": "SubmitOwnerCapabilityRequest",
            "TransferOwnership": "TransferOwnershipRequest",
            "ObserveOwnership": "ObserveOwnershipRequest",
        }
        service = body(SERVICES, "service", "OwnerAuthorizationService")
        for method, request in expected_requests.items():
            self.assertRegex(service, rf"\brpc {method}\({request}\)")
        for request in expected_requests.values():
            self.assertRegex(OWNERSHIP, rf"(?m)^message {request} \{{")

    def test_contract_carries_no_private_authorization_key_field(self) -> None:
        self.assertNotRegex(
            OWNER,
            r"(?m)^\s*(?:bytes|string)\s+(?:private_key|secret_key)\s*=",
        )
        self.assertIn("No private key is transported", OWNER)
        self.assertIn("No private key is ever transmitted", OWNER)


if __name__ == "__main__":
    unittest.main()
