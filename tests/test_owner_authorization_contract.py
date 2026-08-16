from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parent.parent
PROTO_ROOT = ROOT / "proto/heddle/api/v1alpha1"
OWNER_AUTHORIZATION_PROTO = PROTO_ROOT / "owner_authorization.proto"
OWNER_GOVERNANCE_PROTO = PROTO_ROOT / "owner_governance.proto"


def message_body(source: str, name: str) -> str:
    match = re.search(rf"(?ms)^message {re.escape(name)} \{{(.*?)^\}}", source)
    if match is None:
        raise AssertionError(f"missing message {name}")
    return match.group(1)


def enum_body(source: str, name: str) -> str:
    match = re.search(rf"(?ms)^enum {re.escape(name)} \{{(.*?)^\}}", source)
    if match is None:
        raise AssertionError(f"missing enum {name}")
    return match.group(1)


def fields(source: str, name: str) -> list[tuple[str, str, str, int]]:
    return [
        (qualifier or "", field_type, field_name, int(number))
        for qualifier, field_type, field_name, number in re.findall(
            r"(?m)^\s*(?:(optional|repeated)\s+)?"
            r"([A-Za-z][A-Za-z0-9]*)\s+([a-z][a-z0-9_]*)\s*=\s*(\d+)\s*;",
            message_body(source, name),
        )
    ]


def enum_values(source: str, name: str) -> list[tuple[str, int]]:
    return [
        (value, int(number))
        for value, number in re.findall(
            r"(?m)^\s*([A-Z][A-Z0-9_]*)\s*=\s*(\d+)\s*;",
            enum_body(source, name),
        )
    ]


class OwnerAuthorizationContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.assertTrue(
            OWNER_AUTHORIZATION_PROTO.exists(),
            "missing owner-anchored authorization contract",
        )
        self.owner_source = OWNER_AUTHORIZATION_PROTO.read_text()
        self.governance_source = OWNER_GOVERNANCE_PROTO.read_text()
        self.source = self.owner_source + "\n" + self.governance_source

    def test_all_six_reviewed_object_families_are_present(self) -> None:
        expected_messages = {
            # Owner root and typed recovery guardians.
            "AuthorizationVerificationKey",
            "AuthorizationSignature",
            "RecoveryGuardian",
            "RecoveryPolicy",
            "OwnerRoot",
            "SignedOwnerRoot",
            # Bootstrap.
            "NewPasskeyOwnerRootApproval",
            "ExistingPasskeyOwnerRootApproval",
            "WebAuthnOwnerRootApproval",
            "DeferredOwnerRootApproval",
            "BootstrapOwnerRootRequest",
            "BootstrapOwnerRootResponse",
            # Rotation and recovery.
            "OwnerKeyTransition",
            "SignedOwnerKeyTransition",
            # Owner-signed capability submission.
            "SpoolSelector",
            "CapabilityPrincipal",
            "SpoolCapabilityGrant",
            "OwnerCapability",
            "SignedOwnerCapability",
            "OwnerAuthorizationBundle",
            "SubmitOwnerAuthorizationRequest",
            "SubmitOwnerAuthorizationResponse",
            # Anonymous authentication.
            "AnonymousKeyCredential",
            "RegisterAnonymousKeyRequest",
            "RegisterAnonymousKeyResponse",
            # Clone keyring persistence.
            "CloneOwnerPin",
            "CloneAuthorizationKeyring",
            # Owner-signed spool governance.
            "GovernanceStateHead",
            "GovernanceSettingMergePolicy",
            "OwnerGovernanceState",
            "SignedOwnerGovernanceState",
            "GetOwnerGovernanceHeadRequest",
            "GetOwnerGovernanceHeadResponse",
            "SubmitOwnerGovernanceStateRequest",
            "SubmitOwnerGovernanceStateResponse",
        }
        actual_messages = set(
            re.findall(r"(?m)^message ([A-Za-z][A-Za-z0-9]*) \{", self.source)
        )
        self.assertTrue(expected_messages.issubset(actual_messages))

    def test_reviewed_field_names_types_and_tags_are_exact(self) -> None:
        expected_fields = {
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
                (
                    "repeated",
                    "AuthorizationSignature",
                    "recovery_key_proofs",
                    3,
                ),
            ],
            "NewPasskeyOwnerRootApproval": [
                ("", "bytes", "client_data_json", 1),
                ("", "bytes", "attestation_object", 2),
            ],
            "ExistingPasskeyOwnerRootApproval": [
                ("", "bytes", "credential_id", 1),
                ("", "bytes", "client_data_json", 2),
                ("", "bytes", "authenticator_data", 3),
                ("", "bytes", "signature", 4),
            ],
            "WebAuthnOwnerRootApproval": [
                ("", "string", "challenge_id", 1),
                ("", "NewPasskeyOwnerRootApproval", "new_passkey", 2),
                ("", "ExistingPasskeyOwnerRootApproval", "existing_passkey", 3),
            ],
            "DeferredOwnerRootApproval": [
                ("", "OwnerAuthorizationBundle", "provisioning_authority", 1),
                (
                    "",
                    "AuthorizationSignature",
                    "origin_key_request_signature",
                    2,
                ),
            ],
            "BootstrapOwnerRootRequest": [
                ("", "SignedOwnerRoot", "owner_root", 1),
                ("", "WebAuthnOwnerRootApproval", "human", 2),
                ("", "DeferredOwnerRootApproval", "deferred_human", 3),
                ("", "string", "client_operation_id", 4),
            ],
            "BootstrapOwnerRootResponse": [
                ("", "bytes", "owner_id", 1),
                ("", "bytes", "accepted_root_hash", 2),
            ],
            "OwnerKeyTransition": [
                ("", "uint32", "format_version", 1),
                ("", "bytes", "owner_id", 2),
                ("", "bytes", "previous_state_hash", 3),
                ("", "uint64", "sequence", 4),
                ("", "OwnerKeyTransitionKind", "kind", 5),
                ("", "AuthorizationVerificationKey", "next_authority_key", 6),
                ("", "RecoveryPolicy", "next_recovery_policy", 7),
                ("", "int64", "valid_from_unix_seconds", 8),
                ("", "int64", "previous_key_valid_until_unix_seconds", 9),
                ("", "bytes", "nonce", 10),
            ],
            "SignedOwnerKeyTransition": [
                ("", "OwnerKeyTransition", "transition", 1),
                ("repeated", "AuthorizationSignature", "authorizations", 2),
                ("", "AuthorizationSignature", "next_authority_key_proof", 3),
                (
                    "repeated",
                    "AuthorizationSignature",
                    "next_recovery_key_proofs",
                    4,
                ),
            ],
            "SpoolSelector": [
                ("", "bytes", "root_spool_uuid", 1),
                ("repeated", "string", "path_segments", 2),
                ("", "bool", "include_descendants", 3),
            ],
            "CapabilityPrincipal": [
                ("", "CapabilityPrincipalKind", "kind", 1),
                ("", "bytes", "principal_id", 2),
                ("", "AuthorizationVerificationKey", "key", 3),
            ],
            "SpoolCapabilityGrant": [
                ("", "SpoolSelector", "spool", 1),
                ("repeated", "SpoolCapabilityAction", "actions", 2),
            ],
            "OwnerCapability": [
                ("", "uint32", "format_version", 1),
                ("", "bytes", "owner_id", 2),
                ("", "bytes", "issuer_state_hash", 3),
                ("", "bytes", "parent_capability_id", 4),
                ("", "CapabilityPrincipal", "subject", 5),
                ("repeated", "SpoolCapabilityGrant", "grants", 6),
                ("", "int64", "not_before_unix_seconds", 7),
                ("", "int64", "expires_at_unix_seconds", 8),
                ("", "bytes", "nonce", 9),
                ("", "bytes", "capability_id", 10),
            ],
            "SignedOwnerCapability": [
                ("", "OwnerCapability", "capability", 1),
                ("", "AuthorizationSignature", "signature", 2),
            ],
            "OwnerAuthorizationBundle": [
                ("", "SignedOwnerRoot", "owner_root", 1),
                (
                    "repeated",
                    "SignedOwnerKeyTransition",
                    "owner_state_chain",
                    2,
                ),
                ("repeated", "SignedOwnerCapability", "capability_chain", 3),
                ("", "bytes", "subject_biscuit", 4),
            ],
            "SubmitOwnerAuthorizationRequest": [
                ("", "OwnerAuthorizationBundle", "authorization", 1),
                ("", "string", "client_operation_id", 2),
            ],
            "SubmitOwnerAuthorizationResponse": [
                ("", "bytes", "capability_id", 1),
                ("", "int64", "expires_at_unix_seconds", 2),
            ],
            "AnonymousKeyCredential": [
                ("", "uint32", "format_version", 1),
                ("", "bytes", "anonymous_id", 2),
                ("", "AuthorizationVerificationKey", "key", 3),
                ("", "int64", "issued_at_unix_seconds", 4),
                ("", "int64", "expires_at_unix_seconds", 5),
                ("", "bytes", "nonce", 6),
                ("", "AuthorizationSignature", "self_signature", 7),
            ],
            "RegisterAnonymousKeyRequest": [
                ("", "AnonymousKeyCredential", "credential", 1),
                ("optional", "string", "turnstile_token", 2),
                ("", "string", "prior_continuity_token", 3),
                ("", "AuthorizationSignature", "continuity_proof", 4),
                ("", "string", "client_operation_id", 5),
            ],
            "RegisterAnonymousKeyResponse": [
                ("", "bytes", "anonymous_id", 1),
                ("", "string", "continuity_token", 2),
                ("", "int64", "continuity_expires_at_unix_seconds", 3),
            ],
            "CloneOwnerPin": [
                ("", "CloneOwnerPinKind", "kind", 1),
                ("", "bytes", "expected_owner_id", 2),
                ("", "int64", "first_seen_unix_seconds", 3),
            ],
            "CloneAuthorizationKeyring": [
                ("", "uint32", "format_version", 1),
                ("", "bytes", "spool_uuid", 2),
                ("repeated", "string", "canonical_spool_path_segments", 3),
                ("", "CloneOwnerPin", "pin", 4),
                ("", "SignedOwnerRoot", "owner_root", 5),
                (
                    "repeated",
                    "SignedOwnerKeyTransition",
                    "accepted_transitions",
                    6,
                ),
                ("", "bytes", "accepted_state_hash", 7),
                (
                    "repeated",
                    "SignedOwnerCapability",
                    "public_access_capabilities",
                    8,
                ),
                ("", "bytes", "stable_owner_uuid", 9),
                ("", "OwnerKeyBinding", "initial_key_binding", 10),
                (
                    "repeated",
                    "ResourceTransferAuditRecord",
                    "ownership_transfers",
                    11,
                ),
            ],
            "GovernanceStateHead": [
                ("", "bytes", "state_hash", 1),
                ("", "uint64", "sequence", 2),
            ],
            "GovernanceSettingMergePolicy": [
                ("", "string", "setting_key", 1),
                ("", "GovernanceSettingMergeSemantics", "semantics", 2),
            ],
            "OwnerGovernanceState": [
                ("", "uint32", "format_version", 1),
                ("", "bytes", "spool_uuid", 2),
                ("", "GovernanceStateHead", "expected_head", 3),
                ("", "uint64", "sequence", 4),
                ("repeated", "bytes", "merge_parent_state_hashes", 5),
                ("", "SpoolSettings", "settings", 6),
                (
                    "repeated",
                    "GovernanceSettingMergePolicy",
                    "merge_policies",
                    7,
                ),
                ("", "bytes", "owner_state_hash", 8),
                ("", "bytes", "governance_state_hash", 9),
            ],
            "SignedOwnerGovernanceState": [
                ("", "OwnerGovernanceState", "state", 1),
                ("", "AuthorizationSignature", "owner_signature", 2),
            ],
            "GetOwnerGovernanceHeadRequest": [
                ("", "bytes", "spool_uuid", 1),
            ],
            "GetOwnerGovernanceHeadResponse": [
                ("", "bytes", "spool_uuid", 1),
                ("", "GovernanceStateHead", "head", 2),
                ("", "bytes", "owner_state_hash", 3),
            ],
            "SubmitOwnerGovernanceStateRequest": [
                ("", "SignedOwnerGovernanceState", "governance_state", 1),
                ("", "string", "client_operation_id", 2),
            ],
            "SubmitOwnerGovernanceStateResponse": [
                ("", "GovernanceStateHead", "accepted_head", 1),
            ],
        }
        actual_messages = set(
            re.findall(r"(?m)^message ([A-Za-z][A-Za-z0-9]*) \{", self.source)
        )
        self.assertTrue(set(expected_fields).issubset(actual_messages))
        for message, expected in expected_fields.items():
            with self.subTest(message=message):
                self.assertEqual(fields(self.source, message), expected)

    def test_reviewed_enum_values_are_exact(self) -> None:
        expected = {
            "AuthorizationKeyAlgorithm": [
                ("AUTHORIZATION_KEY_ALGORITHM_UNSPECIFIED", 0),
                ("AUTHORIZATION_KEY_ALGORITHM_ED25519", 1),
            ],
            "RecoveryGuardianKind": [
                ("RECOVERY_GUARDIAN_KIND_UNSPECIFIED", 0),
                ("RECOVERY_GUARDIAN_KIND_PAPER", 1),
                ("RECOVERY_GUARDIAN_KIND_SOCIAL", 2),
                ("RECOVERY_GUARDIAN_KIND_WEFT", 3),
            ],
            "OwnerKeyTransitionKind": [
                ("OWNER_KEY_TRANSITION_KIND_UNSPECIFIED", 0),
                ("OWNER_KEY_TRANSITION_KIND_ROTATE", 1),
                ("OWNER_KEY_TRANSITION_KIND_RECOVER", 2),
                ("OWNER_KEY_TRANSITION_KIND_RECOVERY_POLICY", 3),
                ("OWNER_KEY_TRANSITION_KIND_CLAIM_DEFERRED_HUMAN", 4),
            ],
            "CapabilityPrincipalKind": [
                ("CAPABILITY_PRINCIPAL_KIND_UNSPECIFIED", 0),
                ("CAPABILITY_PRINCIPAL_KIND_HUMAN_DEVICE", 1),
                ("CAPABILITY_PRINCIPAL_KIND_SERVICE_ACCOUNT", 2),
                ("CAPABILITY_PRINCIPAL_KIND_AGENT", 3),
                ("CAPABILITY_PRINCIPAL_KIND_ANONYMOUS_KEY", 4),
                ("CAPABILITY_PRINCIPAL_KIND_ANY_ANONYMOUS", 5),
            ],
            "SpoolCapabilityAction": [
                ("SPOOL_CAPABILITY_ACTION_UNSPECIFIED", 0),
                ("SPOOL_CAPABILITY_ACTION_READ", 1),
                ("SPOOL_CAPABILITY_ACTION_WRITE", 2),
                ("SPOOL_CAPABILITY_ACTION_MERGE", 3),
                ("SPOOL_CAPABILITY_ACTION_APPROVE", 4),
                ("SPOOL_CAPABILITY_ACTION_ADMIN", 5),
                ("SPOOL_CAPABILITY_ACTION_REDACT", 6),
                ("SPOOL_CAPABILITY_ACTION_GRANT", 7),
                ("SPOOL_CAPABILITY_ACTION_PURGE", 8),
                ("SPOOL_CAPABILITY_ACTION_VISIBILITY", 9),
                ("SPOOL_CAPABILITY_ACTION_METADATA_SUPERSESSION", 10),
            ],
            "CloneOwnerPinKind": [
                ("CLONE_OWNER_PIN_KIND_UNSPECIFIED", 0),
                ("CLONE_OWNER_PIN_KIND_LOCAL_CREATION", 1),
                ("CLONE_OWNER_PIN_KIND_INVITATION_FINGERPRINT", 2),
                ("CLONE_OWNER_PIN_KIND_CLONE_TOFU", 3),
            ],
            "GovernanceSettingMergeSemantics": [
                ("GOVERNANCE_SETTING_MERGE_SEMANTICS_UNSPECIFIED", 0),
                ("GOVERNANCE_SETTING_MERGE_SEMANTICS_LAST_WRITER_WINS", 1),
                ("GOVERNANCE_SETTING_MERGE_SEMANTICS_GROW_ONLY_SET_UNION", 2),
            ],
        }
        actual_enums = set(
            re.findall(r"(?m)^enum ([A-Za-z][A-Za-z0-9]*) \{", self.source)
        )
        self.assertTrue(set(expected).issubset(actual_enums))
        for enum, values in expected.items():
            with self.subTest(enum=enum):
                self.assertEqual(enum_values(self.source, enum), values)

    def test_recovery_guardians_are_distinguishable_on_the_wire(self) -> None:
        guardian_kinds = enum_body(self.source, "RecoveryGuardianKind")
        for kind in ("PAPER", "SOCIAL", "WEFT"):
            self.assertIn(f"RECOVERY_GUARDIAN_KIND_{kind}", guardian_kinds)

        guardian = message_body(self.source, "RecoveryGuardian")
        policy = message_body(self.source, "RecoveryPolicy")
        self.assertRegex(guardian, r"\bRecoveryGuardianKind\s+kind\s*=\s*1\s*;")
        self.assertRegex(
            guardian,
            r"\bAuthorizationVerificationKey\s+key\s*=\s*2\s*;",
        )
        self.assertRegex(
            policy,
            r"\brepeated\s+RecoveryGuardian\s+guardians\s*=\s*2\s*;",
        )

    def test_clean_cutover_contract_has_no_legacy_runtime_mode(self) -> None:
        all_proto_source = "\n".join(
            path.read_text() for path in sorted(PROTO_ROOT.glob("*.proto"))
        )
        for legacy_surface in (
            "LEGACY_ONLY",
            "OWNER_ANCHORED_ONLY",
            "TRUST_ON_FIRST_USE",
        ):
            self.assertNotIn(legacy_surface, all_proto_source)

    def test_owner_anchored_messages_are_reachable_from_typed_rpcs(self) -> None:
        self.assertRegex(
            self.owner_source, r"(?m)^service OwnerAuthorizationService\s+\{"
        )
        methods = set(re.findall(r"(?m)^\s*rpc\s+(\w+)", self.owner_source))
        self.assertEqual(
            methods,
            {
                "BootstrapOwnerRoot",
                "RotateOwnerKey",
                "RecoverOwnerKey",
                "ChangeOwnerRecoveryPolicy",
                "GetCurrentOwnerKeyring",
                "BeginAgentOwnerClaim",
                "ClaimAgentOwner",
                "SubmitOwnerAuthorization",
                "TransferResourceOwnership",
            },
        )
        importers = {
            path.name
            for path in sorted(PROTO_ROOT.glob("*.proto"))
            if path != OWNER_AUTHORIZATION_PROTO
            and "heddle/api/v1alpha1/owner_authorization.proto" in path.read_text()
        }
        self.assertTrue(
            {"repo_sync.proto", "service.proto"}.issubset(importers)
        )

    def test_governance_messages_cannot_authorize_anything_on_their_own(self) -> None:
        governance_messages = (
            "GovernanceStateHead",
            "GovernanceSettingMergePolicy",
            "OwnerGovernanceState",
            "SignedOwnerGovernanceState",
            "GetOwnerGovernanceHeadRequest",
            "GetOwnerGovernanceHeadResponse",
            "SubmitOwnerGovernanceStateRequest",
            "SubmitOwnerGovernanceStateResponse",
        )
        for name in governance_messages:
            with self.subTest(message=name):
                body = message_body(self.governance_source, name)
                self.assertNotRegex(body, r"\b(?:bearer|grant_envelope)\b")

        self.assertNotRegex(self.governance_source, r"(?m)^service\s+")
        self.assertNotRegex(self.governance_source, r"(?m)^\s*rpc\s+")

    def test_grow_only_merge_is_distinct_from_last_writer_wins_on_the_wire(
        self,
    ) -> None:
        policies = enum_body(self.source, "GovernanceSettingMergeSemantics")
        self.assertIn(
            "GOVERNANCE_SETTING_MERGE_SEMANTICS_LAST_WRITER_WINS",
            policies,
        )
        self.assertIn(
            "GOVERNANCE_SETTING_MERGE_SEMANTICS_GROW_ONLY_SET_UNION",
            policies,
        )
        policy = message_body(self.source, "GovernanceSettingMergePolicy")
        self.assertRegex(policy, r"\bstring\s+setting_key\s*=\s*1\s*;")
        self.assertRegex(
            policy,
            r"\bGovernanceSettingMergeSemantics\s+semantics\s*=\s*2\s*;",
        )

    def test_contract_carries_no_private_or_server_authorization_key(self) -> None:
        field_names = re.findall(
            r"(?m)^\s*(?:optional\s+|repeated\s+)?"
            r"(?:bytes|AuthorizationVerificationKey)\s+(\w+)\s*=",
            self.source,
        )
        forbidden_fields = {
            "private_key",
            "server_signing_key",
            "server_verification_key",
            "server_authorization_key",
            "minting_key",
            "root_signing_key",
        }
        self.assertTrue(forbidden_fields.isdisjoint(field_names))


if __name__ == "__main__":
    unittest.main()
