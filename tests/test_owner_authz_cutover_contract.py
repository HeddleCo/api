from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parent.parent
PROTO = ROOT / "proto/heddle/api/v1alpha1"


def block(source: str, kind: str, name: str) -> str:
    match = re.search(rf"(?ms)^{kind} {re.escape(name)} \{{(.*?)^\}}", source)
    if match is None:
        raise AssertionError(f"missing {kind} {name}")
    return match.group(1)


def fields(source: str, name: str) -> list[tuple[str, int]]:
    return [
        (field, int(tag))
        for field, tag in re.findall(
            r"(?m)^\s*(?:optional\s+|repeated\s+)?[.A-Za-z][.A-Za-z0-9]*\s+"
            r"([a-z][a-z0-9_]*)\s*=\s*(\d+)",
            block(source, "message", name),
        )
    ]


class OwnerAuthzCutoverContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.owner = (PROTO / "owner_authorization.proto").read_text()
        cls.identity = (PROTO / "identity.proto").read_text()
        cls.registry = (PROTO / "registry.proto").read_text()
        cls.sync = (PROTO / "repo_sync.proto").read_text()
        cls.service = (PROTO / "service.proto").read_text()

    def test_existing_fields_remain_and_new_fields_are_appended(self) -> None:
        register = fields(self.identity, "RegisterPublicKeyRequest")
        self.assertEqual(register[:11], [(name, tag) for name, tag in [
            ("challenge_id", 1),
            ("client_data_json", 2),
            ("attestation_object", 3),
            ("device_label", 4),
            ("device_public_key", 5),
            ("client_operation_id", 6),
            ("device_binding_client_data_json", 7),
            ("device_binding_authenticator_data", 8),
            ("device_binding_signature", 9),
            ("attesting_pubkey", 10),
            ("cross_device_attestation", 11),
        ]])
        self.assertEqual(
            register[11:],
            [
                ("owner_root", 12),
                ("owner_root_proof_of_possession", 13),
                ("owner_recovery_policy", 14),
                ("owner_key_binding", 15),
                ("claim_deferred_human", 16),
                ("biscuit_authority_public_key", 17),
                ("device_proof_public_key", 18),
            ],
        )
        self.assertEqual(
            fields(self.sync, "RedactionTransfer"),
            [("blob_hash", 1), ("redactions_blob", 2)],
        )
        self.assertEqual(
            fields(self.sync, "StateVisibilityTransfer"),
            [("state_id", 1), ("state_visibility_blob", 2)],
        )
        self.assertEqual(
            fields(self.sync, "StateAttachmentTransfer"),
            [
                ("state_id", 1),
                ("attachment_id", 2),
                ("attachment_kind", 3),
                ("attachment_object", 4),
            ],
        )
        self.assertEqual(
            fields(self.sync, "PurgeTransfer"),
            [("blob_hash", 1), ("redactions_blob", 2), ("authorization", 3)],
        )

    def test_guardian_default_and_custody_consent_are_distinct(self) -> None:
        selection = block(self.owner, "message", "RegistrationRecoveryPolicy")
        self.assertRegex(
            selection,
            r"GuardianRecoveryPolicySelection\s+guardians\s*=\s*1\s*;",
        )
        self.assertRegex(
            selection,
            r"WeftCustodyRecoveryPolicySelection\s+weft_custody\s*=\s*2\s*;",
        )
        consent = fields(self.owner, "WeftCustodyWarningConsent")
        self.assertEqual(
            consent,
            [
                ("warning_version", 1),
                ("warning_sha256", 2),
                ("acknowledged_at_unix_seconds", 3),
            ],
        )
        register = block(self.identity, "message", "RegisterPublicKeyRequest")
        self.assertIn("omission never selects custody", register)

    def test_recovery_window_is_per_user_not_per_method(self) -> None:
        self.assertNotIn(
            "window_secs",
            dict(fields(self.identity, "DeclareHardwareKeyRecoveryParams")),
        )
        self.assertIn(
            ("window_secs", 2),
            fields(self.identity, "BeginRecoveryResponse"),
        )
        policy = block(self.owner, "message", "RecoveryPolicy")
        self.assertRegex(policy, r"optional\s+uint64\s+window_secs\s*=\s*3\s*;")
        self.assertIn("604800", policy)

    def test_owner_uuid_binding_claim_and_transfer_are_complete(self) -> None:
        self.assertEqual(
            fields(self.owner, "OwnerKeyBinding"),
            [
                ("format_version", 1),
                ("stable_owner_uuid", 2),
                ("root_public_key", 3),
                ("root_state_hash", 4),
                ("kind", 5),
                ("binding_epoch", 6),
                ("challenge_nonce", 7),
                ("root_proof_of_possession", 8),
            ],
        )
        self.assertNotIn("registry_attestation", self.owner)
        self.assertEqual(
            fields(self.owner, "ResourceTransferHandoff"),
            [
                ("format_version", 1),
                ("resource_uuid", 2),
                ("transfer_sequence", 3),
                ("source_owner_uuid", 4),
                ("source_owner_key_state_hash", 5),
                ("destination_owner_uuid", 6),
                ("destination_owner_key_state_hash", 7),
                ("nonce", 8),
            ],
        )
        for message in (
            "OwnerClaimChallenge",
            "ClaimAgentOwnerRequest",
            "ResourceTransferAcceptance",
            "ResourceTransferAuditRecord",
        ):
            self.assertRegex(self.owner, rf"(?m)^message {message} \{{")

    def test_service_descriptor_routes_every_required_owner_flow(self) -> None:
        methods = set(re.findall(r"(?m)^\s*rpc\s+(\w+)", self.owner))
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
        self.assertIn(
            'import public "heddle/api/v1alpha1/owner_authorization.proto";',
            self.service,
        )

    def test_every_attachment_kind_has_generated_spool_write_classification(self) -> None:
        enum = block(self.sync, "enum", "StateAttachmentKind")
        values = re.findall(
            r"(?ms)^\s*(STATE_ATTACHMENT_KIND_[A-Z0-9_]+)\s*=\s*(\d+)\s*"
            r"(\[[^;]+\])?\s*;",
            enum,
        )
        self.assertGreater(len(values), 1)
        for name, number, options in values:
            if int(number) == 0:
                continue
            with self.subTest(kind=name):
                self.assertIn(
                    "STATE_ATTACHMENT_AUTHORIZATION_CLASSIFICATION_SPOOL_WRITE",
                    options,
                )

    def test_spool_creation_and_pull_ready_carry_self_signed_genesis(self) -> None:
        self.assertEqual(
            fields(self.owner, "SpoolOwnerGenesis"),
            [("spool_uuid", 1), ("owner_public_key", 2)],
        )
        self.assertEqual(
            fields(self.owner, "SignedSpoolOwnerGenesis"),
            [("genesis", 1), ("owner_signature", 2)],
        )
        self.assertIn(("owner_genesis", 8), fields(self.registry, "CreateSpoolRequest"))
        self.assertIn(("owner_genesis", 10), fields(self.registry, "HostedSpool"))
        ready = fields(self.sync, "PullReady")
        self.assertEqual(
            ready[-2:],
            [
                ("owner_authorization_protocol_version", 9),
                ("owner_genesis", 10),
            ],
        )
        frame = block(self.sync, "message", "PullServerFrame")
        self.assertRegex(
            frame,
            r"StateAttachmentTransfer\s+state_attachment\s*=\s*9\s*;",
        )

    def test_token_owner_bundle_is_typed_and_grant_envelope_v2_stays_live(self) -> None:
        token = block(self.identity, "message", "AccessTokenResponse")
        self.assertRegex(token, r"bytes\s+grant_envelope\s*=\s*7\s*;")
        self.assertNotRegex(token, r"grant_envelope\s*=\s*7\s*\[deprecated")
        self.assertRegex(
            token,
            r"OwnerAuthorizationBundle\s+owner_authorization\s*=\s*8\s*;",
        )
        self.assertRegex(token, r"string\s+device_id\s*=\s*9\s*;")
        self.assertIn("not owner authority", token)
        self.assertIn("format_version (MUST equal 0x02; this byte is signed)", token)
        self.assertIn("MUST reject the one-key v1 envelope", token)
        self.assertIn("purge-only bundle", token)
        self.assertIn("mint input, not capability", token)
        self.assertIn("MintParams.device_id", token)
        self.assertIn("device_roots.id", token)
        session = block(self.identity, "message", "ActiveSession")
        self.assertRegex(
            session,
            r"OwnerAuthorizationBundle\s+owner_authorization\s*=\s*8\s*;",
        )

    def test_canonical_purge_body_and_limits_are_explicit(self) -> None:
        body = block(self.sync, "message", "PurgeOperationSigningBody")
        self.assertEqual(
            fields(self.sync, "PurgeOperationSigningBody"),
            [
                ("format_version", 1),
                ("spool_uuid", 2),
                ("purge_identity", 3),
                ("payload_sha256", 4),
                ("leaf_capability_id", 5),
            ],
        )
        for required in (
            "heddle-purge-operation-v2",
            "1,048,576 bytes",
            "capability_chain 1..64",
            "raw purge payload <= 67,108,864 bytes",
        ):
            self.assertIn(required, self.sync)
        self.assertNotIn("SidecarOperationSigningBody", self.sync)

    def test_owner_capability_action_set_is_purge_only(self) -> None:
        actions = block(self.owner, "enum", "SpoolCapabilityAction")
        self.assertEqual(
            re.findall(r"(?m)^\s*(SPOOL_CAPABILITY_ACTION_[A-Z_]+)\s*=\s*(\d+)", actions),
            [
                ("SPOOL_CAPABILITY_ACTION_UNSPECIFIED", "0"),
                ("SPOOL_CAPABILITY_ACTION_PURGE", "1"),
            ],
        )
        self.assertNotIn("METADATA_SUPERSESSION", self.owner + self.sync)
        self.assertNotIn("public_access_capabilities", self.owner)
        for message in ("RedactionTransfer", "StateVisibilityTransfer", "StateAttachmentTransfer"):
            self.assertNotIn("authorization", dict(fields(self.sync, message)))
        self.assertIn("authorization", dict(fields(self.sync, "PurgeTransfer")))


if __name__ == "__main__":
    unittest.main()
