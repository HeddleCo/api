from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parent.parent
PROTO = ROOT / "proto/heddle/api/v1alpha2"
OWNER = (PROTO / "owner_records.proto").read_text()
IDENTITY = (PROTO / "identity.proto").read_text()
ADMINISTRATION = (PROTO / "administration.proto").read_text()
VIEWS = (PROTO / "views.proto").read_text()
SYNC = (PROTO / "sync.proto").read_text()
ATTACHMENTS = (ROOT / "proto/heddle/api/common/attachments.proto").read_text()


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
    def test_guardian_default_and_custody_consent_are_distinct(self) -> None:
        selection = block(OWNER, "message", "RegistrationRecoveryPolicy")
        self.assertRegex(
            selection, r"GuardianRecoveryPolicySelection\s+guardians\s*=\s*1\s*;"
        )
        self.assertRegex(
            selection,
            r"WeftCustodyRecoveryPolicySelection\s+weft_custody\s*=\s*2\s*;",
        )
        self.assertEqual(
            fields(OWNER, "WeftCustodyWarningConsent"),
            [
                ("warning_version", 1),
                ("warning_sha256", 2),
                ("acknowledged_at_unix_seconds", 3),
            ],
        )
        registration = block(IDENTITY, "message", "OwnerRegistration")
        self.assertRegex(
            registration, r"RegistrationRecoveryPolicy\s+recovery\s*=\s*4\s*;"
        )

    def test_every_attachment_kind_has_spool_write_classification(self) -> None:
        enum = block(ATTACHMENTS, "enum", "StateAttachmentKind")
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

    def test_spool_creation_and_fetch_carry_self_signed_genesis(self) -> None:
        self.assertEqual(
            fields(OWNER, "SpoolOwnerGenesis"),
            [("spool_uuid", 1), ("owner_public_key", 2)],
        )
        self.assertEqual(
            fields(OWNER, "SignedSpoolOwnerGenesis"),
            [("genesis", 1), ("owner_signature", 2), ("delegated_creation", 3)],
        )
        self.assertIn(
            ("owner_genesis", 5), fields(ADMINISTRATION, "CreateSpoolRequest")
        )
        self.assertIn(("owner_genesis", 10), fields(VIEWS, "SpoolOverview"))
        ready = fields(SYNC, "TransferReady")
        self.assertIn(("owner_genesis", 5), ready)
        self.assertIn(("ownership", 15), ready)
        self.assertIn(("thread_genesis", 16), ready)

    def test_canonical_purge_body_and_owner_chain_are_explicit(self) -> None:
        self.assertEqual(
            fields(OWNER, "PurgeOperationSigningBody"),
            [
                ("format_version", 1),
                ("spool_uuid", 2),
                ("purge_identity", 3),
                ("payload_sha256", 4),
                ("leaf_capability_id", 5),
            ],
        )
        authorization = block(OWNER, "message", "SidecarAuthorization")
        self.assertRegex(
            authorization,
            r"OwnerAuthorizationBundle\s+capability\s*=\s*1\s*;",
        )
        self.assertRegex(
            authorization,
            r"AuthorizationSignature\s+operation_signature\s*=\s*2\s*;",
        )
        self.assertIn("heddle-purge-operation-v2", OWNER)
        self.assertNotIn("SidecarOperationSigningBody", OWNER)

    def test_owner_capability_action_set_is_purge_only(self) -> None:
        actions = block(OWNER, "enum", "SpoolCapabilityAction")
        self.assertEqual(
            re.findall(
                r"(?m)^\s*(SPOOL_CAPABILITY_ACTION_[A-Z_]+)\s*=\s*(\d+)", actions
            ),
            [
                ("SPOOL_CAPABILITY_ACTION_UNSPECIFIED", "0"),
                ("SPOOL_CAPABILITY_ACTION_PURGE", "1"),
            ],
        )
        transfer = block(SYNC, "message", "TransferSidecar")
        self.assertIn("PURGE requires the independently verified owner", transfer)
        self.assertIn("Ordinary write cannot satisfy that requirement", transfer)

    def test_owner_uuid_binding_and_transfer_are_complete(self) -> None:
        self.assertEqual(
            fields(OWNER, "OwnerKeyBinding"),
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
        self.assertEqual(
            fields(OWNER, "ResourceTransferHandoff"),
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
        keyring = fields(OWNER, "CloneAuthorizationKeyring")
        self.assertIn(("ownership_transfers", 9), keyring)
        self.assertIn(("transfer_owner_histories", 10), keyring)


if __name__ == "__main__":
    unittest.main()
