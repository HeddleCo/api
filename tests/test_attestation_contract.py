from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parent.parent
ATTESTATION_PROTO = ROOT / "proto/heddle/api/v1alpha1/attestation.proto"


def message_body(source: str, name: str) -> str:
    match = re.search(rf"(?ms)^message {re.escape(name)} \{{(.*?)^\}}", source)
    if match is None:
        raise AssertionError(f"missing message {name}")
    return match.group(1)


class AttestationContractTest(unittest.TestCase):
    def test_record_and_verify_carry_the_security_bindings(self) -> None:
        self.assertTrue(
            ATTESTATION_PROTO.exists(), "missing canonical attestation.proto"
        )
        source = ATTESTATION_PROTO.read_text()

        artifact = message_body(source, "ArtifactRef")
        record = message_body(source, "RecordSignatureRequest")
        verify = message_body(source, "VerifySignatureRequest")
        signature = message_body(source, "VerifiedArtifactSignature")

        self.assertRegex(artifact, r"\bstring\s+kind\s*=")
        self.assertRegex(artifact, r"\bbytes\s+digest\s*=")
        self.assertRegex(record, r"\bRepositoryRef\s+repo_path\s*=")
        self.assertRegex(record, r"\bArtifactRef\s+artifact\s*=")
        self.assertRegex(record, r"\bbytes\s+biscuit_envelope\s*=")
        self.assertRegex(record, r"\bbytes\s+signer_public_key\s*=")
        self.assertRegex(record, r"\bstring\s+client_operation_id\s*=")
        self.assertRegex(verify, r"\bRepositoryRef\s+repo_path\s*=")
        self.assertRegex(verify, r"\bArtifactRef\s+artifact\s*=")
        self.assertRegex(signature, r"\bSignatureActorKind\s+actor_kind\s*=")

    def test_contract_names_the_replay_and_identity_guards(self) -> None:
        source = ATTESTATION_PROTO.read_text()
        self.assertIn("must exactly match the authenticated repository", source)
        self.assertIn("must exactly match `artifact`", source)
        self.assertIn("never accepted from a client-supplied flag", source)
        self.assertIn("(artifact, signer)", source)

    def test_record_is_a_distinct_privilege_granting_operation(self) -> None:
        source = ATTESTATION_PROTO.read_text()
        self.assertRegex(
            source,
            r"rpc\s+RecordSignature\(RecordSignatureRequest\)\s+returns\s+\(SignatureReceipt\)",
        )
        self.assertRegex(
            source,
            r"rpc\s+VerifySignature\(VerifySignatureRequest\)\s+returns\s+\(SignatureChain\)",
        )
        record_rpc = re.search(
            r"(?ms)rpc RecordSignature\(.*?^\s*\}", source
        )
        self.assertIsNotNone(record_rpc)
        self.assertIn("SIGNING_TIER_PROOF_OF_POSSESSION", record_rpc.group(0))
        self.assertIn("RPC_EFFECT_DURABLE_WRITE", record_rpc.group(0))
        self.assertIn("AUTHORIZATION_ROLE_RESOURCE_WRITER", record_rpc.group(0))


if __name__ == "__main__":
    unittest.main()
