from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parent.parent
ACTIVITY = (ROOT / "proto/heddle/api/v1alpha2/activity.proto").read_text()
SERVICES = (ROOT / "proto/heddle/api/v1alpha2/services.proto").read_text()


def body(source: str, kind: str, name: str) -> str:
    match = re.search(rf"(?ms)^{kind} {re.escape(name)} \{{(.*?)^\}}", source)
    if match is None:
        raise AssertionError(f"missing {kind} {name}")
    return match.group(1)


class AttestationContractTest(unittest.TestCase):
    def test_evidence_record_carries_signed_security_bindings(self) -> None:
        record = body(ACTIVITY, "message", "EvidenceRecord")
        for field, tag in (
            ("RecordRef ref", 1),
            ("RevisionRef revision", 3),
            ("string check", 4),
            ("SignedRecord evidence", 5),
            ("CheckEvidenceSummary summary", 7),
            ("ThreadRef thread", 8),
        ):
            self.assertRegex(record, rf"\b{re.escape(field)}\s*=\s*{tag}\s*;")
        for binding in (
            "this ID",
            "Spool",
            "original Thread",
            "native revision",
            "original actor/authority",
            "completion time",
        ):
            self.assertIn(binding, record)
        self.assertIn("Signature validity alone", record)

    def test_record_and_verify_use_distinct_request_shapes(self) -> None:
        record = body(ACTIVITY, "message", "RecordEvidenceRequest")
        verify = body(ACTIVITY, "message", "VerifyEvidenceRequest")
        result = body(ACTIVITY, "message", "EvidenceVerification")
        self.assertRegex(record, r"\bstring\s+client_operation_id\s*=\s*1\s*;")
        self.assertRegex(record, r"\bEvidenceRecord\s+evidence\s*=\s*2\s*;")
        self.assertRegex(verify, r"\brepeated\s+EvidenceRecord\s+evidence\s*=\s*1\s*;")
        self.assertRegex(result, r"\bbool\s+verified\s*=\s*2\s*;")
        self.assertRegex(result, r"\brepeated\s+Requirement\s+requirements\s*=\s*3\s*;")

    def test_record_is_a_distinct_privilege_granting_operation(self) -> None:
        service = body(SERVICES, "service", "EvidenceService")
        self.assertRegex(
            service,
            r"rpc RecordEvidence\(RecordEvidenceRequest\) returns \(MutationResponse\)",
        )
        self.assertRegex(
            service,
            r"rpc VerifyEvidence\(VerifyEvidenceRequest\) returns "
            r"\(VerifyEvidenceResponse\)",
        )
        record = re.search(r"(?ms)rpc RecordEvidence\(.*?^  \}", service)
        verify = re.search(r"(?ms)rpc VerifyEvidence\(.*?^  \}", service)
        self.assertIsNotNone(record)
        self.assertIsNotNone(verify)
        self.assertIn("SIGNING_TIER_PROOF_OF_POSSESSION", record.group(0))
        self.assertIn("RPC_EFFECT_DURABLE_WRITE", record.group(0))
        self.assertIn("AUTHORIZATION_ROLE_RESOURCE_WRITER", record.group(0))
        self.assertIn("RPC_EFFECT_READ_ONLY", verify.group(0))
        self.assertIn("RETRY_BEHAVIOR_SAFE", verify.group(0))


if __name__ == "__main__":
    unittest.main()
