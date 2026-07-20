from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parent.parent
CONTRACT = ROOT / "proto/heddle/api/v1alpha1/contract.proto"
ERRORS = ROOT / "proto/heddle/api/v1alpha1/errors.proto"


class TransportContractTest(unittest.TestCase):
    def test_rust_package_has_no_tonic_generation_or_features(self) -> None:
        cargo = (ROOT / "Cargo.toml").read_text()
        build = (ROOT / "build.rs").read_text()
        self.assertNotRegex(cargo, r"(?m)^tonic(?:-prost)?\s*=")
        self.assertNotRegex(cargo, r"(?m)^(?:client|server)\s*=")
        self.assertNotIn("tonic", build)

    def test_call_context_owns_every_cross_transport_field(self) -> None:
        source = CONTRACT.read_text()
        body = re.search(r"(?ms)^message CallContext \{(.*?)^\}", source)
        self.assertIsNotNone(body)
        for field in (
            "deadline",
            "bearer_capability",
            "bearer_proof",
            "request_proof",
            "human_verification",
            "client_operation_id",
            "trace",
        ):
            self.assertRegex(body.group(1), rf"\b{field}\s*=")

    def test_failure_vocabulary_has_no_grpc_field(self) -> None:
        source = ERRORS.read_text()
        self.assertIn("message CallFailure", source)
        self.assertIn("CallFailureCode code = 1", source)
        self.assertNotIn("grpc_code", source)

    def test_production_alpn_and_cross_product_fixture_are_checked_in(self) -> None:
        transport = (ROOT / "src/transport.rs").read_text()
        self.assertIn('b"heddle-api/1"', transport)
        self.assertTrue((ROOT / "tests/fixtures/hosted-call-v1.json").exists())


if __name__ == "__main__":
    unittest.main()
