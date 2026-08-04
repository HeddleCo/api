from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PROTO = ROOT / "proto/heddle/api/v1alpha1/registry.proto"


def block_body(source: str, kind: str, name: str) -> str:
    match = re.search(
        rf"(?ms)^{re.escape(kind)} {re.escape(name)} \{{(.*?)^\}}", source
    )
    if match is None:
        raise AssertionError(f"missing {kind} {name}")
    return match.group(1)


class ExploreContractTest(unittest.TestCase):
    def test_bulk_rpc_exposes_inputs_without_server_scoring_policy(self) -> None:
        source = REGISTRY_PROTO.read_text()
        metadata = block_body(source, "message", "ExploreMetadata")
        service = block_body(source, "service", "RegistryService")

        for field in (
            "continuity",
            "verification",
            "collaboration",
            "thread",
            "clarity",
            "burst_factor",
            "latest_state_at",
            "oldest_state_at",
        ):
            self.assertRegex(metadata, rf"\b{field}\s*=")
        self.assertNotRegex(metadata, r"\b(?:recency|score|lane)\s*=")
        self.assertRegex(
            service,
            r"rpc ListExploreMetadata\(ListExploreMetadataRequest\) "
            r"returns \(ListExploreMetadataResponse\)",
        )
        rpc = re.search(
            r"(?ms)rpc ListExploreMetadata\(.*?\n  \}", service
        )
        self.assertIsNotNone(rpc)
        self.assertIn("AUTHORIZATION_ACCESS_PUBLIC", rpc.group(0))
        self.assertIn("RPC_EFFECT_READ_ONLY", rpc.group(0))


if __name__ == "__main__":
    unittest.main()
