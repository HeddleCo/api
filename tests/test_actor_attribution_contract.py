from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parent.parent
REPOSITORY_PROTO = ROOT / "proto/heddle/api/v1alpha1/repository.proto"


def message_body(source: str, name: str) -> str:
    match = re.search(rf"(?ms)^message {re.escape(name)} \{{(.*?)^\}}", source)
    if match is None:
        raise AssertionError(f"missing message {name}")
    return match.group(1)


class ActorAttributionContractTest(unittest.TestCase):
    def test_repo_event_keeps_root_subject_and_adds_delegation_agent_id(self) -> None:
        event = message_body(REPOSITORY_PROTO.read_text(), "RepoEvent")

        self.assertRegex(event, r"\bstring\s+actor_subject\s*=\s*9\s*;")
        self.assertRegex(event, r"\bstring\s+actor_agent_id\s*=\s*14\s*;")
        self.assertIn("Empty for", event)
        self.assertIn("actor_subject remains the root subject", event)


if __name__ == "__main__":
    unittest.main()
