from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parent.parent
COLLABORATION = (ROOT / "proto/heddle/api/v1alpha2/collaboration.proto").read_text()
INTEGRATION = (ROOT / "proto/heddle/api/v1alpha2/integration.proto").read_text()
ACTIVITY = (ROOT / "proto/heddle/api/v1alpha2/activity.proto").read_text()
SERVICES = (ROOT / "proto/heddle/api/v1alpha2/services.proto").read_text()
REPOSITORY = (ROOT / "proto/heddle/api/common/repository.proto").read_text()
ALL_V2 = "\n".join(
    path.read_text()
    for path in sorted((ROOT / "proto/heddle/api/v1alpha2").glob("*.proto"))
)


def body(source: str, kind: str, name: str) -> str:
    match = re.search(rf"(?ms)^{kind} {re.escape(name)} \{{(.*?)^\}}", source)
    if match is None:
        raise AssertionError(f"missing {kind} {name}")
    return match.group(1)


def fields(source: str, message: str) -> list[tuple[str, int]]:
    return [
        (name, int(tag))
        for name, tag in re.findall(
            r"(?m)^\s*(?:(?:optional|repeated)\s+)?[A-Za-z][A-Za-z0-9_.]*\s+"
            r"([a-z][a-z0-9_]*)\s*=\s*(\d+)\s*;",
            body(source, "message", message),
        )
    ]


class AdditiveBundleContractTest(unittest.TestCase):
    def test_discussion_writes_carry_explicit_scope_audience_and_signature(self) -> None:
        self.assertEqual(
            fields(COLLABORATION, "OpenDiscussionRequest"),
            [
                ("client_operation_id", 1),
                ("spool", 2),
                ("anchor", 3),
                ("title", 4),
                ("initial_body", 5),
                ("blocking", 6),
                ("signed_operation", 7),
                ("audience", 8),
                ("audience_label", 9),
            ],
        )
        request = body(COLLABORATION, "message", "OpenDiscussionRequest")
        self.assertIn("portable operation signature", request)
        self.assertIn("Required explicit audience", request)
        service = body(SERVICES, "service", "CollaborationService")
        rpc = re.search(r"(?ms)rpc OpenDiscussion\(.*?^  \}", service)
        self.assertIsNotNone(rpc)
        self.assertIn("RPC_EFFECT_DURABLE_WRITE", rpc.group(0))
        self.assertIn("client_operation_id_required: true", rpc.group(0))

    def test_discussion_turns_keep_actor_and_causal_identity(self) -> None:
        self.assertEqual(
            fields(COLLABORATION, "DiscussionTurn"),
            [
                ("ref", 1),
                ("discussion", 2),
                ("body", 3),
                ("principal_id", 4),
                ("agent_id", 5),
                ("mentions", 6),
                ("created_at", 7),
                ("causal_id", 8),
                ("causal_parents", 9),
            ],
        )
        event = body(COLLABORATION, "message", "CollaborationEvent")
        self.assertRegex(event, r"\bDiscussionTurn\s+turn\s*=\s*3\s*;")
        self.assertRegex(event, r"\bSignedRecord\s+operation\s*=\s*7\s*;")

    def test_provider_integration_is_provider_neutral_and_secret_safe(self) -> None:
        self.assertEqual(
            fields(INTEGRATION, "ProviderRepository"),
            [
                ("connection", 1),
                ("provider_repository_id", 2),
                ("clone_url", 3),
                ("name", 4),
                ("private", 5),
                ("installation_id", 6),
            ],
        )
        connection = body(INTEGRATION, "message", "ProviderConnection")
        self.assertNotRegex(connection, r"\b(?:access_token|authorization_code)\s*=")
        self.assertIn("contains no provider token or OAuth authorization code", connection)
        credential = body(INTEGRATION, "message", "StoreProviderCredentialRequest")
        self.assertRegex(credential, r"\bstring\s+access_token\s*=\s*3\s*;")
        self.assertIn("Never project or log this value", credential)

    def test_repo_event_kind_remains_available_from_common_repository_types(self) -> None:
        kinds = body(REPOSITORY, "enum", "RepoEventKind")
        self.assertIn("REPO_EVENT_KIND_UNSPECIFIED = 0", kinds)
        self.assertIn("REPO_EVENT_KIND_DISCUSSION_TURN = 1", kinds)
        event_fields = fields(REPOSITORY, "RepoEvent")
        self.assertIn(("actor_subject", 9), event_fields)
        self.assertIn(("actor_agent_id", 14), event_fields)
        self.assertIn(("kind", 15), event_fields)

    def test_notifications_are_recipient_owned_and_public_unsubscribe_is_bounded(self) -> None:
        self.assertEqual(
            fields(ACTIVITY, "NotificationRecord"),
            [
                ("ref", 1),
                ("version", 2),
                ("subject", 3),
                ("kind", 4),
                ("title", 5),
                ("body", 6),
                ("created_at", 7),
                ("read_at", 8),
                ("actions", 9),
            ],
        )
        self.assertEqual(
            fields(ACTIVITY, "UnsubscribeNotificationsRequest"),
            [
                ("client_operation_id", 1),
                ("unsubscribe_capability", 2),
                ("rules", 3),
            ],
        )
        service = body(SERVICES, "service", "NotificationService")
        observe = re.search(r"(?ms)rpc ObserveNotifications\(.*?^  \}", service)
        unsubscribe = re.search(
            r"(?ms)rpc UnsubscribeNotifications\(.*?^  \}", service
        )
        self.assertIsNotNone(observe)
        self.assertIsNotNone(unsubscribe)
        self.assertIn("AUTHORIZATION_ACCESS_AUTHENTICATED_PRINCIPAL", observe.group(0))
        self.assertIn("AUTHORIZATION_ACCESS_PUBLIC", unsubscribe.group(0))
        self.assertIn("client_operation_id_required: true", unsubscribe.group(0))

    def test_v1_private_and_batch_specific_models_are_absent(self) -> None:
        for retired in (
            "RegistryService",
            "ListInstallationRepositoriesRequest",
            "MintGitHubAppSetupChallengeRequest",
            "ListDiscussionsByStatesRequest",
            "ReadingOrderPartition",
            "NotificationKind",
            "FeedItemKind",
        ):
            self.assertNotRegex(ALL_V2, rf"(?m)^(?:message|enum|service) {retired} \{{")


if __name__ == "__main__":
    unittest.main()
