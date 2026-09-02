from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parent.parent
COLLABORATION = (ROOT / "proto/heddle/api/v1alpha1/collaboration.proto").read_text()
IDENTITY = (ROOT / "proto/heddle/api/v1alpha1/identity.proto").read_text()
REGISTRY = (ROOT / "proto/heddle/api/v1alpha1/registry.proto").read_text()
REPOSITORY = (ROOT / "proto/heddle/api/v1alpha1/repository.proto").read_text()
STATE_REVIEW = (ROOT / "proto/heddle/api/v1alpha1/state_review.proto").read_text()
CONTRACT = (ROOT / "proto/heddle/api/v1alpha1/contract.proto").read_text()
ATTENTION = (ROOT / "proto/heddle/api/v1alpha1/attention.proto").read_text()
NOTIFICATION = (ROOT / "proto/heddle/api/v1alpha1/notification.proto").read_text()


def body(source: str, kind: str, name: str) -> str:
    match = re.search(rf"(?ms)^{kind} {name} \{{(.*?)^\}}", source)
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
    def test_open_discussion_severity_binds_to_merge_requirement_kind(self) -> None:
        self.assertEqual(
            fields(COLLABORATION, "OpenDiscussionRequest")[8:10],
            [("severity", 9), ("kind", 10)],
        )
        requirement_kinds = body(REGISTRY, "enum", "UnmetRequirementKind")
        self.assertIn("UNMET_REQUIREMENT_KIND_OPEN_DISCUSSION = 3", requirement_kinds)

    def test_coordination_discussions_are_first_class_thread_subjects(self) -> None:
        kinds = body(COLLABORATION, "enum", "DiscussionKind")
        self.assertIn("DISCUSSION_KIND_UNSPECIFIED = 0", kinds)
        self.assertIn("DISCUSSION_KIND_CODE_ANCHORED = 1", kinds)
        self.assertIn("DISCUSSION_KIND_COORDINATION = 2", kinds)

        open_request = body(COLLABORATION, "message", "OpenDiscussionRequest")
        self.assertIn("optional PathSymbolRef anchor = 3", open_request)
        self.assertEqual(
            fields(COLLABORATION, "ListByThreadRefRequest"),
            [
                ("repo_path", 1),
                ("thread_ref", 2),
                ("status", 3),
                ("kind", 4),
                ("page_size", 5),
                ("page_token", 6),
            ],
        )
        self.assertEqual(
            fields(COLLABORATION, "ListByThreadRefResponse"),
            [("discussions", 1), ("next_page_token", 2)],
        )
        self.assertEqual(fields(COLLABORATION, "Discussion")[-1], ("kind", 14))

        service = body(COLLABORATION, "service", "CollaborationService")
        self.assertIn(
            "rpc ListByThreadRef(ListByThreadRefRequest) "
            "returns (ListByThreadRefResponse)",
            service,
        )
        rpc = re.search(r"(?ms)rpc ListByThreadRef\(.*?\n  \}", service)
        self.assertIsNotNone(rpc)
        self.assertIn("RPC_EFFECT_READ_ONLY", rpc.group(0))
        self.assertIn("RETRY_BEHAVIOR_SAFE", rpc.group(0))
        self.assertIn("AUTHORIZATION_ACCESS_AUTHENTICATED_PRINCIPAL", rpc.group(0))

    def test_github_app_installation_repository_listing_and_setup_mint(self) -> None:
        self.assertEqual(
            fields(IDENTITY, "ListInstallationRepositoriesRequest"),
            [("installation_id", 1), ("page_size", 2), ("page_token", 3)],
        )
        self.assertEqual(
            fields(IDENTITY, "ListInstallationRepositoriesResponse"),
            [("repositories", 1), ("next_page_token", 2)],
        )
        self.assertEqual(
            fields(IDENTITY, "InstallationRepository"),
            [
                ("id", 1),
                ("full_name", 2),
                ("installation_granted", 3),
                ("visibility", 4),
                ("description", 5),
                ("default_branch", 6),
                ("clone_url", 7),
                ("stargazers_count", 8),
                ("size_kb", 9),
            ],
        )
        self.assertEqual(
            fields(IDENTITY, "MintGitHubAppSetupChallengeRequest"),
            [("client_operation_id", 1)],
        )
        self.assertEqual(
            fields(IDENTITY, "MintGitHubAppSetupChallengeResponse"),
            [("state", 1)],
        )
        service = body(IDENTITY, "service", "IdentityService")
        self.assertIn(
            "rpc ListInstallationRepositories(ListInstallationRepositoriesRequest) "
            "returns (ListInstallationRepositoriesResponse)",
            service,
        )
        self.assertIn(
            "rpc MintGitHubAppSetupChallenge(MintGitHubAppSetupChallengeRequest) "
            "returns (MintGitHubAppSetupChallengeResponse)",
            service,
        )
        list_rpc = re.search(
            r"(?ms)rpc ListInstallationRepositories\(.*?\n  \}", service
        )
        self.assertIsNotNone(list_rpc)
        self.assertIn("RPC_EFFECT_READ_ONLY", list_rpc.group(0))
        self.assertIn("RETRY_BEHAVIOR_SAFE", list_rpc.group(0))
        self.assertIn("client_operation_id_required: false", list_rpc.group(0))
        mint_rpc = re.search(
            r"(?ms)rpc MintGitHubAppSetupChallenge\(.*?\n  \}", service
        )
        self.assertIsNotNone(mint_rpc)
        self.assertIn("RPC_EFFECT_TRANSIENT_WRITE", mint_rpc.group(0))
        self.assertIn("RETRY_BEHAVIOR_CLIENT_OPERATION_ID", mint_rpc.group(0))
        self.assertIn("client_operation_id_required: true", mint_rpc.group(0))

    def test_retired_rpcs_and_private_messages_are_absent(self) -> None:
        for source, service_name, methods in (
            (IDENTITY, "IdentityService", ("MintBiscuit", "RecordSubscription")),
            (
                REGISTRY,
                "RegistryService",
                ("CreateNamespace", "CreateRepository", "GetCurrentUserNamespace"),
            ),
        ):
            service = body(source, "service", service_name)
            for method in methods:
                self.assertNotRegex(service, rf"\brpc {method}\(")
        for message in (
            "MintBiscuitRequest",
            "RecordSubscriptionRequest",
            "RecordSubscriptionResponse",
        ):
            self.assertNotRegex(IDENTITY, rf"(?m)^message {message} \{{")
        for message in (
            "CreateNamespaceRequest",
            "CreateRepositoryRequest",
            "GetCurrentUserNamespaceRequest",
        ):
            self.assertNotRegex(REGISTRY, rf"(?m)^message {message} \{{")

    def test_list_discussions_by_states_is_batched_digest_read(self) -> None:
        self.assertEqual(
            fields(COLLABORATION, "ListDiscussionsByStatesRequest"),
            [("repo_path", 1), ("state_ids", 2), ("status", 3)],
        )
        self.assertEqual(
            fields(COLLABORATION, "StateDiscussionDigest"),
            [
                ("state_id", 1),
                ("discussion_count", 2),
                ("open_count", 3),
                ("resolved_count", 4),
                ("orphaned_count", 5),
                ("discussions", 6),
            ],
        )
        service = body(COLLABORATION, "service", "CollaborationService")
        self.assertIn(
            "rpc ListDiscussionsByStates(ListDiscussionsByStatesRequest) "
            "returns (ListDiscussionsByStatesResponse)",
            service,
        )
        rpc = re.search(r"(?ms)rpc ListDiscussionsByStates\(.*?\n  \}", service)
        self.assertIsNotNone(rpc)
        self.assertIn("RPC_EFFECT_READ_ONLY", rpc.group(0))
        self.assertIn("AUTHORIZATION_ACCESS_AUTHENTICATED_PRINCIPAL", rpc.group(0))

    def test_list_thread_histories_is_batched_list_states(self) -> None:
        self.assertEqual(
            fields(REPOSITORY, "ListThreadHistoriesRequest"),
            [("repo_path", 1), ("refs", 2), ("limit", 3)],
        )
        self.assertEqual(
            fields(REPOSITORY, "ThreadHistory"),
            [("ref", 1), ("states", 2)],
        )
        service = body(REPOSITORY, "service", "RepositoryService")
        self.assertIn(
            "rpc ListThreadHistories(ListThreadHistoriesRequest) "
            "returns (ListThreadHistoriesResponse)",
            service,
        )

    def test_reading_order_entries_are_additive_and_range_bearing(self) -> None:
        partition = body(STATE_REVIEW, "message", "ReadingOrderPartition")
        self.assertRegex(partition, r"repeated PathSymbolRef structural = 1")
        self.assertRegex(partition, r"repeated ReadingOrderEntry structural_entries = 4")
        self.assertRegex(partition, r"repeated ReadingOrderEntry consequence_entries = 5")
        self.assertRegex(
            partition, r"repeated ReadingOrderEntry tests_and_docs_entries = 6"
        )
        self.assertEqual(
            fields(STATE_REVIEW, "ReadingOrderEntry"),
            [("ref", 1), ("start_line", 2), ("end_line", 3)],
        )
        entry = body(STATE_REVIEW, "message", "ReadingOrderEntry")
        self.assertIn("optional uint32 start_line = 2", entry)
        self.assertIn("optional uint32 end_line = 3", entry)
        path_symbol = body(STATE_REVIEW, "message", "PathSymbolRef")
        self.assertNotRegex(path_symbol, r"start_line|end_line")


    def test_discussion_turn_gains_streaming_identity_and_import_provenance(
        self,
    ) -> None:
        # E5 server-minted identity (turn_seq/turn_id) and E3 imported-turn
        # provenance land additively at the next free numbers on DiscussionTurn;
        # the first five fields are unchanged.
        self.assertEqual(
            fields(STATE_REVIEW, "DiscussionTurn"),
            [
                ("author_name", 1),
                ("author_email", 2),
                ("body", 3),
                ("posted_at", 4),
                ("references", 5),
                ("turn_seq", 6),
                ("turn_id", 7),
                ("external_author_display", 8),
                ("external_author_id", 9),
                ("source_url", 10),
                ("original_created_at", 11),
            ],
        )
        turn = body(STATE_REVIEW, "message", "DiscussionTurn")
        self.assertIn("uint64 turn_seq = 6", turn)
        self.assertIn("google.protobuf.Timestamp original_created_at = 11", turn)

    def test_discussion_turns_ride_the_repo_events_live_plane(self) -> None:
        # E5 reuses SubscribeRepoEvents/repo_events. A typed RepoEventKind names
        # the discussion-turn event; event_type (string) stays authoritative and
        # RepoEvent.kind is an additive typed projection at the next free number.
        kinds = body(REPOSITORY, "enum", "RepoEventKind")
        self.assertIn("REPO_EVENT_KIND_UNSPECIFIED = 0", kinds)
        self.assertIn("REPO_EVENT_KIND_DISCUSSION_TURN = 1", kinds)
        self.assertEqual(fields(REPOSITORY, "RepoEvent")[-1], ("kind", 15))
        self.assertIn("string event_type = 3", body(REPOSITORY, "message", "RepoEvent"))

    def test_notification_kind_mirrors_feed_item_kind_numbers(self) -> None:
        # E6 NotificationKind values 1..6 mirror FeedItemKind numbers so a feed
        # item projects onto a notification without remapping; 10..13 are
        # notification-only kinds.
        notif = body(NOTIFICATION, "enum", "NotificationKind")
        feed = body(ATTENTION, "enum", "FeedItemKind")
        mirrored = {
            1: "REVIEW_READY",
            2: "AGENT_COMPLETED",
            3: "SECURITY_SURFACE",
            4: "DRIFT_ALERT",
            6: "IMPORTED_DISCUSSION",
        }
        for number, name in mirrored.items():
            self.assertIn(f"FEED_ITEM_KIND_{name} = {number}", feed)
            self.assertIn(f"NOTIFICATION_KIND_{name} = {number}", notif)
        # 5 mirrors the FeedItemKind number while naming the digest form.
        self.assertIn("FEED_ITEM_KIND_REPO_QUIET = 5", feed)
        self.assertIn("NOTIFICATION_KIND_REPO_QUIET_DIGEST = 5", notif)
        for number, name in (
            (10, "MENTION"),
            (11, "DISCUSSION_REPLY"),
            (12, "ACCOUNT_SECURITY"),
            (13, "STEER_HELD"),
        ):
            self.assertIn(f"NOTIFICATION_KIND_{name} = {number}", notif)

    def test_notification_service_is_shipped_recipient_owned_surface(self) -> None:
        self.assertIn("CAPABILITY_AREA_NOTIFICATIONS = 15", CONTRACT)
        self.assertIn(
            "notification_id", dict(fields(NOTIFICATION, "Notification"))
        )
        # A Notification references a FeedItem rather than copying it.
        self.assertIn("feed_item_id", dict(fields(NOTIFICATION, "Notification")))
        service = body(NOTIFICATION, "service", "NotificationService")
        # 0.23.0: the service is SHIPPED (E6 handlers landed). Only Unsubscribe
        # keeps a method-level PLANNED override pending email delivery.
        service_contract = re.search(
            r"(?ms)option \(heddle\.api\.v1alpha1\.service_contract\) = \{.*?\};",
            service,
        )
        self.assertIsNotNone(service_contract)
        self.assertIn(
            "maturity: SERVICE_MATURITY_SHIPPED", service_contract.group(0)
        )
        for rpc_name in (
            "ListNotifications",
            "SubscribeNotifications",
            "MarkNotificationRead",
            "GetNotificationPreferences",
            "SetNotificationPreferences",
            "Unsubscribe",
        ):
            self.assertRegex(service, rf"\brpc {rpc_name}\(")
        # Per-recipient RPCs are scoped to the caller subject, not a repo, and
        # carry no maturity override — they inherit the service's SHIPPED maturity.
        mark = re.search(r"(?ms)rpc MarkNotificationRead\(.*?\n  \}", service)
        self.assertIsNotNone(mark)
        self.assertNotIn("maturity:", mark.group(0))
        self.assertIn(
            "AUTHORIZATION_SCOPE_SOURCE_CALLER_SUBJECT", mark.group(0)
        )
        self.assertIn("RPC_EFFECT_DURABLE_WRITE", mark.group(0))
        # Unsubscribe is public/unauthenticated; the in-body token is the proof.
        # It stays PLANNED (deferred pending email) via a method-level override.
        unsub = re.search(r"(?ms)rpc Unsubscribe\(.*?\n  \}", service)
        self.assertIsNotNone(unsub)
        self.assertIn("maturity: SERVICE_MATURITY_PLANNED", unsub.group(0))
        self.assertIn("AUTHORIZATION_ACCESS_PUBLIC", unsub.group(0))
        self.assertIn("unsubscribe_token", dict(fields(NOTIFICATION, "UnsubscribeRequest")))


if __name__ == "__main__":
    unittest.main()
