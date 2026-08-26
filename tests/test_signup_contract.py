from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parent.parent
IDENTITY = (ROOT / "proto/heddle/api/v1alpha1/identity.proto").read_text()
ERRORS = (ROOT / "proto/heddle/api/v1alpha1/errors.proto").read_text()


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


def rpc(name: str) -> tuple[str, str, str]:
    match = re.search(
        rf"(?ms)^  rpc {name}\((\w+)\) returns \((\w+)\) "
        rf"\{{(.*?)^  \}}",
        body(IDENTITY, "service", "IdentityService"),
    )
    if match is None:
        raise AssertionError(f"missing rpc {name}")
    return match.group(1), match.group(2), match.group(3)


class SignupContractTest(unittest.TestCase):
    def test_public_drop_claim_and_count_contracts(self) -> None:
        self.assertEqual(
            fields(IDENTITY, "ClaimNextDropCodeRequest"),
            [("drop_slug", 1), ("src", 2)],
        )
        self.assertIn(
            "optional string src = 2",
            body(IDENTITY, "message", "ClaimNextDropCodeRequest"),
        )
        self.assertEqual(
            fields(IDENTITY, "ClaimNextDropCodeResponse"),
            [("code", 1), ("held_until", 2)],
        )
        self.assertEqual(
            fields(IDENTITY, "RemainingDropCodesRequest"),
            [("drop_slug", 1)],
        )
        self.assertEqual(
            fields(IDENTITY, "RemainingDropCodesResponse"),
            [("count", 1)],
        )

        request_type, response_type, contract = rpc("ClaimNextDropCode")
        self.assertEqual(request_type, "ClaimNextDropCodeRequest")
        self.assertEqual(response_type, "ClaimNextDropCodeResponse")
        for required in (
            "signing_tier: SIGNING_TIER_NONE",
            "effect: RPC_EFFECT_TRANSIENT_WRITE",
            "retry_behavior: RETRY_BEHAVIOR_NEVER",
            "client_operation_id_required: false",
            "authorization_access: AUTHORIZATION_ACCESS_PUBLIC",
            "authorization_role: AUTHORIZATION_ROLE_CALLER_BOUND",
            "authorization_scope_source: AUTHORIZATION_SCOPE_SOURCE_CALLER_SUBJECT",
            "authorization_existence: AUTHORIZATION_EXISTENCE_HIDE",
        ):
            self.assertIn(required, contract)

        request_type, response_type, contract = rpc("RemainingDropCodes")
        self.assertEqual(request_type, "RemainingDropCodesRequest")
        self.assertEqual(response_type, "RemainingDropCodesResponse")
        for required in (
            "signing_tier: SIGNING_TIER_NONE",
            "effect: RPC_EFFECT_READ_ONLY",
            "retry_behavior: RETRY_BEHAVIOR_SAFE",
            "client_operation_id_required: false",
            "authorization_access: AUTHORIZATION_ACCESS_PUBLIC",
            "authorization_role: AUTHORIZATION_ROLE_CALLER_BOUND",
            "authorization_scope_source: AUTHORIZATION_SCOPE_SOURCE_CALLER_SUBJECT",
            "authorization_existence: AUTHORIZATION_EXISTENCE_HIDE",
        ):
            self.assertIn(required, contract)

        service = body(IDENTITY, "service", "IdentityService")
        self.assertIn("hosted Iroh ALPN", service)
        self.assertIn("caller's Biscuit", service)
        self.assertIn("subject-scoped anti-abuse budget", service)
        self.assertIn("missing or revoked drop is", service)

    def test_mailbox_token_is_confined_to_service_account_issuance(self) -> None:
        self.assertEqual(
            fields(IDENTITY, "IssueSignupEmailChallengeRequest"),
            [("username", 1), ("recipient_email", 2), ("client_operation_id", 3)],
        )
        self.assertEqual(
            fields(IDENTITY, "IssueSignupEmailChallengeResponse"),
            [("status", 1), ("expires_at", 2), ("verification_token", 3)],
        )
        acceptance = body(
            IDENTITY, "enum", "SignupEmailChallengeAcceptanceStatus"
        )
        self.assertIn("ACCEPTANCE_STATUS_ACCEPTED = 1", acceptance)
        self.assertNotRegex(acceptance, r"(REJECTED|MISSING|NOT_FOUND)")

        request, response, contract = rpc("IssueSignupEmailChallenge")
        self.assertEqual(request, "IssueSignupEmailChallengeRequest")
        self.assertEqual(response, "IssueSignupEmailChallengeResponse")
        for required in (
            "maturity: SERVICE_MATURITY_PLANNED",
            "signing_tier: SIGNING_TIER_NONE",
            "client_operation_id_required: true",
            "authorization_access: "
            "AUTHORIZATION_ACCESS_AUTHENTICATED_SERVICE_ACCOUNT",
        ):
            self.assertIn(required, contract)
        owners = re.findall(
            r"(?m)^  rpc (\w+)\([^)]*\) returns "
            r"\(IssueSignupEmailChallengeResponse\)",
            body(IDENTITY, "service", "IdentityService"),
        )
        self.assertEqual(owners, ["IssueSignupEmailChallenge"])

    def test_verification_and_binding_use_server_verified_email(self) -> None:
        self.assertEqual(
            fields(IDENTITY, "VerifySignupEmailResponse"),
            [
                ("bootstrap_token", 1),
                ("recipient_email", 2),
                ("bound_handle", 3),
            ],
        )
        verification = body(
            IDENTITY, "message", "VerifySignupEmailResponse"
        )
        for required in (
            "Server-canonicalized address",
            "unused, non-revoked invite",
            '"Invite found for <email>"',
            "never copied from a request field",
        ):
            self.assertIn(required, verification)

        self.assertEqual(
            fields(IDENTITY, "BindSignupInviteEmailRequest"),
            [
                ("invite_code", 1),
                ("recipient_email", 2),
                ("client_operation_id", 3),
            ],
        )
        binding = body(
            IDENTITY, "message", "BindSignupInviteEmailRequest"
        )
        self.assertIn("signup_bootstrap_email fact", binding)
        self.assertIn("does not\n  // prove control", binding)
        _, _, contract = rpc("BindSignupInviteEmail")
        for required in (
            "signing_tier: SIGNING_TIER_PROOF_OF_POSSESSION",
            "client_operation_id_required: true",
            'path: "recipient_email"',
        ):
            self.assertIn(required, contract)

    def test_anonymous_resolution_has_no_missing_code_shape(self) -> None:
        status = body(IDENTITY, "enum", "SignupInviteResolutionStatus")
        for value in ("VALID = 1", "CONSUMED = 2", "EXPIRED = 3"):
            self.assertIn(value, status)
        self.assertNotRegex(status, r"(MISSING|INVALID|NOT_FOUND|REVOKED)")
        response = body(
            IDENTITY, "message", "ResolveSignupInviteResponse"
        )
        self.assertEqual(
            fields(IDENTITY, "ResolveSignupInviteResponse"),
            [
                ("status", 1),
                ("inviter_display_handle", 2),
                ("inviter_member_ordinal", 3),
                ("recipient_email", 4),
            ],
        )
        self.assertNotRegex(response, r"\b(bool\s+exists|bool\s+found)\b")
        self.assertIn("invalid and expired serialize alike", response)
        self.assertIn("no inviter subject, email", response)
        _, _, contract = rpc("ResolveSignupInvite")
        self.assertIn(
            "authorization_access: AUTHORIZATION_ACCESS_PUBLIC", contract
        )
        self.assertIn(
            "authorization_existence: AUTHORIZATION_EXISTENCE_HIDE", contract
        )
        service_prefix = IDENTITY[: IDENTITY.index("rpc ResolveSignupInvite")]
        self.assertIn("Anonymous, per-IP-rate-limited lookup", service_prefix[-800:])
        self.assertIn("same per-IP budget", service_prefix[-800:])

    def test_code_claim_is_non_retryable_and_existence_hidden(self) -> None:
        self.assertEqual(
            fields(IDENTITY, "ClaimSignupInviteRequest"),
            [("invite_code", 1)],
        )
        request = body(IDENTITY, "message", "ClaimSignupInviteRequest")
        self.assertIn("Same high-entropy opaque invite code", request)
        self.assertIn("Possession is the only authorization", request)

        methods = body(IDENTITY, "enum", "SignupBootstrapMethod")
        self.assertEqual(
            re.findall(r"SIGNUP_BOOTSTRAP_METHOD_(\w+)\s*=\s*(\d+)", methods),
            [
                ("UNSPECIFIED", "0"),
                ("BEGIN_WEB_AUTHN_REGISTRATION", "1"),
                ("REGISTER_PUBLIC_KEY", "2"),
            ],
        )
        self.assertEqual(
            fields(IDENTITY, "ClaimSignupInviteResponse"),
            [
                ("bootstrap_token", 1),
                ("expires_at", 2),
                ("allowed_methods", 3),
                ("reservation_id", 4),
                ("session_id", 5),
            ],
        )
        response = body(IDENTITY, "message", "ClaimSignupInviteResponse")
        self.assertIn("Opaque short-lived bearer", response)
        self.assertIn("must carry no other capability", response)
        self.assertIn("BEGIN_WEB_AUTHN_REGISTRATION and REGISTER_PUBLIC_KEY exactly", response)
        self.assertIn("The bearer remains the authority", response)
        self.assertIn("mint input, not", response)
        self.assertIn("signup_bootstrap_invite", response)
        self.assertIn("session rev_id", response)

        request_type, response_type, contract = rpc("ClaimSignupInvite")
        self.assertEqual(request_type, "ClaimSignupInviteRequest")
        self.assertEqual(response_type, "ClaimSignupInviteResponse")
        for required in (
            "maturity: SERVICE_MATURITY_PLANNED",
            "signing_tier: SIGNING_TIER_NONE",
            "effect: RPC_EFFECT_DURABLE_WRITE",
            "retry_behavior: RETRY_BEHAVIOR_NEVER",
            "client_operation_id_required: false",
            "authorization_access: AUTHORIZATION_ACCESS_PUBLIC",
            "authorization_role: AUTHORIZATION_ROLE_CALLER_BOUND",
            "authorization_scope_source: "
            "AUTHORIZATION_SCOPE_SOURCE_REQUEST_RESOURCE",
            'path: "invite_code"',
            "authorization_existence: AUTHORIZATION_EXISTENCE_HIDE",
        ):
            self.assertIn(required, contract)

        service_prefix = IDENTITY[: IDENTITY.index("rpc ClaimSignupInvite")]
        public_contract = service_prefix[-1800:]
        for hidden_state in (
            "malformed or unknown",
            "consumed",
            "reserved",
            "revoked",
            "email-bound",
        ):
            self.assertIn(hidden_state, public_contract)
        for failure_shape in (
            "CALL_FAILURE_CODE_NOT_FOUND",
            "ERROR_REASON_RESOURCE_NOT_FOUND",
            "empty ErrorDetail.resource and .field",
            "SIGNUP_FAILURE_REASON_INVITE_UNAVAILABLE",
            "processing\n  // path/timing envelope must also be the same",
        ):
            self.assertIn(failure_shape, public_contract)

    def test_agent_rooted_provisioning_is_invite_and_key_bound(self) -> None:
        self.assertEqual(
            fields(IDENTITY, "ProvisionAgentRootedAccountRequest"),
            [
                ("invite_code", 1),
                ("agent_public_key", 2),
                ("client_operation_id", 3),
            ],
        )
        request = body(
            IDENTITY, "message", "ProvisionAgentRootedAccountRequest"
        )
        self.assertIn("Same high-entropy opaque invite code", request)
        self.assertIn("MUST contain\n  // exactly 32 bytes", request)
        self.assertIn("request proof MUST verify against this key", request)
        self.assertEqual(
            fields(IDENTITY, "ProvisionAgentRootedAccountResponse"),
            [("handle", 1), ("account_id", 2), ("agent_capability", 3)],
        )
        response = body(
            IDENTITY, "message", "ProvisionAgentRootedAccountResponse"
        )
        self.assertIn("Serialized pre-attenuated capability", response)
        self.assertIn("requiring an independent root", response)

        request_type, response_type, contract = rpc(
            "ProvisionAgentRootedAccount"
        )
        self.assertEqual(request_type, "ProvisionAgentRootedAccountRequest")
        self.assertEqual(response_type, "ProvisionAgentRootedAccountResponse")
        for required in (
            "maturity: SERVICE_MATURITY_PLANNED",
            "signing_tier: SIGNING_TIER_PROOF_OF_POSSESSION",
            "effect: RPC_EFFECT_DURABLE_WRITE",
            "retry_behavior: RETRY_BEHAVIOR_CLIENT_OPERATION_ID",
            "client_operation_id_required: true",
            "authorization_access: AUTHORIZATION_ACCESS_PUBLIC",
            "authorization_scope_source: "
            "AUTHORIZATION_SCOPE_SOURCE_REQUEST_RESOURCE",
            'path: "invite_code"',
            "authorization_existence: AUTHORIZATION_EXISTENCE_HIDE",
        ):
            self.assertIn(required, contract)

    def test_begin_registration_carries_adoption_pre_consent(self) -> None:
        self.assertEqual(
            fields(IDENTITY, "BeginWebAuthnRegistrationRequest"),
            [
                ("username", 1),
                ("display_name", 2),
                ("account_id", 3),
                ("agent_node_id", 4),
                ("pre_consent_signature", 5),
                ("nonce", 6),
                ("authorization_hash", 7),
                ("expires_at_millis", 8),
            ],
        )
        request = body(IDENTITY, "message", "BeginWebAuthnRegistrationRequest")
        self.assertIn("pre-consent", request)
        self.assertIn("does not bind", request)
        self.assertIn("credentialId", request)
        self.assertIn("Hex SHA-256 of the claim secret", request)
        self.assertIn("trailing counted fields", request)
        self.assertIn("both must travel together", request)
        self.assertIn("Empty on non-adoption and on old clients", request)
        self.assertIn("Zero on non-adoption and on old clients", request)
        self.assertIn(
            "the lowercase hex SHA-256 of the claim secret (64 hex chars)",
            request,
        )
        self.assertIn("Do not send uppercase or raw 32-byte digest", request)
        self.assertIn("On the wire this stays proto `int64`", request)
        self.assertIn(
            "exactly 8 big-endian two's-complement bytes of that i64 "
            "(`i64::to_be_bytes`)",
            request,
        )
        self.assertIn("Not decimal text, not protobuf varint", request)
        self.assertIn("Empty hash + 0 is old-client v1", request)

    def test_create_agent_account_is_invite_gated_pet_name_path(self) -> None:
        self.assertEqual(
            fields(IDENTITY, "CreateAgentAccountRequest"),
            [
                ("invite_code", 1),
                ("agent_public_key", 2),
                ("client_operation_id", 3),
            ],
        )
        self.assertEqual(
            fields(IDENTITY, "CreateAgentAccountResponse"),
            [
                ("account_id", 1),
                ("pet_name", 2),
                ("agent_capability", 3),
                ("web_origin", 5),
            ],
        )
        response = body(IDENTITY, "message", "CreateAgentAccountResponse")
        self.assertIn("globally-unique pet name", response)
        self.assertIn("no handle", response)
        self.assertIn("SERVER_WEB_ORIGIN", response)
        self.assertIn("{web_origin}/claim/{node_id}.{secret}", response)
        self.assertIn("self-hosting", response)

        request_type, response_type, contract = rpc("CreateAgentAccount")
        self.assertEqual(request_type, "CreateAgentAccountRequest")
        self.assertEqual(response_type, "CreateAgentAccountResponse")
        for required in (
            "maturity: SERVICE_MATURITY_PLANNED",
            "signing_tier: SIGNING_TIER_PROOF_OF_POSSESSION",
            "effect: RPC_EFFECT_DURABLE_WRITE",
            "retry_behavior: RETRY_BEHAVIOR_CLIENT_OPERATION_ID",
            "client_operation_id_required: true",
            "authorization_access: AUTHORIZATION_ACCESS_PUBLIC",
            'path: "invite_code"',
            "authorization_existence: AUTHORIZATION_EXISTENCE_HIDE",
        ):
            self.assertIn(required, contract)

    def test_promote_agent_account_is_one_call_promote_consent(self) -> None:
        self.assertEqual(
            fields(IDENTITY, "PromoteAgentAccountRequest"),
            [
                ("account_id", 1),
                ("handle", 2),
                ("credential_id", 3),
                ("challenge_id", 4),
                ("client_data_json", 5),
                ("attestation_object", 6),
                ("agent_node_id", 7),
                ("promote_consent_signature", 8),
                ("client_operation_id", 9),
                ("authorization_hash", 10),
                ("expires_at_millis", 11),
            ],
        )
        request = body(IDENTITY, "message", "PromoteAgentAccountRequest")
        self.assertIn("credentialId", request)
        self.assertIn("just-created passkey", request)
        self.assertIn("anti-replay binding", IDENTITY)
        self.assertIn("Hex SHA-256 of the claim secret", request)
        self.assertIn("trailing counted fields", request)
        self.assertIn("both must travel together", request)
        self.assertIn("Empty on non-adoption and on old clients", request)
        self.assertIn("Zero on non-adoption and on old clients", request)
        self.assertIn(
            "the lowercase hex SHA-256 of the claim secret (64 hex chars)",
            request,
        )
        self.assertIn("Do not send uppercase or raw 32-byte digest", request)
        self.assertIn("On the wire this stays proto `int64`", request)
        self.assertIn(
            "exactly 8 big-endian two's-complement bytes of that i64 "
            "(`i64::to_be_bytes`)",
            request,
        )
        self.assertIn("Not decimal text, not protobuf varint", request)
        self.assertIn("Empty hash + 0 is old-client v1", request)
        self.assertEqual(
            fields(IDENTITY, "PromoteAgentAccountResponse"),
            [
                ("session", 1),
                ("canonical_handle", 2),
                ("account_id", 3),
            ],
        )

        request_type, response_type, contract = rpc("PromoteAgentAccount")
        self.assertEqual(request_type, "PromoteAgentAccountRequest")
        self.assertEqual(response_type, "PromoteAgentAccountResponse")
        for required in (
            "maturity: SERVICE_MATURITY_PLANNED",
            "signing_tier: SIGNING_TIER_PROOF_OF_POSSESSION",
            "effect: RPC_EFFECT_DURABLE_WRITE",
            "retry_behavior: RETRY_BEHAVIOR_CLIENT_OPERATION_ID",
            "client_operation_id_required: true",
            "authorization_access: AUTHORIZATION_ACCESS_PUBLIC",
            'path: "account_id"',
            "authorization_existence: AUTHORIZATION_EXISTENCE_HIDE",
        ):
            self.assertIn(required, contract)

    def test_signup_failures_use_error_detail_context(self) -> None:
        signup = body(ERRORS, "message", "SignupFailure")
        expected = {
            "INVITE_MISSING": 1,
            "INVITE_CLAIMED": 2,
            "INVITE_REVOKED": 3,
            "VERIFICATION_TOKEN_EXPIRED": 4,
            "VERIFICATION_TOKEN_REPLAYED": 5,
            "INVITE_UNAVAILABLE": 6,
        }
        for reason, tag in expected.items():
            self.assertIn(f"SIGNUP_FAILURE_REASON_{reason} = {tag}", signup)
        self.assertIn(
            "SignupFailure signup = 17",
            body(ERRORS, "message", "ErrorDetail"),
        )
        self.assertIn("must never be returned by ResolveSignupInvite", ERRORS)
        self.assertIn(
            "No narrower invite lifecycle reason\n"
            "    // above may be returned by ClaimSignupInvite",
            ERRORS,
        )


if __name__ == "__main__":
    unittest.main()
