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
            r"(?m)^\s*[A-Za-z][A-Za-z0-9_.]*\s+"
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
            [("bootstrap_token", 1), ("recipient_email", 2)],
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

    def test_signup_failures_use_error_detail_context(self) -> None:
        signup = body(ERRORS, "message", "SignupFailure")
        expected = {
            "INVITE_MISSING": 1,
            "INVITE_CLAIMED": 2,
            "INVITE_REVOKED": 3,
            "VERIFICATION_TOKEN_EXPIRED": 4,
            "VERIFICATION_TOKEN_REPLAYED": 5,
        }
        for reason, tag in expected.items():
            self.assertIn(f"SIGNUP_FAILURE_REASON_{reason} = {tag}", signup)
        self.assertIn(
            "SignupFailure signup = 17",
            body(ERRORS, "message", "ErrorDetail"),
        )
        self.assertIn("must never be returned by ResolveSignupInvite", ERRORS)


if __name__ == "__main__":
    unittest.main()
