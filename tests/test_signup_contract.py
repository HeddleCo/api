from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parent.parent
IDENTITY = (ROOT / "proto/heddle/api/v1alpha2/identity.proto").read_text()
SERVICES = (ROOT / "proto/heddle/api/v1alpha2/services.proto").read_text()


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


def rpc(name: str) -> tuple[str, str, str]:
    service = body(SERVICES, "service", "IdentityService")
    match = re.search(
        rf"(?ms)^\s*rpc {re.escape(name)}\((\w+)\) returns \((\w+)\) "
        rf"\{{(.*?)^\s*\}}",
        service,
    )
    if match is None:
        raise AssertionError(f"missing rpc {name}")
    return match.group(1), match.group(2), match.group(3)


class SignupContractTest(unittest.TestCase):
    def test_signup_invitation_creation_returns_secret_separately(self) -> None:
        self.assertEqual(
            fields(IDENTITY, "CreateSignupInvitationRequest"),
            [("client_operation_id", 1), ("invitation", 2)],
        )
        self.assertEqual(
            fields(IDENTITY, "CreateSignupInvitationResponse"),
            [("receipt", 1), ("invitation", 2), ("redemption_secret", 3)],
        )
        invitation = body(IDENTITY, "message", "SignupInvitation")
        self.assertNotRegex(invitation, r"\b(?:redemption_secret|invitation_secret)\s*=")
        _, _, contract = rpc("CreateSignupInvitation")
        self.assertIn("RPC_EFFECT_DURABLE_WRITE", contract)
        self.assertIn("client_operation_id_required: true", contract)
        self.assertIn("AUTHORIZATION_ACCESS_AUTHENTICATED_PRINCIPAL", contract)

    def test_redemption_is_public_idempotent_and_existence_hidden(self) -> None:
        self.assertEqual(
            fields(IDENTITY, "RedeemSignupInvitationRequest"),
            [("client_operation_id", 1), ("redemption_secret", 2)],
        )
        self.assertEqual(
            fields(IDENTITY, "RedeemSignupInvitationResponse"),
            [("receipt", 1), ("reservation", 2)],
        )
        reservation = body(IDENTITY, "message", "SignupReservation")
        self.assertRegex(reservation, r"\bRecordRef\s+ref\s*=\s*1\s*;")
        self.assertRegex(
            reservation,
            r"\bgoogle\.protobuf\.Timestamp\s+expires_at\s*=\s*2\s*;",
        )
        _, _, contract = rpc("RedeemSignupInvitation")
        for required in (
            "SIGNING_TIER_NONE",
            "RPC_EFFECT_DURABLE_WRITE",
            "RETRY_BEHAVIOR_CLIENT_OPERATION_ID",
            "client_operation_id_required: true",
            "AUTHORIZATION_ACCESS_PUBLIC",
            "AUTHORIZATION_EXISTENCE_HIDE",
        ):
            self.assertIn(required, contract)

    def test_resolution_collapses_invalid_states_without_identity_oracle(self) -> None:
        resolution = body(IDENTITY, "message", "SignupInvitationResolution")
        self.assertEqual(
            re.findall(r"(?m)^\s+(STATUS_[A-Z_]+)\s*=\s*(\d+)", resolution),
            [
                ("STATUS_UNSPECIFIED", "0"),
                ("STATUS_AVAILABLE", "1"),
                ("STATUS_IN_USE", "2"),
                ("STATUS_UNAVAILABLE", "3"),
            ],
        )
        self.assertNotRegex(resolution, r"STATUS_(?:MISSING|REVOKED|EXPIRED)")
        self.assertNotRegex(resolution, r"\b(?:subject|account_id)\s*=")
        self.assertEqual(
            fields(IDENTITY, "ResolveSignupInvitationRequest"),
            [("redemption_secret", 1)],
        )
        _, _, contract = rpc("ResolveSignupInvitation")
        self.assertIn("RPC_EFFECT_READ_ONLY", contract)
        self.assertIn("RETRY_BEHAVIOR_SAFE", contract)
        self.assertIn("AUTHORIZATION_ACCESS_PUBLIC", contract)

    def test_email_verification_keeps_delivery_secret_out_of_browser_result(self) -> None:
        self.assertEqual(
            fields(IDENTITY, "BeginEmailVerificationRequest"),
            [
                ("client_operation_id", 1),
                ("email", 2),
                ("invitation_code", 3),
                ("handle", 4),
            ],
        )
        challenge = body(IDENTITY, "message", "EmailVerificationChallenge")
        self.assertRegex(challenge, r"\bbytes\s+delivery_proof\s*=\s*4\s*;")
        self.assertIn("Never\n  // return this field in a browser", challenge)
        self.assertEqual(
            fields(IDENTITY, "CompleteEmailVerificationRequest"),
            [("client_operation_id", 1), ("challenge", 2), ("proof", 3)],
        )
        response = body(IDENTITY, "message", "CompleteEmailVerificationResponse")
        self.assertRegex(
            response, r"\bVerifiedEmailReservation\s+reservation\s*=\s*2\s*;"
        )
        _, _, begin = rpc("BeginEmailVerification")
        self.assertIn("AUTHORIZATION_ACCESS_AUTHENTICATED_PRINCIPAL", begin)
        _, _, complete = rpc("CompleteEmailVerification")
        self.assertIn("AUTHORIZATION_ACCESS_PUBLIC", complete)

    def test_registration_accepts_only_typed_invite_and_email_reservations(self) -> None:
        self.assertEqual(
            fields(IDENTITY, "BeginRegistrationRequest"),
            [
                ("caller_public_key", 1),
                ("handle", 2),
                ("display_name", 3),
                ("invitation_reservation", 4),
                ("verified_email", 5),
                ("method", 6),
                ("oauth_provider", 7),
            ],
        )
        complete = fields(IDENTITY, "CompleteRegistrationRequest")
        for required in (
            ("client_operation_id", 1),
            ("challenge", 2),
            ("caller_public_key", 4),
            ("device_binding", 5),
            ("establish_owner", 7),
            ("claim_owner", 8),
            ("mint_root_attachment", 9),
            ("passkey_authority", 12),
        ):
            self.assertIn(required, complete)

    def test_agent_account_provisioning_is_invite_and_key_bound(self) -> None:
        self.assertEqual(
            fields(IDENTITY, "ProvisionAccountRequest"),
            [
                ("client_operation_id", 1),
                ("invitation_secret", 2),
                ("agent_public_key", 3),
            ],
        )
        self.assertEqual(
            fields(IDENTITY, "ProvisionAccountResponse"),
            [
                ("receipt", 1),
                ("principal", 2),
                ("credential", 3),
                ("claim_web_origin", 4),
                ("ownership", 5),
            ],
        )
        request = body(IDENTITY, "message", "ProvisionAccountRequest")
        self.assertIn("agent proves its own key", IDENTITY)
        self.assertIn("Reusing an operation ID with different bytes is rejected", IDENTITY)
        _, _, contract = rpc("ProvisionAccount")
        self.assertIn("SIGNING_TIER_PROOF_OF_POSSESSION", contract)
        self.assertIn("AUTHORIZATION_ACCESS_PUBLIC", contract)
        self.assertIn("AUTHORIZATION_EXISTENCE_HIDE", contract)
        self.assertIn("client_operation_id_required: true", contract)

    def test_retired_promotion_is_replaced_by_root_attachment_registration(self) -> None:
        self.assertNotRegex(IDENTITY, r"(?m)^message PromoteAgentAccountRequest \{")
        self.assertEqual(
            fields(IDENTITY, "RegisterRootAttachmentRequest"),
            [
                ("client_operation_id", 1),
                ("attachment", 2),
                ("subject_possession", 3),
                ("label", 4),
            ],
        )
        _, _, contract = rpc("RegisterRootAttachment")
        self.assertIn("SIGNING_TIER_PROOF_OF_POSSESSION", contract)
        self.assertIn("RPC_EFFECT_DURABLE_WRITE", contract)
        self.assertIn("AUTHORIZATION_ACCESS_AUTHENTICATED_PRINCIPAL", contract)


if __name__ == "__main__":
    unittest.main()
