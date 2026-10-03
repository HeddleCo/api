"""Pin the normative requirements for the planned consumer implementations."""

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
IDENTITY = (ROOT / "proto/heddle/api/v1alpha2/identity.proto").read_text()
ACCOUNT = (ROOT / "docs/alpha-v2/account-management.md").read_text()


class AccountManagementContractTest(unittest.TestCase):
    def test_remove_passkey_requires_independent_root_and_declares_denial(self):
        removal = IDENTITY.split("message RemovePasskeyRequest", 1)[0].rsplit(
            "message RenamePasskeyResponse", 1
        )[1]
        for requirement in ("require_independent_root", "root_established", "unattenuated"):
            self.assertIn(requirement, removal)
            self.assertIn(requirement, ACCOUNT)
        actions = IDENTITY.split("repeated ActionAvailability actions = 9", 1)[0]
        self.assertRegex(actions, r"RemovePasskey[^\n]*authorized=false")
        self.assertIn("two usable sign-in methods", ACCOUNT)
        self.assertIn("matching versions", ACCOUNT)
        self.assertIn("valid request signatures", ACCOUNT)
        self.assertIn("owned targets", ACCOUNT)
        self.assertIn("AUTH_ROOT_BOUNDARY_CATALOG", ACCOUNT)
        self.assertIn("DenyAttenuated", ACCOUNT)
        self.assertIn("eligible independent-root request succeeds", ACCOUNT)

    def test_account_command_inputs_inherit_bounded_uuid_handle_and_reference_rules(self):
        for name in ("RemovePasskey", "SetDisplayName", "SetPrimaryHandle", "RemoveHandle"):
            request = re.search(
                rf"message {name}Request \{{(.*?)\n\}}", IDENTITY, re.S
            ).group(1)
            before_id = request.split("string client_operation_id = 1", 1)[0]
            self.assertIn("UUID", before_id, name)
            self.assertIn("45 ASCII bytes", before_id, name)
            if name in ("SetPrimaryHandle", "RemoveHandle"):
                self.assertIn("nonempty", request, name)
                self.assertIn("256 UTF-8 bytes", request, name)
                self.assertIn("before normalization", request, name)
                self.assertIn("provider qualifier", request, name)
                self.assertIn("parse_canonical_text", request, name)
            if name == "RemovePasskey":
                self.assertIn("unscoped", request)
                self.assertIn("spool absent", request)
                self.assertIn("1366", request)
        for requirement in ("32", "36", "38", "45", "urn:uuid:",
                            "parse_canonical_text", "is_valid_human_username",
                            "before normalization", "256 UTF-8 bytes"):
            self.assertIn(requirement, ACCOUNT)


if __name__ == "__main__":
    unittest.main()
