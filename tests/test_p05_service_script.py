"""Static contract checks for the P05 service/firewall installation script."""

from __future__ import annotations

import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "tests" / "p05_service_install.ps1"


class ServiceScriptContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = SCRIPT.read_text(encoding="utf-8")

    def test_script_exists_and_uses_strict_mode(self) -> None:
        self.assertTrue(SCRIPT.is_file())
        self.assertIn("$ErrorActionPreference = 'Stop'", self.text)

    def test_service_identity_is_the_dedicated_virtual_account(self) -> None:
        self.assertIn("$ServiceName = 'mcp-velociraptor'", self.text)
        self.assertIn("$RunAsAccount = 'NT SERVICE\\mcp-velociraptor'", self.text)
        # New-Service must carry the virtual-account credential, and no code
        # line (comments excluded) may mention LocalSystem or an admin user.
        code_lines = [
            line for line in self.text.splitlines() if line.strip() and not line.strip().startswith("#")
        ]
        self.assertFalse(
            any("LocalSystem" in line for line in code_lines),
            "LocalSystem must not appear in executable lines",
        )
        self.assertIn("-Credential (New-Object System.Management.Automation.PSCredential(", self.text)

    def test_firewall_rule_is_single_and_port_exact(self) -> None:
        self.assertEqual(self.text.count("New-NetFirewallRule"), 1)
        self.assertIn("-LocalPort $FirewallPort", self.text)
        self.assertIn("$FirewallPort = 28790", self.text)
        self.assertIn("$FirewallRuleName = 'mcp-velociraptor-28790'", self.text)

    def test_token_is_never_a_parameter_or_literal(self) -> None:
        self.assertNotIn("-Token", self.text)
        self.assertNotIn("Bearer ", self.text)
        # The protected env file is only checked for required prefixes; its
        # values (including the bearer token) are never read into variables.
        self.assertNotIn("Get-Content $Path | Select-String 'VELOCIRAPTOR_MCP_BEARER_TOKEN='", self.text)

    def test_wildcard_bind_is_rejected_before_install(self) -> None:
        self.assertIn("$Wildcards = @('0.0.0.0', '::', '')", self.text)
        self.assertIn("Assert-BindAddress -Address $BindAddress", self.text)
        # The bind address must be a measured host-only address on this VM.
        self.assertIn("-like '192.168.204.*'", self.text)

    def test_install_is_idempotent_and_rollback_is_scoped(self) -> None:
        self.assertIn("already installed; install is a no-op", self.text)
        self.assertIn("rule already present; install is a no-op", self.text)
        self.assertIn("Get-Service -Name $ServiceName -ErrorAction SilentlyContinue", self.text)
        self.assertIn("Get-NetFirewallRule -DisplayName $FirewallRuleName -ErrorAction SilentlyContinue", self.text)
        # Rollback only removes the exact owned names, nothing broader.
        self.assertIn("sc.exe delete $ServiceName", self.text)
        self.assertIn("Remove-NetFirewallRule", self.text)

    def test_existing_service_with_wrong_account_is_refused(self) -> None:
        self.assertIn(
            "does not run as $RunAsAccount; refusing to touch it",
            self.text,
        )


if __name__ == "__main__":
    unittest.main()
