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
        self.assertIn("sc.exe create $ServiceName binPath= $binPath obj= $RunAsAccount start= demand", self.text)
        self.assertIn("-Name VELOCIRAPTOR_ENV_FILE -PropertyType String", self.text)
        self.assertIn("tests\\p05_service_host.py", self.text)
        self.assertIn("$Service.StartName -ne $RunAsAccount", self.text)
        self.assertNotIn(".UserName", self.text)

    def test_firewall_rule_is_single_and_port_exact(self) -> None:
        self.assertEqual(self.text.count("New-NetFirewallRule"), 1)
        self.assertIn("-LocalPort $FirewallPort", self.text)
        self.assertIn("$FirewallPort = 28790", self.text)
        self.assertIn("$FirewallRuleName = 'mcp-velociraptor-28790'", self.text)

    def test_token_is_never_a_parameter_or_literal(self) -> None:
        self.assertNotIn("-Token", self.text)
        self.assertNotIn("Bearer ", self.text)
        # Configuration is read inside the installer process, never emitted.
        self.assertNotIn("Get-Content $Path | Select-String 'VELOCIRAPTOR_MCP_BEARER_TOKEN='", self.text)

    def test_wildcard_bind_is_rejected_before_install(self) -> None:
        self.assertIn("$Wildcards = @('0.0.0.0', '::', '')", self.text)
        self.assertIn("Assert-BindAddress -Address $BindAddress", self.text)
        self.assertIn("Where-Object IPAddress -eq $Address", self.text)
        self.assertIn("PrefixOrigin -ne 'Manual'", self.text)

    def test_install_is_idempotent_and_rollback_is_scoped(self) -> None:
        self.assertIn("already installed; install is a no-op", self.text)
        self.assertIn("rule already present; install is a no-op", self.text)
        self.assertIn("Get-CimInstance Win32_Service", self.text)
        self.assertIn("Get-NetFirewallRule -PolicyStore ActiveStore", self.text)
        # Rollback only removes the exact owned names, nothing broader.
        self.assertIn("sc.exe delete $ServiceName", self.text)
        self.assertIn("Remove-NetFirewallRule", self.text)

    def test_existing_service_with_wrong_account_is_refused(self) -> None:
        self.assertIn(
            "Existing service identity differs; refusing to touch it",
            self.text,
        )

    def test_firewall_sources_are_exact_not_a_subnet(self) -> None:
        self.assertIn("-LocalAddress $BindAddress -RemoteAddress $HostAddress", self.text)
        self.assertNotIn("192.168.204", self.text)
        self.assertIn("Assert-RuleIdentity $rules[0]", self.text)

    def test_rollback_requires_ownership_before_deletion(self) -> None:
        rollback = self.text.split("function Invoke-Rollback {", 1)[1]
        self.assertLess(rollback.index("$tag.P05CreatedBy -cne $Owner"), rollback.index("sc.exe delete"))
        self.assertLess(rollback.index("$rules[0].Description -cne $Owner"), rollback.index("sc.exe delete"))
        self.assertNotIn("Stop-Service", rollback)

    def test_service_host_does_not_dump_deployment_environment(self) -> None:
        # The previous diagnostic wrote the first four token characters.
        # This source guard is not a substitute for Windows service testing.
        host = (REPO_ROOT / "tests" / "p05_service_host.py").read_text(encoding="utf-8")
        self.assertNotIn("service-host-env.log", host)
        self.assertNotIn("os.environ.items()", host)
        self.assertNotIn("value[:4]", host)

    def test_path_preflight_precedes_protected_content_and_installation(self) -> None:
        install = self.text.split('function Invoke-Install {', 1)[1].split('function Invoke-Verify {', 1)[0]
        self.assertLess(install.index('Assert-DeploymentPaths'), install.index('Assert-ProtectedEnv'))
        self.assertLess(install.index('Assert-DeploymentPaths'), install.index('sc.exe create'))
        self.assertIn('[IO.FileAttributes]::ReparsePoint', self.text)
        # The preflight walks every ancestor through Get-Item; .Parent/.Directory
        # instances lack the provider-added PSProvider property under StrictMode.
        self.assertIn('$ancestor = Get-Item -LiteralPath $prefix -Force', self.text)
        self.assertIn("$ancestor.PSProvider.Name -ne 'FileSystem'", self.text)
        verify = self.text.split('function Invoke-Verify {', 1)[1].split('function Invoke-Rollback {', 1)[0]
        self.assertIn('Assert-DeploymentPaths', verify)
        self.assertIn('Assert-ProtectedEnv -Path $ProtectedEnvFile', verify)

    def test_existing_automatic_service_is_preserved_and_reported(self) -> None:
        self.assertIn("$Service.StartMode -notin @('Manual', 'Auto')", self.text)
        self.assertIn('$result.service_start_mode = $service.StartMode', self.text)
        self.assertNotIn('Set-Service', self.text)

    def test_secret_acl_is_checked_before_read_and_code_tree_is_read_only(self) -> None:
        config = self.text.split('function Assert-ProtectedEnv {', 1)[1].split('function Get-ServiceOrNull', 1)[0]
        self.assertLess(config.index('Assert-PathAcl -Path $Path -Role secret'), config.index('Get-Content'))
        self.assertIn('Assert-CodeTreeAcl -ServiceSid $serviceSid', config)
        self.assertIn('Assert-PathAcl -Path $path -Role code', self.text)
        self.assertIn('unapproved principal write access', self.text)
        self.assertNotIn('Set-Acl', self.text)


if __name__ == "__main__":
    unittest.main()
