"""Static regressions for the P05 guest ready collector.

No test invokes guest commands from the host.  Mocked Windows behaviour is
reserved for the Windows VM acceptance run; these checks only compile and
inspect the declared action surface here.
"""

from __future__ import annotations

import ast
import os
from pathlib import Path
import py_compile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tests" / "p05_ready_collect.py"


@unittest.skipUnless(os.name == "nt", "CON002: test execution is reserved for Windows")
class ReadyCollectorStaticTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = SOURCE.read_text(encoding="utf-8")
        self.tree = ast.parse(self.text, filename=str(SOURCE))

    def test_compiles_without_running_guest_collection(self) -> None:
        py_compile.compile(str(SOURCE), doraise=True)

    def test_accepts_outer_run_restore_and_source_bundle_but_has_no_cli(self) -> None:
        function = next(node for node in self.tree.body if isinstance(node, ast.FunctionDef) and node.name == "collect_guest_ready")
        self.assertEqual([argument.arg for argument in function.args.kwonlyargs], ["run", "restoreidentity", "sourcebundle", "evidence_directory"])
        self.assertNotIn("argparse", self.text)
        self.assertNotIn("if __name__", self.text)

    def test_declares_exact_guest_scope_and_keeps_host_observations_external(self) -> None:
        module = ast.literal_eval(next(node.value for node in self.tree.body if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "OBSERVATIONS" for target in node.targets)))
        self.assertEqual(set(module), {"guest_identity", "fixture_instance", "fixture_static", "parent_bindings", "guest_processes", "dependencies", "service", "acl", "firewall", "resources"})
        self.assertNotIn("host_clock", module)
        self.assertNotIn("host_processes", module)

    def test_static_action_surface_is_read_only_and_failure_is_not_success(self) -> None:
        forbidden = ("Start-Service", "Stop-Service", "Restart-Service", "Set-Acl", "New-NetFirewallRule", "Remove-NetFirewallRule", "Start-Process", "Stop-Process", "trace stop", "inventory_add", "artifact_set", "cancel_flow", "start_collection")
        for token in forbidden:
            self.assertNotIn(token, self.text)
        self.assertIn("exist_ok=False", self.text)
        self.assertIn('"kind": "p05-ready-command-v1"', self.text)
        self.assertIn("verify_local_public_bytes", self.text)
        self.assertIn("urllib.request.urlopen", self.text)
        self.assertIn("resource_creators", self.text)
        self.assertIn("security_descriptor_base64", self.text)
        self.assertIn("Get-ChildItem -LiteralPath", self.text)
        self.assertIn("runtime_logs_root", self.text)
        self.assertNotIn("ACL observation covers only", self.text)

    def test_command_line_disclosure_is_limited_to_approved_pid_projection(self) -> None:
        self.assertIn("$approved -contains $_.ProcessId", self.text)
        self.assertIn("guest process transcript exposes a non-approved", (ROOT / "tests" / "p05_ready_evidence.py").read_text(encoding="utf-8"))
        self.assertIn("protected configuration", self.text.casefold())
        self.assertNotIn("read_text", self.text[self.text.index("def _acl"):self.text.index("def _firewall")])

    def test_acl_collector_keeps_sid_as_array_and_rejects_reparse_before_enumeration(self) -> None:
        acl = self.text[self.text.index("def _acl"):self.text.index("def _firewall")]
        self.assertIn("$sid=@((sc.exe showsid", acl)
        node = acl[acl.index("function TreeNode"):]
        self.assertLess(node.index("if($i.is_reparse_point)"), node.index("Get-ChildItem"))

    def test_dependency_witness_identity_and_unfiltered_windows_inventory_are_retained(self) -> None:
        self.assertIn('local_public_bytes.append({"name": name, **observed})', self.text)
        identity = self.text[self.text.index("def _guest_identity"):self.text.index("def _dependencies")]
        self.assertIn("FROM clients() WHERE os_info.system = 'windows'", identity)
        self.assertNotIn("WHERE client_id", identity)
        self.assertIn("@($task.Actions).Count -ne 1", self.text)

    @unittest.skipUnless(os.name == "nt", "mocked collector contract is reserved for the Windows guest")
    def test_mocked_failed_command_preserves_a_non_success_transcript(self) -> None:
        # This is intentionally a mock-only Windows regression.  It does not
        # launch PowerShell, make a VQL call, or inspect the host process table.
        from tests import p05_ready_collect as collect

        result = collect.CommandResult(
            argv=("powershell.exe", "-Command", "fixed-read-only-query"),
            stdout="{\"partial\":true}",
            stderr="actual backend failure",
            exit_code=1,
            started_at="2026-09-14T00:00:00.000Z",
            ended_at="2026-09-14T00:00:01.000Z",
        )
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(collect.ReadyCollectionError):
                collect._record(Path(directory), "dependencies", "run", "restore", result)
            raw = (Path(directory) / "dependencies.json").read_text(encoding="utf-8")
        self.assertIn('"code":1', raw)
        self.assertIn("actual backend failure", raw)
        self.assertNotIn('"ok":true', raw)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
