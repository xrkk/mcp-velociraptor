"""Windows fixture tests for the real selector CLI evidence namespace gate."""
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


def selector():
    path = Path(__file__).resolve().parents[1] / 'PLAN/2026.09.02' / (
        '2026.09.02-02-总纲-mcp-velociraptor-Windows-DFIR二次开发-长程执行'
    ) / '快照恢复选择器.py'
    spec = importlib.util.spec_from_file_location('namespace_selector', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RecoveryNamespaceTests(unittest.TestCase):
    def test_only_in_root_plain_file_can_reach_governed_action(self):
        module = selector()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'fixed'
            root.mkdir()
            inside = root / 'record.json'
            inside.write_text('{}')
            outside = Path(directory) / 'outside.json'
            outside.write_text('{}')
            with patch.object(module, 'EVIDENCE_ROOT', root):
                module.require_governed_evidence(inside)
                with self.assertRaises(module.StateError):
                    module.require_governed_evidence(outside)
                with self.assertRaises(module.StateError):
                    module.require_governed_evidence(root / '..' / 'outside.json')
                with self.assertRaises(module.StateError):
                    module.require_governed_evidence(root)


if __name__ == '__main__':
    unittest.main()
