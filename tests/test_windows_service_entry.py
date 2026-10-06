"""Exercise the formal launcher from SCM's unrelated working directory."""

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


class WindowsServiceEntryTests(unittest.TestCase):
    def test_launch_uses_deployed_adapter_and_preserves_exit_without_stdout(self):
        source = Path(__file__).resolve().parents[1] / "velociraptor_windows_service.py"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            deployment = root / "deployment"
            (deployment / "tests").mkdir(parents=True)
            shutil.copyfile(source, deployment / source.name)
            (deployment / "tests" / "p05_service_host.py").write_text(
                "def main():\n    return 37\n", encoding="utf-8"
            )
            foreign = root / "System32"
            foreign.mkdir()
            (foreign / "p05_service_host.py").write_text(
                "raise RuntimeError('wrong adapter')\n", encoding="utf-8"
            )
            result = subprocess.run(
                [sys.executable, str(deployment / source.name)], cwd=foreign,
                capture_output=True, timeout=10,
            )
            self.assertEqual(result.returncode, 37, result.stderr.decode())
            self.assertEqual(result.stdout, b"")
            self.assertEqual(result.stderr, b"")


if __name__ == "__main__":
    unittest.main()
