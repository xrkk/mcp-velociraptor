"""Host consumer graph regression with explicit issuer/writer native seams.

Reuse the complete CapabilityFixture and its synthetic receiver. Package
build/verify/fingerprint use real POSIX no-follow I/O without a reader seam.
These tests do not claim production Windows issuance or live DFIR coverage.
"""
import json
import os
import unittest

from tests import p06_pc021_consumer as consumer
from tests.test_p05_pc021_capability import CapabilityFixture


@unittest.skipUnless(os.name == 'posix', 'explicit host issuer/writer simulations')
class ConsumerContentHostTests(CapabilityFixture):
    def committed(self):
        case, canonical, capability = self.scene()
        result = self.run_writer(case, canonical, capability)
        self.assertEqual(result.status, 'COMMITTED')
        return case, canonical, result

    def admit(self, case, canonical, result):
        return consumer.verify_p06_admission(
            case, epoch7_canonical=self.c7, epoch8_canonical=canonical.read_bytes(),
            epoch8_receipt_path=result.receipt_path,
            policy=self.policy, root_policy=self.root_policy,
        )

    def test_real_portable_content_admits_complete_current_graph_read_only(self):
        case, canonical, result = self.committed()
        before = self.tree()
        admitted = self.admit(case, canonical, result)
        self.assertTrue(admitted['authorizes_p06'])
        self.assertEqual(admitted['phase_count'], 3)
        self.assertFalse(admitted['historical_only'])
        self.assertEqual(self.tree(), before)

    def test_corrupt_and_symlink_downloaded_member_refuse_read_only(self):
        case, canonical, result = self.committed()
        root = json.loads((case / 'activation-evidence.json').read_bytes())
        manifest_path = case / root['initial']['package_manifest']['path']
        manifest = json.loads(manifest_path.read_bytes())
        member = next(row for row in manifest['members'] if row['path'].startswith('downloads/'))
        path = manifest_path.parent / member['path']
        original = path.read_bytes()
        path.write_bytes(original + b'corrupt')
        before = self.tree()
        with self.assertRaisesRegex(Exception, 'downloaded member size or sha256 differs'):
            self.admit(case, canonical, result)
        self.assertEqual(self.tree(), before)
        path.write_bytes(original)
        external = self.parent / 'external-leaf.bin'
        path.rename(external)
        path.symlink_to(external)
        before = self.tree()
        with self.assertRaisesRegex(Exception, 'phase downloaded member is not one plain file'):
            self.admit(case, canonical, result)
        self.assertEqual(self.tree(), before)
        self.assertEqual(external.read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
