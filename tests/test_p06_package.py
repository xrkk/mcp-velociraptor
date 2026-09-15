"""Isolated package primitives; not a substitute for formal P06 acceptance."""

import hashlib
import tempfile
import unittest
import zipfile
from pathlib import Path

from tests.p06_evidence import EvidenceError, plain_file
from tests.p06_package import (
    canonical_bytes,
    member_inventory,
    source_for_member,
    verify_manifest,
    verify_payload_zip,
)


class PackageTests(unittest.TestCase):
    def test_receipt_is_append_only_and_rejects_duplicate_attempt(self):
        from tests.p06_receive import receive
        from tests.p06_aggregate_reports import load_ledger
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for number in (1,2):
                run = root/str(number)
                run.mkdir()
                (run/'report.json').write_bytes(canonical_bytes({
                    'status':'failed','scenario':'unit','run_id':str(number),
                    'failure':{'message':'synthetic failure'},'coverage':[]}))
                (run/'package-manifest.json').write_bytes(canonical_bytes(member_inventory(run,root)))
                self.assertEqual(receive(run,root)['monotonic_attempt'],number)
            original = (root/'接收清单.jsonl').read_bytes()
            with self.assertRaises(ValueError):
                receive(run,root)
            self.assertEqual((root/'接收清单.jsonl').read_bytes(),original)
            self.assertEqual(len(load_ledger(root/'接收清单.jsonl',root)),2)
            self.assertFalse((root/'.receive.lock').exists())

    def test_receipt_rejects_failed_coverage(self):
        from tests.p06_receive import receive
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/'report.json').write_bytes(canonical_bytes({
                'status':'failed','scenario':'unit','failure':{'message':'x'},'coverage':['bad']}))
            (root/'package-manifest.json').write_bytes(canonical_bytes(member_inventory(root,root)))
            with self.assertRaises(ValueError):
                receive(root,root)
            self.assertFalse((root/'接收清单.jsonl').exists())

    def make_payload(self, root, *, extra=False, altered=False):
        (root / 'report.json').write_bytes(b'{}\n')
        manifest = canonical_bytes(member_inventory(root, root, payload=True))
        (root / 'qualification-payload-manifest.json').write_bytes(manifest)
        with zipfile.ZipFile(root / 'qualification-payload.zip', 'w') as archive:
            archive.writestr('qualification-payload-manifest.json', manifest)
            archive.writestr('run/report.json', b'[]\n' if altered else b'{}\n')
            if extra:
                archive.writestr('../escape', b'extra')

    def test_payload_zip_binds_originals_without_extracting(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_payload(root)
            result = verify_payload_zip(root, root)
            raw = (root / 'qualification-payload.zip').read_bytes()
            self.assertEqual(result['payload_sha256'], hashlib.sha256(raw).hexdigest())
            self.assertEqual(result['evidence_reserve_bytes'], len(raw))
            self.assertFalse((root / 'run').exists())

    def test_payload_zip_rejects_undeclared_or_changed_bytes(self):
        for extra, altered in ((True, False), (False, True)):
            with self.subTest(extra=extra, altered=altered), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.make_payload(root, extra=extra, altered=altered)
                with self.assertRaises(EvidenceError):
                    verify_payload_zip(root, root)

    def test_payload_zip_rejects_corrupt_container(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_payload(root)
            (root / 'qualification-payload.zip').write_bytes(b'not a zip')
            with self.assertRaises(EvidenceError):
                verify_payload_zip(root, root)

    def test_noncanonical_relative_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'file').write_bytes(b'original')
            for name in ('./file', 'a/../file', 'a//file', 'file/', '/file',
                         'C:/file', 'a\\file', ''):
                with self.subTest(name=name), self.assertRaises((EvidenceError, OSError)):
                    plain_file(root, name)

    def test_nested_bytes_and_lengths_are_canonical_and_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'nested').mkdir()
            (root / 'nested' / '原件').write_bytes(b'abc')
            expected = {'schema_version': 1, 'members': [{
                'path': 'run/nested/原件', 'size': 3,
                'sha256': hashlib.sha256(b'abc').hexdigest(),
            }]}
            self.assertEqual(member_inventory(root, root), expected)
            raw = canonical_bytes(expected)
            (root / 'package-manifest.json').write_bytes(raw)
            self.assertEqual(verify_manifest(root, root), hashlib.sha256(raw).hexdigest())
            (root / 'nested' / '原件').write_bytes(b'abcd')
            with self.assertRaises(EvidenceError):
                verify_manifest(root, root)

    def test_extra_member_and_noncanonical_manifest_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = canonical_bytes(member_inventory(root, root))
            manifest = root / 'package-manifest.json'
            manifest.write_bytes(original + b'\n')
            with self.assertRaises(EvidenceError):
                verify_manifest(root, root)
            manifest.write_bytes(original)
            (root / 'extra').write_bytes(b'x')
            with self.assertRaises(EvidenceError):
                verify_manifest(root, root)

    def test_payload_excludes_only_its_root_self_references(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ('package-manifest.json', 'qualification-payload-manifest.json',
                         'qualification-payload.zip', 'resource-budget.json', 'report.json'):
                (root / name).write_bytes(b'{}')
            (root / 'nested').mkdir()
            (root / 'nested' / 'resource-budget.json').write_bytes(b'{}')
            paths = [row['path'] for row in member_inventory(root, root, payload=True)['members']]
            self.assertEqual(paths, ['run/nested/resource-budget.json', 'run/report.json'])
            final = member_inventory(root, root)['members']
            self.assertEqual(len(final), 5)

    def test_restore_originals_are_bound_and_deduplicated(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run = root / 'run'
            run.mkdir()
            (root / 'original').write_bytes(b'raw')
            record = {'path': 'original', 'sha256': hashlib.sha256(b'raw').hexdigest()}
            (run / 'snapshot-evidence.json').write_bytes(canonical_bytes({
                'restore': {'restore_records': [record, record]},
            }))
            rows = member_inventory(run, root)['members']
            self.assertEqual(sum(row['path'] == 'restore/original' for row in rows), 1)
            (root / 'original').write_bytes(b'changed')
            with self.assertRaises(EvidenceError):
                member_inventory(run, root)

    def test_snapshot188_activation_bundle_is_recursively_packaged_per_attempt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run = root / 'run'
            run.mkdir()
            bundle = root / 'activation-188' / '123e4567-e89b-12d3-a456-426614174000'
            (bundle / 'p05-originals' / 'reports').mkdir(parents=True)
            (bundle / 'source').mkdir()
            activation = bundle / 'activation-evidence.json'
            activation.write_bytes(b'{"kind":"snapshot188"}\n')
            (bundle / 'p05-originals' / 'reports' / 'initial.json').write_bytes(b'initial')
            (bundle / 'source' / 'p05-plan.md').write_bytes(b'plan')
            record = {
                'kind': 'activation_evidence',
                'path': activation.relative_to(root).as_posix(),
                'sha256': hashlib.sha256(activation.read_bytes()).hexdigest(),
            }
            (run / 'snapshot-evidence.json').write_bytes(canonical_bytes({
                'restore': {
                    'restore_attempt_id': 'restore-unit',
                    'restore_records': [record],
                },
            }))

            paths = {row['path'] for row in member_inventory(run, root)['members']}
            self.assertTrue({
                'restore/restore-unit/activation/activation-evidence.json',
                'restore/restore-unit/activation/p05-originals/reports/initial.json',
                'restore/restore-unit/activation/source/p05-plan.md',
            }.issubset(paths))
            self.assertNotIn('restore/' + record['path'], paths)
            self.assertEqual(
                source_for_member(
                    run,
                    root,
                    'restore/restore-unit/activation/p05-originals/reports/initial.json',
                ).read_bytes(),
                b'initial',
            )

    def test_user187_adoption_bundle_is_recursively_packaged_per_attempt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run = root / 'run'
            run.mkdir()
            bundle = root / 'baseline-adoption' / '123e4567-e89b-12d3-a456-426614174187'
            (bundle / 'source').mkdir(parents=True)
            adoption = bundle / 'adoption.json'
            adoption.write_bytes(b'{"kind":"user187-preparation-adoption-v1"}\n')
            (bundle / 'old-canonical.json').write_bytes(b'old canonical')
            (bundle / 'source' / 'self-review.md').write_bytes(b'review')
            record = {
                'kind': 'baseline_adoption',
                'path': adoption.relative_to(root).as_posix(),
                'sha256': hashlib.sha256(adoption.read_bytes()).hexdigest(),
            }
            (run / 'snapshot-evidence.json').write_bytes(canonical_bytes({
                'restore': {
                    'restore_attempt_id': 'restore-unit',
                    'restore_records': [record],
                },
            }))

            paths = {row['path'] for row in member_inventory(run, root)['members']}
            self.assertTrue({
                'restore/restore-unit/baseline-adoption/adoption.json',
                'restore/restore-unit/baseline-adoption/old-canonical.json',
                'restore/restore-unit/baseline-adoption/source/self-review.md',
            }.issubset(paths))
            self.assertNotIn('restore/' + record['path'], paths)
            self.assertEqual(
                source_for_member(
                    run,
                    root,
                    'restore/restore-unit/baseline-adoption/source/self-review.md',
                ).read_bytes(),
                b'review',
            )


if __name__ == '__main__':
    unittest.main()
