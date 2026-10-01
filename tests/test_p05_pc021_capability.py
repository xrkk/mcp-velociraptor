"""PC021 capability host seams over a complete synthetic content graph.

Requires the existing PC020 fixture environment, never edits the input trees.
All outputs live under PC020_TEST_TEMP_ROOT. Only Windows native refresh,
directory identity and replace are simulated; graph predicates are real.
Receiver observations are explicitly synthetic, not evidence of a live host.
"""
from __future__ import annotations

import json
import copy
import gc
import importlib.util
import os
import shutil
import tempfile
import unittest
import uuid
import pickle
import threading
import sys
import weakref
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from tests import p05_pc020_activation as graph
from tests import p05_pc020_evidence as evidence
from tests import p05_pc021_activation_writer as writer
from tests import p05_pc021_issuer as issuer
from tests import pc022_windows_refresh as refresh
from tests import p06_pc021_consumer as consumer
from tests.pc020_activation_fixture import ActivationFixture


class CapabilityFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        names = {
            'historical': 'PC020_ACTIVATION188_FIXTURE',
            'predecessor': 'PC020_PREDECESSOR_FIXTURE',
            'baseline': 'PC020_BASELINE_DIR_FIXTURE',
            'old_activation': 'PC020_ACTIVATION_DIR_FIXTURE',
            'sources': 'PC020_REAL_SOURCE_ROOT',
        }
        values = {key: os.environ.get(env) for key, env in names.items()}
        missing = [key for key, value in values.items() if not value or not Path(value).exists()]
        if missing or not os.environ.get('PC020_TEST_TEMP_ROOT'):
            raise RuntimeError(f'PC020 fixture inputs/output root required: {missing}')
        cls.temp = tempfile.TemporaryDirectory(dir=os.environ['PC020_TEST_TEMP_ROOT'])
        cls.parent = Path(cls.temp.name).resolve()
        cls.base = cls.parent / 'activation-189' / str(uuid.uuid4())
        payload = {
            'schema_version': 1, 'observer_ipv4': '192.168.204.1',
            'endpoint': 'http://192.168.204.1:28786/',
            'interface_ipv4': ['192.168.204.1'], 'rows': [],
        }
        with patch('tests.test_p05_pc020_evidence.receiver_document',
                   return_value=(0, json.dumps(payload) + '\n', '')):
            fixture = ActivationFixture(
                cls.base, Path(values['historical']), Path(values['predecessor']).read_bytes(),
                Path(values['baseline']), Path(values['old_activation']),
                Path(values['sources']), Path(__file__).resolve().parents[1],
            )
        cls.policy, cls.root_policy = fixture.policy, fixture.root_policy
        cls.c7 = fixture.canonical_bytes
        cls.draft = json.loads((cls.base / 'activation-evidence.json').read_bytes())
        cls.draft.pop('issued_at')
        # This is a complete, valid graph before any capability assertion.
        cls.facts = graph.verify_snapshot189_activation(
            cls.base / 'activation-evidence.json', policy=cls.policy,
            root_policy=cls.root_policy, epoch7_canonical=cls.c7,
        )

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.seams = ExitStack()
        self.addCleanup(self.seams.close)
        self.seams.enter_context(patch.object(refresh, 'windows_refresh_directory', return_value={}))
        self.seams.enter_context(patch.object(refresh, 'handle_directory_identity',
                                             side_effect=lambda p: (p.stat().st_dev, p.stat().st_ino)))
        self.seams.enter_context(patch.object(refresh, 'windows_replace_file',
                                             side_effect=lambda source, target: os.replace(source, target)))

    def unissued(self):
        case = self.base.parent / str(uuid.uuid4())
        shutil.copytree(self.base, case)
        (case / 'activation-evidence.json').unlink()
        (case / 'issuance-receipt.json').unlink()
        canonical = self.parent / f'canonical-{uuid.uuid4()}.json'
        canonical.write_bytes(self.c7)
        return case, canonical

    def issue(self, case):
        return issuer.issue_activation(
            case, root_draft=json.loads(json.dumps(self.draft)), policy=self.policy,
            root_policy=self.root_policy, epoch7_canonical=self.c7,
        )

    def scene(self):
        case, canonical = self.unissued()
        return case, canonical, self.issue(case).capability

    def run_writer(self, case, canonical, capability):
        return writer.transition_to_epoch8(
            canonical, case, capability, policy=self.policy, root_policy=self.root_policy,
        )

    def tree(self):
        return {p.relative_to(self.parent).as_posix(): evidence._sha(p.read_bytes())
                for p in self.parent.rglob('*') if p.is_file()}


FIELDS = ('operation', 'workflow_id', 'issuance_id', 'epoch7_sha256',
          'activation_root_sha256', 'issuance_receipt_sha256')


class CapabilityAdmissionTests(CapabilityFixture):
    def assert_refused_clean(self, case, canonical, capability, reason):
        before = self.tree()
        actual_open = Path.open
        with patch.object(writer, '_create_durable', wraps=writer._create_durable) as creates, \
             patch.object(Path, 'open', autospec=True, side_effect=actual_open) as opens, \
             patch.object(Path, 'unlink', autospec=True, side_effect=Path.unlink) as unlinks, \
             patch.object(Path, 'rename', autospec=True, side_effect=Path.rename) as renames, \
             patch.object(refresh, 'windows_refresh_directory', wraps=refresh.windows_refresh_directory) as refreshes, \
             patch.object(refresh, 'windows_replace_file', wraps=refresh.windows_replace_file) as replaces:
            with self.assertRaisesRegex(writer.Epoch8TransitionError, reason) as raised:
                self.run_writer(case, canonical, capability)
        self.assertEqual(creates.call_count, 0)
        for opened in opens.call_args_list:
            mode = opened.args[1] if len(opened.args) > 1 else opened.kwargs.get('mode', 'r')
            self.assertFalse(set(mode) & set('wax+'), mode)
        self.assertEqual((unlinks.call_count, renames.call_count, refreshes.call_count,
                          replaces.call_count), (0, 0, 0, 0))
        self.assertEqual(self.tree(), before)
        self.assertFalse(raised.exception.outcome.receipt_written)
        self.assertFalse(raised.exception.outcome.receipt_path.exists())
        return raised.exception

    def test_mint_commit_exact_records_and_downstream_without_capability(self):
        case, canonical, capability = self.scene()
        self.assertFalse(capability.spent)
        self.assertEqual(self.facts['phase_count'], 3)
        self.assertFalse(self.facts['authorizes_activation_write'])
        result = self.run_writer(case, canonical, capability)
        self.assertEqual(result.status, writer.COMMITTED)
        self.assertTrue(capability.spent)
        intent = json.loads(result.intent_path.read_bytes())
        receipt = json.loads(result.receipt_path.read_bytes())
        self.assertEqual(set(intent), writer.INTENT_V2_KEYS)
        self.assertEqual(set(receipt), writer.RECEIPT_V3_KEYS)
        self.assertEqual(receipt['kind'], writer.RECEIPT_V3_KIND)
        self.assertEqual(receipt['from_sha256'], evidence._sha(self.c7))
        self.assertEqual(receipt['to_sha256'], evidence._sha(canonical.read_bytes()))
        self.assert_refused_clean(case, canonical, capability, 'already spent')
        del capability
        gc.collect()
        admitted = consumer.verify_p06_admission(
            case, policy=self.policy, root_policy=self.root_policy,
            epoch7_canonical=self.c7, epoch8_canonical=canonical.read_bytes(),
            epoch8_receipt_path=result.receipt_path,
        )
        self.assertTrue(admitted['authorizes_p06'])

    def test_public_fields_copy_serialization_and_object_origin_cannot_authorize(self):
        case, canonical, capability = self.scene()
        fields = {name: getattr(capability, name) for name in FIELDS}
        with self.assertRaisesRegex(TypeError, 'minted only'):
            issuer.IssuanceCapability(**fields)
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with self.subTest(operation=operation.__name__), self.assertRaises(TypeError):
                operation(capability)
        # Even allocation without __init__ plus copying every field gives no
        # registry identity. Reflection here tests the origin check, not a
        # claim of defending trusted controller internals against hostile code.
        foreign = object.__new__(issuer.IssuanceCapability)
        for name, value in fields.items():
            object.__setattr__(foreign, name, value)
        self.assert_refused_clean(case, canonical, foreign, 'not minted')
        self.assert_refused_clean(case, canonical, json.loads(json.dumps(fields)), 'private issuance')
        self.assertFalse(capability.spent)

    def test_every_binding_and_wrong_activation_directory_refuse_unspent(self):
        case, canonical, capability = self.scene()
        for name in FIELDS:
            original = getattr(capability, name)
            object.__setattr__(capability, name, 'different')
            try:
                with self.subTest(field=name):
                    self.assert_refused_clean(case, canonical, capability, 'bindings differ')
                    self.assertFalse(capability.spent)
            finally:
                object.__setattr__(capability, name, original)
        other, _, other_capability = self.scene()
        self.assert_refused_clean(other, canonical, capability, 'not bound')
        self.assertFalse(capability.spent)
        self.assertFalse(other_capability.spent)

    def test_actual_c7_r_s_hash_mismatch_has_zero_writes(self):
        case, canonical, capability = self.scene()
        for path in (canonical, case/'activation-evidence.json', case/'issuance-receipt.json'):
            original = path.read_bytes()
            path.write_bytes(original + b'\n')
            try:
                with self.subTest(file=path.name):
                    self.assert_refused_clean(case, canonical, capability, 'hashes differ')
                    self.assertFalse(capability.spent)
            finally:
                path.write_bytes(original)

    def test_recursive_graph_drift_refuses_unspent_with_valid_c7_r_s(self):
        case, canonical, capability = self.scene()
        root = json.loads((case/'activation-evidence.json').read_bytes())
        leaf = case / root['source_inputs'][0]['content']['path']
        original = leaf.read_bytes()
        leaf.write_bytes(original + b'\n')
        self.assert_refused_clean(case, canonical, capability, 'identity|differs')
        self.assertFalse(capability.spent)

    def test_all_admission_reads_and_graph_validation_are_under_one_lock(self):
        case, canonical, capability = self.scene()
        state = issuer._capability_state(capability)
        actual_open = Path.open
        checked = []
        paths = {canonical, case/'activation-evidence.json', case/'issuance-receipt.json'}
        def opened(path, mode='r', *args, **kwargs):
            if path in paths and 'r' in mode and not state.spent:
                self.assertTrue(state.lock.locked(), str(path))
                checked.append(path)
            return actual_open(path, mode, *args, **kwargs)
        with patch.object(Path, 'open', opened):
            result = self.run_writer(case, canonical, capability)
        self.assertEqual(result.status, writer.COMMITTED)
        self.assertTrue(paths.issubset(set(checked)))
        self.assertGreaterEqual(checked.count(canonical), 2)
        self.assertGreaterEqual(checked.count(case/'activation-evidence.json'), 2)
        self.assertGreaterEqual(checked.count(case/'issuance-receipt.json'), 2)

    def test_concurrent_loser_has_no_reads_or_file_actions_and_preserves_winner(self):
        case, canonical, capability = self.scene()
        state = issuer._capability_state(capability)
        reading, release_read, loser_lookup = threading.Event(), threading.Event(), threading.Event()
        creating, release_create = threading.Event(), threading.Event()
        consume, read, create = issuer._consume_for_writer, writer._read, writer._create_durable
        calls = []
        def consume_spy(cap, verify):
            if threading.current_thread().name == 'loser':
                loser_lookup.set()
            return consume(cap, verify)
        def read_spy(path):
            calls.append(('read', threading.current_thread().name, str(path)))
            if path == canonical and not state.spent and not reading.is_set():
                self.assertTrue(state.lock.locked())
                reading.set()
                self.assertTrue(release_read.wait(30))
            return read(path)
        def create_spy(path, payload):
            calls.append(('create', threading.current_thread().name, str(path)))
            if str(path).endswith('.next'):
                creating.set()
                self.assertTrue(release_create.wait(30))
            return create(path, payload)
        def invoke(label):
            threading.current_thread().name = label
            try:
                return self.run_writer(case, canonical, capability)
            except writer.Epoch8TransitionError as exc:
                return exc
        with patch.object(issuer, '_consume_for_writer', side_effect=consume_spy), \
             patch.object(writer, '_read', side_effect=read_spy), \
             patch.object(writer, '_create_durable', side_effect=create_spy):
            with ThreadPoolExecutor(max_workers=2) as pool:
                winner = pool.submit(invoke, 'winner')
                try:
                    self.assertTrue(reading.wait(30))
                    loser = pool.submit(invoke, 'loser')
                    self.assertTrue(loser_lookup.wait(30))
                    self.assertFalse(loser.done())
                    release_read.set()
                    self.assertTrue(creating.wait(30))
                    before = self.tree()
                    refusal = loser.result(timeout=30)
                    self.assertIsInstance(refusal, writer.Epoch8TransitionError)
                    self.assertIn('already spent', str(refusal))
                    self.assertFalse(refusal.outcome.receipt_written)
                    self.assertEqual(self.tree(), before)
                finally:
                    release_read.set()
                    release_create.set()
                committed = winner.result(timeout=30)
        self.assertEqual(committed.status, writer.COMMITTED)
        self.assertEqual([c for c in calls if c[1] == 'loser'], [])
        self.assertEqual(len([c for c in calls if c[0] == 'create']), 3)
        self.assertTrue(capability.spent)
        self.assert_refused_clean(case, canonical, capability, 'already spent')

    def test_receipt_file_fsync_failure_with_parseable_graph_mints_nothing(self):
        case, canonical = self.unissued()
        fsync = os.fsync
        def fail_receipt(fd):
            # The receipt fsync is the second file fsync in the real issuer.
            fail_receipt.calls += 1
            if fail_receipt.calls == 2:
                raise OSError('receipt file fsync failed')
            return fsync(fd)
        fail_receipt.calls = 0
        registered = list(issuer._minted)
        with patch.object(os, 'fsync', side_effect=fail_receipt):
            with self.assertRaisesRegex(OSError, 'receipt file fsync failed'):
                self.issue(case)
        self.assertEqual(list(issuer._minted), registered)
        json.loads((case/'issuance-receipt.json').read_bytes())
        facts = graph.verify_snapshot189_activation(
            case/'activation-evidence.json', policy=self.policy,
            root_policy=self.root_policy, epoch7_canonical=self.c7,
        )
        self.assertFalse(facts['authorizes_activation_write'])
        self.assert_refused_clean(case, canonical, None, 'private issuance')
        before = self.tree()
        with self.assertRaisesRegex(issuer.IssuerError, 'already exists'):
            self.issue(case)
        self.assertEqual(self.tree(), before)

    def test_lost_capability_and_new_controller_cannot_resume_disk_receipt(self):
        case, canonical, capability = self.scene()
        fields = {name: getattr(capability, name) for name in FIELDS}
        spec = importlib.util.spec_from_file_location('pc021_new_controller', issuer.__file__)
        fresh = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {spec.name: fresh}):
            spec.loader.exec_module(fresh)
            with self.assertRaisesRegex(fresh.IssuerError, 'private issuance'):
                fresh._capability_state(capability)
            with self.assertRaisesRegex(TypeError, 'minted only'):
                fresh.IssuanceCapability(**fields)
        lost = weakref.ref(capability)
        del capability
        gc.collect()
        self.assertIsNone(lost())
        with self.assertRaises(TypeError):
            issuer.IssuanceCapability(**fields)
        self.assert_refused_clean(case, canonical, None, 'private issuance')
        before = self.tree()
        with self.assertRaisesRegex(issuer.IssuerError, 'already exists'):
            self.issue(case)
        self.assertEqual(self.tree(), before)

    def test_consumed_first_file_failure_cannot_reuse_authority(self):
        case, canonical, capability = self.scene()
        create = writer._create_durable
        def fail_first(path, payload):
            if str(path).endswith('.next'):
                self.assertTrue(capability.spent)
                raise OSError('before first file create')
            return create(path, payload)
        with patch.object(writer, '_create_durable', side_effect=fail_first):
            with self.assertRaises(writer.Epoch8TransitionError) as raised:
                self.run_writer(case, canonical, capability)
        self.assertTrue(capability.spent)
        self.assertEqual(canonical.read_bytes(), self.c7)
        self.assertFalse(Path(str(canonical)+'.next').exists())
        self.assertEqual(raised.exception.outcome.status, writer.FAILED_BEFORE_REPLACE)
        self.assert_refused_clean(case, canonical, capability, 'already spent')

    def test_pre_replace_drift_and_post_replace_fault_preserve_uncertainty(self):
        case, canonical, capability = self.scene()
        create = writer._create_durable
        def drift(path, payload):
            create(path, payload)
            if path.name.endswith('.epoch8-intent.json'):
                canonical.write_bytes(self.c7 + b'\n')
        with patch.object(writer, '_create_durable', side_effect=drift):
            with self.assertRaises(writer.Epoch8TransitionError) as raised:
                self.run_writer(case, canonical, capability)
        result = raised.exception.outcome
        self.assertEqual(result.status, writer.FAILED_BEFORE_REPLACE)
        self.assertTrue(result.canonical_observation.startswith('external_drift:'))
        self.assertEqual(canonical.read_bytes(), self.c7 + b'\n')
        self.assertTrue(result.next_path.exists())
        case, canonical, capability = self.scene()
        with patch.object(refresh, 'windows_replace_file', side_effect=OSError('replace uncertain')):
            with self.assertRaises(writer.Epoch8TransitionError) as raised:
                self.run_writer(case, canonical, capability)
        self.assertEqual(raised.exception.outcome.status, writer.TRANSITION_INDETERMINATE)
        self.assertTrue(raised.exception.outcome.next_path.exists())
        self.assertEqual(canonical.read_bytes(), self.c7)
        self.assertTrue(capability.spent)
        case, canonical, capability = self.scene()
        def tamper_after_replace(source, target):
            os.replace(source, target)
            target.write_bytes(b'external bytes after replace')
        with patch.object(refresh, 'windows_replace_file', side_effect=tamper_after_replace):
            with self.assertRaises(writer.Epoch8TransitionError) as raised:
                self.run_writer(case, canonical, capability)
        self.assertEqual(raised.exception.outcome.status, writer.TRANSITION_INDETERMINATE)
        self.assertEqual(canonical.read_bytes(), b'external bytes after replace')
        self.assertFalse(raised.exception.outcome.next_path.exists())
        self.assertTrue(capability.spent)

    def test_unknown_next_is_never_removed_or_reused(self):
        case, canonical, capability = self.scene()
        unknown = Path(str(canonical)+'.next')
        unknown.write_bytes(b'unknown ownership')
        with self.assertRaisesRegex(writer.Epoch8TransitionError, 'unknown existing'):
            self.run_writer(case, canonical, capability)
        self.assertTrue(capability.spent)
        self.assertEqual(unknown.read_bytes(), b'unknown ownership')
        self.assertEqual(canonical.read_bytes(), self.c7)


if __name__ == '__main__':
    unittest.main()
