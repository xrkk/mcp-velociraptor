# Copyright 2026 Google LLC
"""LNX-VR Linux domain unit tests (pure logic, no live server)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from velociraptor_linux_domain import (
    LinuxDomainError,
    LinuxPlatformRouter,
    ScopeState,
    build_triage_plan,
    compare_triage_runs,
    default_artifact_names,
    fingerprint_artifacts,
)

WINDOWS_CLIENT = {'client_id': 'C.win123', 'os': 'windows',
                  'hostname': 'win-host'}
LINUX_CLIENT = {'client_id': 'C.lnx1', 'os': 'linux', 'hostname': 'remnux'}


class RouterTests(unittest.TestCase):
    def test_routes_only_linux(self):
        router = LinuxPlatformRouter(lambda: [WINDOWS_CLIENT, LINUX_CLIENT])
        self.assertEqual(router.list_linux_clients(), [LINUX_CLIENT])
        self.assertEqual(router.resolve_linux_target(), LINUX_CLIENT)
        self.assertEqual(router.resolve_linux_target('C.lnx1'), LINUX_CLIENT)

    def test_windows_target_refused_with_no_mutation_proof(self):
        router = LinuxPlatformRouter(lambda: [WINDOWS_CLIENT, LINUX_CLIENT])
        with self.assertRaises(LinuxDomainError) as caught:
            router.resolve_linux_target('C.win123')
        error = caught.exception
        self.assertEqual(error.code, 'WRONG_PLATFORM')
        # Windows no-mis-operation proof travels with the refusal.
        self.assertEqual(error.details['velociraptor_mutations_issued'], 0)
        self.assertEqual(error.details['os'], 'windows')

    def test_unknown_and_ambiguous(self):
        router = LinuxPlatformRouter(lambda: [WINDOWS_CLIENT, LINUX_CLIENT])
        with self.assertRaises(LinuxDomainError) as caught:
            router.resolve_linux_target('C.nope')
        self.assertEqual(caught.exception.code, 'CLIENT_NOT_FOUND')
        two_linux = LinuxPlatformRouter(
            lambda: [LINUX_CLIENT, dict(LINUX_CLIENT, client_id='C.lnx2')])
        with self.assertRaises(LinuxDomainError) as caught:
            two_linux.resolve_linux_target()
        self.assertEqual(caught.exception.code, 'LINUX_CLIENT_NOT_UNIQUE')


class ScopeTests(unittest.TestCase):
    def test_default_scope_fingerprint_stable(self):
        a = ScopeState('s1')
        b = ScopeState('s2')
        self.assertEqual(a.effective_scope()['fingerprint'],
                         b.effective_scope()['fingerprint'])
        self.assertEqual(a.effective_scope()['mode'], 'default')

    def test_extension_requires_reason_and_bounds(self):
        scope = ScopeState('s1')
        with self.assertRaises(LinuxDomainError):
            scope.extend_temporarily(['Custom.Artifact'], reason='  ', expires_in_seconds=60)
        with self.assertRaises(LinuxDomainError):
            scope.extend_temporarily(['Custom.Artifact'], reason='r', expires_in_seconds=0)
        with self.assertRaises(LinuxDomainError):
            scope.extend_temporarily(default_artifact_names(), reason='r', expires_in_seconds=60)

    def test_extend_withdraw_stop_transitions(self):
        scope = ScopeState('s1')
        scope._record = scope._record  # keep real recorder
        before = set(default_artifact_names())
        extended = scope.extend_temporarily(['Custom.Extra'], reason='triage gap',
                                            expires_in_seconds=300)
        self.assertEqual(extended['mode'], 'temporary_extension')
        self.assertIn('Custom.Extra', extended['allowed_artifacts'])
        self.assertTrue(extended['active_extensions'])
        withdrawn = scope.withdraw()
        self.assertEqual(withdrawn['mode'], 'default')
        self.assertNotIn('Custom.Extra', withdrawn['allowed_artifacts'])
        self.assertFalse(withdrawn['active_extensions'])
        stopped = scope.stop()
        self.assertTrue(stopped['stopped'])
        actions = [t['action'] for t in scope.transitions]
        self.assertEqual(actions, ['extend', 'withdraw', 'stop'])
        # after stop everything refuses
        with self.assertRaises(LinuxDomainError):
            scope.extend_temporarily(['X.Y'], reason='r', expires_in_seconds=60)
        self.assertEqual(before, set(default_artifact_names()))


class TriageTests(unittest.TestCase):
    def test_plan_respects_scope_and_stability(self):
        scope = ScopeState('s1')
        plan = build_triage_plan(scope, LINUX_CLIENT)
        self.assertEqual(plan.artifacts, sorted(default_artifact_names()))
        self.assertEqual(plan.fingerprint,
                         fingerprint_artifacts(default_artifact_names()))
        scope.extend_temporarily(['Custom.Extra'], reason='r', expires_in_seconds=60)
        plan2 = build_triage_plan(scope, LINUX_CLIENT)
        self.assertIn('Custom.Extra', plan2.artifacts)
        self.assertNotEqual(plan.fingerprint, plan2.fingerprint)
        scope.stop()
        with self.assertRaises(LinuxDomainError):
            build_triage_plan(scope, LINUX_CLIENT)

    def test_two_run_comparison(self):
        run_a = {'fingerprint': 'f1', 'client_id': 'C.lnx1',
                 'category_results': {'process': 1, 'net': 1}}
        run_b = {'fingerprint': 'f1', 'client_id': 'C.lnx1',
                 'category_results': {'process': 1, 'net': 1, 'extra': 1}}
        result = compare_triage_runs(run_a, run_b)
        self.assertTrue(result['repeatable'])
        run_c = dict(run_b, fingerprint='f2')
        self.assertFalse(compare_triage_runs(run_a, run_c)['repeatable'])
        run_d = dict(run_b, category_results={'process': 1})
        self.assertFalse(compare_triage_runs(run_a, run_d)['repeatable'])


if __name__ == '__main__':
    unittest.main(verbosity=2)


class TargetScopeTests(unittest.TestCase):
    """AUD-LNXVR-001: high-granularity default scope is target-anchored."""

    def test_bind_targets_and_effective_scope(self):
        s = ScopeState(session_id='t')
        with self.assertRaises(LinuxDomainError):
            s.bind_targets(['  '])
        sc = s.bind_targets(['/home/x/.config', 'pid:4242'])
        self.assertEqual(sc['targets'], ['/home/x/.config', 'pid:4242'])
        self.assertIn('related targets', sc['target_semantics'])

    def test_target_vql_hints_bind_collector_params(self):
        hints = ScopeState.target_vql_hints(['/tmp/a', '/var/b', 'pid:1'])
        self.assertEqual(hints['path_globs'], ['/tmp/a', '/var/b'])
        self.assertEqual(hints['subject_filters'], ['pid:1'])
        self.assertEqual(hints['collector_bindings']['Linux.Search.FileFinder'],
                         {'Globs': ['/tmp/a', '/var/b']})

    def test_withdraw_deactivates_extensions(self):
        s = ScopeState(session_id='t')
        s.bind_targets(['/tmp/rel'])
        s.extend_temporarily(['Linux.Events.ProcessTree'], reason='r', expires_in_seconds=60)
        sc = s.withdraw()
        self.assertEqual(sc['mode'], 'default')
        self.assertTrue(all(not e['active'] for e in s.extensions))

    def test_stopped_scope_rejects_bind(self):
        s = ScopeState(session_id='t')
        s.stop()
        with self.assertRaises(LinuxDomainError):
            s.bind_targets(['/x'])

    def test_default_artifacts_cover_required_categories(self):
        names = default_artifact_names()
        for required in ('Linux.Sys.Pslist',
                         'Linux.Systemd.Status', 'Linux.Sys.Crontab',
                         'Linux.Network.Netstat'):
            self.assertIn(required, names)
