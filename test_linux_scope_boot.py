"""Local current-boot scope qualification and clock-unit negatives."""
import unittest
from unittest.mock import patch, Mock
from velociraptor_linux_backend import LinuxTriageBackend
from velociraptor_linux_scope import CurrentBootScopeProfessional, birth_basis
from velociraptor_linux_domain import LinuxDomainError


class CurrentScopeTests(unittest.TestCase):
    def test_current_boot_binding_preserves_original_deployment(self):
        obj = CurrentBootScopeProfessional.__new__(CurrentBootScopeProfessional)
        old = dict(vm_uuid='vm', boot_id='old', client_id='client')
        obj.deployment = dict(ready=old)
        obj.expected_scope = dict(vm_uuid='vm', boot_id='new', client_id='client')
        with patch.object(LinuxTriageBackend, 'identity') as verify:
            obj.identity()
            verify.assert_called_once()
        self.assertEqual(obj.binding['boot_id'], 'new')
        self.assertEqual(old['boot_id'], 'old')
        for key in ('vm_uuid', 'client_id'):
            obj.expected_scope[key] = 'foreign'
            with self.assertRaises(LinuxDomainError):
                obj.identity()
            obj.expected_scope[key] = old[key]

    def test_scope_factory_restricts_owner_session_and_tools(self):
        from velociraptor_linux_cli import RegisteredLinuxClient
        obj = RegisteredLinuxClient.__new__(RegisteredLinuxClient)
        obj.scope_binding = dict(session_id='s', owner_id='o')
        handler = Mock(return_value={'ok': True})
        obj.handlers = {'linux_scope_query': handler, 'linux_triage_collect': handler}
        for name, request in [('linux_triage_collect', obj.scope_binding),
                              ('linux_scope_query', dict(session_id='s', owner_id='foreign'))]:
            with self.assertRaises(LinuxDomainError):
                obj.call(name, {'request': request})
        handler.assert_not_called()
        obj.call('linux_scope_query', {'request': obj.scope_binding})
        handler.assert_called_once()

    def test_birth_units_require_zero_initial_time_namespace(self):
        with patch('velociraptor_linux_scope.os.sysconf', return_value=100), \
             patch('velociraptor_linux_scope.os.readlink', return_value='time:[1]'), \
             patch('velociraptor_linux_scope.Path.read_text', return_value='monotonic 0 0\nboottime 0 0\n'):
            value = birth_basis([dict(pid=123)])
            self.assertEqual(value['tick_ns'], 10000000)
            self.assertEqual(value['proc_stat_field'], 22)
        for ticks, link, offsets in [(250, 'time:[1]', 'monotonic 0 0\nboottime 0 0\n'),
                                      (100, 'time:[1]', 'monotonic 0 0\nboottime 1 0\n')]:
            with patch('velociraptor_linux_scope.os.sysconf', return_value=ticks), \
                 patch('velociraptor_linux_scope.os.readlink', return_value=link), \
                 patch('velociraptor_linux_scope.Path.read_text', return_value=offsets):
                with self.assertRaises(LinuxDomainError):
                    birth_basis([dict(pid=123)])


if __name__ == '__main__':
    unittest.main()
