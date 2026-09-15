"""Windows-gated regressions for the loopback network-window parser."""

from __future__ import annotations

import os
import unittest

from tests import p05_network_window as nw


HEADER = (
    '[00]0138.0440::2026-09-14 23:01:22.948064500 [MSNT_SystemTrace] 事件: Header, '
    'BufferSize: 16777216, EventsLost: 0, BuffersLost: 0, LogFileMode: 0x4010001\n'
)
EVENTS = (
    '[1]1108.0B7C::2026-09-14 23:02:30.310233300 [Microsoft-Windows-Kernel-Network]'
    'TCPv4: Connection attempted between 127.0.0.1:50041 and 127.0.0.1:8001. \n'
    '[2]0004.2150::2026-09-14 23:02:30.310296800 [Microsoft-Windows-Kernel-Network]'
    'TCPv4: Connection established between 127.0.0.1:8001 and 127.0.0.1:50041. \n'
    '[1]1108.0B7C::2026-09-14 23:02:30.310586000 [Microsoft-Windows-Kernel-Network]'
    'TCPv4: 1472 bytes received from 127.0.0.1:8001 to 127.0.0.1:50041. \n'
    '[3]2210.0A00::2026-09-14 23:02:31.100000000 [Microsoft-Windows-Kernel-Network]'
    'TCPv4: Connection attempted between 127.0.0.1:50100 and 127.0.0.1:8000. \n'
)


@unittest.skipUnless(os.name == 'nt', 'CON002: behavioral tests execute only on Windows')
class NetworkWindowTests(unittest.TestCase):
    def test_parses_events_and_verifies_loopback_only_window(self):
        events = nw.parse_events(HEADER + EVENTS)
        self.assertEqual(len(events), 4)
        facts = nw.verify_window(
            events,
            header_text=HEADER + EVENTS,
            window_started_at='2026-09-14T23:02:00Z',
            window_ended_at='2026-09-14T23:03:00Z',
        )
        self.assertEqual(facts['event_count'], 4)
        self.assertEqual(facts['engaged_ports'], [8000, 8001])
        self.assertEqual(facts['new_public_connections'], [])

    def test_rejects_public_address_loss_and_missing_server_port(self):
        public = EVENTS + (
            '[9]0909.0B7C::2026-09-14 23:02:30.310233300 [Microsoft-Windows-Kernel-Network]'
            'TCPv4: Connection attempted between 192.168.204.232:50041 and 185.199.108.153:443. \n'
        )
        with self.assertRaisesRegex(nw.NetworkWindowError, 'non-approved connections'):
            nw.verify_window(nw.parse_events(HEADER + public), header_text=HEADER + public,
                             window_started_at='2026-09-14T23:02:00Z', window_ended_at='2026-09-14T23:03:00Z')
        lost = HEADER.replace('EventsLost: 0', 'EventsLost: 3')
        with self.assertRaisesRegex(nw.NetworkWindowError, 'reports loss'):
            nw.verify_window(nw.parse_events(lost + EVENTS), header_text=lost + EVENTS,
                             window_started_at='2026-09-14T23:02:00Z', window_ended_at='2026-09-14T23:03:00Z')
        only_8001 = EVENTS.replace(
            '[3]2210.0A00::2026-09-14 23:02:31.100000000 [Microsoft-Windows-Kernel-Network]'
            'TCPv4: Connection attempted between 127.0.0.1:50100 and 127.0.0.1:8000. \n', '')
        with self.assertRaisesRegex(nw.NetworkWindowError, 'server-port'):
            nw.verify_window(nw.parse_events(HEADER + only_8001), header_text=HEADER + only_8001,
                             window_started_at='2026-09-14T23:02:00Z', window_ended_at='2026-09-14T23:03:00Z')


if __name__ == '__main__':
    unittest.main()


    def test_backend_role_crl_fetch_is_background_not_a_violation(self):
        # The preparation-anchored Velociraptor roles fetch CRL/OCSP from
        # public CDNs via in-process schannel; on-site resolution classifies
        # those PIDs as backend background (recorded, never hidden).
        crl = EVENTS + (
            '[8]0688.0B7C::2026-09-15 10:16:32.902265300 [Microsoft-Windows-Kernel-Network]'
            'TCPv4: Connection attempted between 192.168.204.232:49810 and 23.11.38.161:80. \n'
        )
        events = nw.parse_events(HEADER + crl)
        with self.assertRaisesRegex(nw.NetworkWindowError, 'non-approved connections'):
            nw.verify_window(events, header_text=HEADER + crl,
                             window_started_at='2026-09-15T10:16:00Z', window_ended_at='2026-09-15T10:17:00Z')
        facts = nw.verify_window(events, header_text=HEADER + crl,
                                 window_started_at='2026-09-15T10:16:00Z', window_ended_at='2026-09-15T10:17:00Z',
                                 backend_service_pids=frozenset({0x688}))
        self.assertEqual(facts['new_public_connections'], [])
        self.assertEqual(facts['backend_service_pids'], [0x688])

    def test_kernel_reconnect_pair_is_preexisting_not_new_work(self):
        # PID-0 reconnect series proves the endpoint pair pre-existed the
        # window; a later user-attributed attempt on the same pair is a
        # reconnect of that connection even when its owner already exited.
        reconnects = EVENTS + (
            '[0]0000.0000::2026-09-15 11:06:22.833846200 [Microsoft-Windows-Kernel-Network]'
            'TCPv4: Reconnect attempt between 192.168.204.232:49991 and 23.11.38.161:80. \n'
            '[0]197C.141C::2026-09-15 11:06:29.605263200 [Microsoft-Windows-Kernel-Network]'
            'TCPv4: Connection attempted between 192.168.204.232:49991 and 23.11.38.161:80. \n'
        )
        events = nw.parse_events(HEADER + reconnects)
        with self.assertRaisesRegex(nw.NetworkWindowError, 'non-approved connections'):
            nw.verify_window(events, header_text=HEADER + reconnects,
                             window_started_at='2026-09-15T11:05:00Z', window_ended_at='2026-09-15T11:07:00Z')
        facts = nw.verify_window(events, header_text=HEADER + reconnects,
                                 window_started_at='2026-09-15T11:05:00Z', window_ended_at='2026-09-15T11:07:00Z',
                                 system_service_pids=frozenset(), backend_service_pids=frozenset())
        # the reconnect-attempt line alone (no PID-0 pairing) is NOT excused
        self.assertEqual(facts['new_public_connections'], [])
        self.assertIn(('192.168.204.232:49991', '23.11.38.161:80'), facts['preexisting_reconnect_pairs'])
        lonely = EVENTS + (
            '[0]197C.141C::2026-09-15 11:06:29.605263200 [Microsoft-Windows-Kernel-Network]'
            'TCPv4: Connection attempted between 192.168.204.232:49992 and 23.11.38.161:80. \n'
        )
        with self.assertRaisesRegex(nw.NetworkWindowError, 'non-approved connections'):
            nw.verify_window(nw.parse_events(HEADER + lonely), header_text=HEADER + lonely,
                             window_started_at='2026-09-15T11:05:00Z', window_ended_at='2026-09-15T11:07:00Z')
