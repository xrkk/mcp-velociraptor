"""K14 regression: real synthetic graph; explicit host native-I/O simulation.

Windows entrypoint: original IssuerTests plus WindowsReadbackTests on a plain
local NTFS PC020_TEST_TEMP_ROOT. These host tests prove control flow, not NTFS
sharing, Win32 ABI execution, directory durability or hardware durability.
"""
import ctypes
from contextlib import ExitStack
import inspect
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests import p05_pc021_readback as rb
from tests import p05_pc021_issuer as issuer
from tests import p05_pc020_activation as graph
from tests.test_p05_pc021_capability import CapabilityFixture, _HostReadbackIO


class NativeReadbackAlgorithmTests(unittest.TestCase):
    def test_platform_and_structure_layout(self):
        self.assertEqual(ctypes.sizeof(rb._AttributeTag), 8)
        self.assertEqual(ctypes.sizeof(rb._FileId), 24)
        self.assertEqual(rb._FileId.identifier.offset, 8)
        if os.name != 'nt':
            with self.assertRaisesRegex(rb.ReadbackError, 'Windows-only'):
                rb._native()

    def test_win32_binding_flags_types_file_id_and_fail_closed(self):
        from types import SimpleNamespace
        calls = []
        class Function:
            def __init__(self, name, action):self.name, self.action = name, action
            def __call__(self, *args):
                calls.append((self.name, args))
                return self.action(*args)
        attributes, fail_id = [0], [False]
        def info(handle, code, target, size):
            if code == 9:
                self.assertEqual(size, 8)
                ctypes.cast(target, ctypes.POINTER(rb._AttributeTag)).contents.attributes = attributes[0]
            elif code == 18:
                self.assertEqual(size, 24)
                if fail_id[0]:return 0
                value = ctypes.cast(target, ctypes.POINTER(rb._FileId)).contents
                value.volume = 77;value.identifier[0] = 42
            else:self.fail('unexpected file information class')
            return 1
        def read(handle, buffer, size, count, overlapped):
            ctypes.memmove(buffer, b'bytes', 5)
            ctypes.cast(count, ctypes.POINTER(ctypes.c_uint32)).contents.value = 5
            return 1
        dll = SimpleNamespace(
            CreateFileW=Function('open', lambda *args: 123),
            GetFileInformationByHandleEx=Function('info', info),
            GetFileType=Function('type', lambda handle: 1),
            ReadFile=Function('read', read), CloseHandle=Function('close', lambda handle: 1))
        path = Path('/fake/R')
        with patch.object(rb.os, 'name', 'nt'), \
             patch.object(rb.ctypes, 'WinDLL', return_value=dll, create=True), \
             patch.object(rb.ctypes, 'get_last_error', return_value=87, create=True):
            api = rb._native()
            self.assertEqual(api.open(path, False), 123)
            self.assertEqual(calls[-1][1], (str(path), 0x80000000, 1, None, 3, 0x02200000, None))
            self.assertEqual(api.identity(123, False), (77, bytes([42]) + bytes(15)))
            self.assertEqual(api.read(123), b'bytes');api.close(123)
            for value in (0x400, 0x10):
                attributes[0] = value
                with self.assertRaisesRegex(rb.ReadbackError, 'reparse|type'):api.identity(123, False)
            attributes[0] = 0;fail_id[0] = True
            with self.assertRaisesRegex(rb.ReadbackError, r'\(18\) failed: 87'):api.identity(123, False)
        self.assertEqual(dll.CreateFileW.restype, ctypes.c_void_p)
        self.assertEqual(dll.ReadFile.argtypes[2], ctypes.c_uint32)

    @unittest.skipUnless(os.name == 'posix', 'explicit POSIX test simulation')
    def test_actual_handles_plain_symlink_special_ancestry_and_replacement(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp).resolve(); path = parent/'root'; path.write_bytes(b'actual bytes')
            with patch.object(rb, '_native', side_effect=_HostReadbackIO):
                self.assertEqual(rb._read_no_follow(path), b'actual bytes')
                link=parent/'link'; link.symlink_to(path)
                with self.assertRaises(OSError): rb._read_no_follow(link)
                directory=parent/'dir'; directory.mkdir()
                with self.assertRaisesRegex(rb.ReadbackError, 'type'): rb._read_no_follow(directory)
                if hasattr(os, 'mkfifo'):
                    fifo=parent/'fifo'; os.mkfifo(fifo)
                    with self.assertRaisesRegex(rb.ReadbackError, 'type'): rb._read_no_follow(fifo)
                alias=parent/'alias'; alias.symlink_to(parent, target_is_directory=True)
                with self.assertRaises(OSError): rb._read_no_follow(alias/'root')
            class Replaced(_HostReadbackIO):
                def read(self, handle):
                    data=super().read(handle)
                    if data:
                        target=parent/'replacement'; target.write_bytes(data); os.replace(target,path)
                    return data
            with patch.object(rb,'_native',side_effect=Replaced):
                with self.assertRaisesRegex(rb.ReadbackError,'path identity changed'):
                    rb._read_no_follow(path)
            self.assertEqual(path.read_bytes(), b'actual bytes')

    def test_reparse_volume_identity_failures_and_exactly_once_close(self):
        path=Path.cwd()/'fake'/'A'/'R'
        for fault in ('reparse', 'special', 'volume', 'read', 'open', 'identity', 'close', 'read+close'):
            with self.subTest(fault=fault):
                class API:
                    def __init__(self):self.opened=[];self.closed=[];self.paths={}
                    def open(self,p,d):
                        if p==path and fault=='open':raise rb.ReadbackError('open primary')
                        h=len(self.opened)+1;self.opened.append(h);self.paths[h]=(p,d);return h
                    def identity(self,h,d):
                        p,_=self.paths[h]
                        if not d and fault in ('reparse','special','identity'):
                            raise rb.ReadbackError(fault+' primary')
                        return (2 if not d and fault=='volume' else 1, str(p))
                    def read(self,h):
                        if fault in ('read','read+close'):raise rb.ReadbackError('read primary')
                        return b''
                    def close(self,h):
                        self.closed.append(h)
                        if 'close' in fault:raise rb.ReadbackError('close secondary')
                api=API()
                with patch.object(rb,'_native',return_value=api):
                    with self.assertRaises(rb.ReadbackError) as raised:rb._read_no_follow(path)
                self.assertEqual(sorted(api.opened), sorted(api.closed))
                self.assertEqual(len(api.closed),len(set(api.closed)))
                if fault=='read+close':
                    self.assertIn('read primary',str(raised.exception))
                    self.assertEqual(len(raised.exception.aggregated),len(api.opened))


@unittest.skipUnless(os.name == 'posix', 'explicit host native simulation')
class RootGateTests(CapabilityFixture):
    def bindings(self):
        return dict(policy=self.policy, root_policy=self.root_policy, epoch7_canonical=self.c7)

    def test_host_production_preflight_creates_no_outputs(self):
        case, _ = self.unissued()
        before = list(issuer._minted)
        with patch.object(rb, '_native', side_effect=rb._WindowsIO), \
             patch.object(issuer, '_create_durable_file_events', wraps=issuer._create_durable_file_events) as create:
            with self.assertRaisesRegex(rb.ReadbackError, 'Windows-only'):
                self.issue(case)
        self.assertEqual(create.call_count, 0)
        self.assertFalse((case/'activation-evidence.json').exists())
        self.assertFalse((case/'issuance-receipt.json').exists())
        self.assertEqual(list(issuer._minted), before)

    def test_shared_predicate_runs_before_event6_with_s_absent(self):
        case,_=self.unissued(); original=graph._verify_immutable_root; calls=[]
        def verified(path,payload,**bindings):
            self.assertFalse((case/'issuance-receipt.json').exists())
            self.assertEqual(bindings['epoch7_canonical'],self.c7)
            result=original(path,payload,**bindings);self.assertEqual(result['phase_count'],3)
            with self.assertRaises(graph.Activation189Error):
                graph.verify_snapshot189_activation(path,**bindings)
            calls.append('root verified');return result
        with patch.object(graph,'_verify_immutable_root',side_effect=verified), \
             patch.object(issuer,'_utc_now',wraps=issuer._utc_now) as clock:
            outcome=self.issue(case)
        self.assertEqual(calls,['root verified']);self.assertEqual(clock.call_count,6)
        self.assertEqual([e['event'] for e in outcome.events],list(graph.EVENT_ORDER))
        self.assertEqual(outcome.events[1]['at'],json.loads(outcome.root_path.read_bytes())['issued_at'])
        self.assertFalse(outcome.capability.spent)
        self.assertEqual(set(inspect.signature(graph.verify_snapshot189_activation).parameters),
                         {'activation_path', 'policy', 'root_policy', 'epoch7_canonical'})

    def test_recursive_drift_after_durable_r_never_records_event6_or_creates_s(self):
        for member in ('source', 'initial', 'cycle1', 'cycle2', 'C7-preparation-binding'):
            with self.subTest(member=member):
                case, _ = self.unissued()
                create = issuer._create_durable_file_events; events = []
                def drift(path, payload, record):
                    create(path, payload, record);events.append(record)
                    doc = json.loads(payload)
                    if member == 'source':ref = doc['source_inputs'][0]['content']
                    elif member == 'initial':ref = doc['initial']['report']
                    elif member == 'cycle1':ref = doc['candidate_cycles'][0]['report']
                    elif member == 'cycle2':ref = doc['candidate_cycles'][1]['report']
                    else:ref = doc['preparation_evidence']
                    leaf = case/ref['path'];leaf.write_bytes(leaf.read_bytes()+b'\n')
                before = list(issuer._minted)
                with patch.object(issuer, '_create_durable_file_events', side_effect=drift):
                    with self.assertRaisesRegex(Exception, 'byte identity differs'):
                        self.issue(case)
                self.assertEqual(len(events[0]), 5)
                self.assertFalse((case/'issuance-receipt.json').exists())
                self.assertTrue((case/'activation-evidence.json').exists())
                self.assertEqual(list(issuer._minted), before)

    def test_root_failure_boundaries_preserve_without_receipt_or_mint(self):
        for fault in ('refresh','bytes','nofollow','root-validation','unexpected-S'):
            with self.subTest(fault=fault):
                case,_=self.unissued(); create=issuer._create_durable_file_events;events=[]
                def created(path,payload,record):
                    events.append(record);create(path,payload,record)
                    if fault=='bytes':path.write_bytes(payload+b'\n')
                    if fault=='unexpected-S':(case/'issuance-receipt.json').write_bytes(b'foreign S')
                before=list(issuer._minted)
                with patch.object(issuer,'_create_durable_file_events',side_effect=created):
                    with patch.object(issuer.refresh,'windows_refresh_directory',side_effect=OSError('refresh failed')) if fault=='refresh' else patch.object(issuer,'json_deep_copy',wraps=issuer.json_deep_copy):
                        with patch.object(rb,'_read_no_follow',side_effect=rb.ReadbackError('nofollow refused')) if fault=='nofollow' else patch.object(graph,'_verify_immutable_root',side_effect=graph.Activation189Error('root failed')) if fault=='root-validation' else patch.object(rb,'_native',side_effect=_HostReadbackIO):
                            with self.assertRaisesRegex(Exception, {'refresh':'refresh failed', 'bytes':'root readback differs', 'nofollow':'nofollow refused', 'root-validation':'root failed', 'unexpected-S':'receipt appeared'}[fault]):self.issue(case)
                self.assertEqual(list(issuer._minted),before);self.assertTrue((case/'activation-evidence.json').exists())
                self.assertEqual(len(events[0]),4 if fault=='refresh' else 5)
                if fault=='unexpected-S':self.assertEqual((case/'issuance-receipt.json').read_bytes(),b'foreign S')
                else:self.assertFalse((case/'issuance-receipt.json').exists())

    def test_root_file_write_flush_fsync_close_events_stop_at_actual_boundary(self):
        for fault in ('write', 'flush', 'fsync', 'close'):
            with self.subTest(fault=fault):
                case, _ = self.unissued(); root = case/'activation-evidence.json'
                actual_open = Path.open; actual_create = issuer._create_durable_file_events
                events = []; before = list(issuer._minted)
                class Stream:
                    def __init__(self, stream):self.stream = stream
                    def __enter__(self):self.stream.__enter__();return self
                    def __exit__(self, *args):
                        result = self.stream.__exit__(*args)
                        if fault == 'close':raise OSError('root close failed')
                        return result
                    def write(self, data):
                        if fault == 'write':
                            self.stream.write(data[:17]);return 0
                        return self.stream.write(data)
                    def flush(self):
                        self.stream.flush()
                        if fault == 'flush':raise OSError('root flush failed')
                    def fileno(self):return self.stream.fileno()
                def opened(path, mode='r', *args, **kwargs):
                    stream = actual_open(path, mode, *args, **kwargs)
                    return Stream(stream) if path == root and mode == 'xb' else stream
                def created(path, payload, record):
                    events.append(record);actual_create(path, payload, record)
                with ExitStack() as seams:
                    seams.enter_context(patch.object(Path, 'open', opened))
                    seams.enter_context(patch.object(issuer, '_create_durable_file_events', side_effect=created))
                    if fault == 'fsync':
                        seams.enter_context(patch.object(os, 'fsync', side_effect=OSError('root fsync failed')))
                    with self.assertRaisesRegex(Exception, 'short write|root '+fault+' failed'):
                        self.issue(case)
                self.assertEqual(len(events[0]), 2 if fault == 'write' else 3)
                self.assertTrue(root.exists());self.assertFalse((case/'issuance-receipt.json').exists())
                self.assertEqual(list(issuer._minted), before)

    def test_receipt_failure_boundaries_never_mint_or_retry(self):
        for fault in ('write','fsync','refresh','nofollow','bytes','complete'):
            with self.subTest(fault=fault):
                case,_=self.unissued();create=issuer._create_durable_file;read=rb._read_no_follow
                def receipt_create(path,payload):
                    if fault=='write':
                        with path.open('xb') as stream:stream.write(payload[:17])
                        raise OSError('receipt write failed')
                    create(path,payload)
                def read_back(path):
                    if path.name=='issuance-receipt.json':
                        if fault=='nofollow':raise rb.ReadbackError('receipt nofollow failed')
                        if fault=='bytes':return read(path)+b'\n'
                    return read(path)
                fsync=os.fsync;counter=[0]
                def sync(fd):
                    counter[0]+=1
                    if counter[0]==2:raise OSError('receipt fsync failed')
                    return fsync(fd)
                refresh=issuer.refresh.windows_refresh_directory;count=[0]
                def refreshed(path):
                    count[0]+=1
                    if count[0]==2:raise OSError('receipt refresh failed')
                    return refresh(path)
                before=list(issuer._minted)
                with ExitStack() as seams:
                    seams.enter_context(patch.object(issuer,'_create_durable_file',side_effect=receipt_create))
                    seams.enter_context(patch.object(rb,'_read_no_follow',side_effect=read_back))
                    if fault=='fsync':seams.enter_context(patch.object(os,'fsync',side_effect=sync))
                    if fault=='refresh':seams.enter_context(patch.object(issuer.refresh,'windows_refresh_directory',side_effect=refreshed))
                    if fault=='complete':seams.enter_context(patch.object(graph,'verify_snapshot189_activation',side_effect=graph.Activation189Error('complete failed')))
                    with self.assertRaisesRegex(Exception, {'write':'receipt write failed', 'fsync':'receipt fsync failed', 'refresh':'receipt refresh failed', 'nofollow':'receipt nofollow failed', 'bytes':'receipt readback differs', 'complete':'complete failed'}[fault]):self.issue(case)
                self.assertTrue((case/'activation-evidence.json').exists());self.assertTrue((case/'issuance-receipt.json').exists())
                self.assertEqual(list(issuer._minted),before)
                preserved={p.name:p.read_bytes() for p in (case/'activation-evidence.json',case/'issuance-receipt.json')}
                with self.assertRaisesRegex(issuer.IssuerError,'already exists'):self.issue(case)
                self.assertEqual(preserved,{p.name:p.read_bytes() for p in (case/'activation-evidence.json',case/'issuance-receipt.json')})

    def test_complete_rejects_bad_receipt_extra_keys_and_incomplete_phases(self):
        case,_=self.unissued();self.issue(case);root=case/'activation-evidence.json'; receipt=case/'issuance-receipt.json'
        root_bytes,receipt_bytes=root.read_bytes(),receipt.read_bytes()
        for mutation in ('bad-S','extra-S','extra-R','missing-initial','one-cycle','third-cycle','wrong-C7'):
            with self.subTest(mutation=mutation):
                root.write_bytes(root_bytes);receipt.write_bytes(receipt_bytes);bindings=self.bindings()
                doc=json.loads(root_bytes);s=json.loads(receipt_bytes)
                if mutation=='bad-S':s['events']=[];receipt.write_bytes(json.dumps(s).encode())
                if mutation=='extra-S':s['extra']=True;receipt.write_bytes(json.dumps(s).encode())
                if mutation=='extra-R':doc['extra']=True
                if mutation=='missing-initial':doc.pop('initial')
                if mutation=='one-cycle':doc['candidate_cycles'].pop()
                if mutation=='third-cycle':doc['candidate_cycles'].append(doc['candidate_cycles'][0])
                if mutation=='wrong-C7':bindings['epoch7_canonical']=b'{}'
                if mutation not in ('bad-S','extra-S','wrong-C7'):root.write_bytes(json.dumps(doc).encode())
                with self.assertRaises(graph.Activation189Error):graph.verify_snapshot189_activation(root,**bindings)


@unittest.skipUnless(os.name=='nt','native Windows/NTFS readback not executed on host')
class WindowsReadbackTests(unittest.TestCase):
    def test_native_plain_file_and_directory(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('PC020_TEST_TEMP_ROOT')) as tmp:
            path=Path(tmp).resolve()/'readback.json';path.write_bytes(b'{"native":true}')
            self.assertEqual(rb._read_no_follow(path),path.read_bytes())
            with self.assertRaises(rb.ReadbackError):rb._read_no_follow(path.parent)


if __name__=='__main__':unittest.main(verbosity=2)
