"""PC022 raw-API simulations: exact three-handle control flow, no native claim."""
import ctypes
import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from contextlib import ExitStack
from unittest.mock import patch

from tests import pc022_windows_refresh as r


ORDER = [('open',101),('tag',101),('id',101),('open',102),('id',102),
         ('close',102),('flush',101),('close',101),('open',103),('id',103),('close',103)]


class APIs:
    def __init__(self, faults=None, attributes=16, drift=None):
        self.faults=faults or {};self.attributes=attributes;self.drift=drift
        self.events=[];self.opens=[];self.error=0

    def outcome(self, event):
        mode=self.faults.get(event)
        if mode:
            self.error=777
            if mode=='raise':
                error=OSError('injected API exception');error.winerror=888;raise error
            return False
        return True

    def create(self, *args):
        handle=101+len(self.opens);self.opens.append(args);event=('open',handle);self.events.append(event)
        return handle if self.outcome(event) else r.INVALID_HANDLE_VALUE

    def info(self, handle, code, pointer, size):
        event=('tag' if code==9 else 'id',handle);self.events.append(event)
        if not self.outcome(event):return 0
        if code==9:
            assert size==8
            ctypes.cast(pointer,ctypes.POINTER(r.FILE_ATTRIBUTE_TAG_INFO)).contents.file_attributes=self.attributes
        else:
            assert code==18 and size==24
            value=ctypes.cast(pointer,ctypes.POINTER(r.FILE_ID_INFO)).contents
            value.volume_serial_number=0xABCDEF0123456789
            value.file_id[15]=255;value.file_id[0]=43 if handle==self.drift else 42
        return 1

    def close(self, handle):
        event=('close',handle);self.events.append(event);return self.outcome(event)

    def flush(self, handle):
        event=('flush',handle);self.events.append(event);return self.outcome(event)

    def install(self, stack):
        stack.enter_context(patch.object(r,'kernel32',object()))
        for name, function in [('CreateFileW',self.create),('GetFileInformationByHandleEx',self.info),
                               ('CloseHandle',self.close),('FlushFileBuffers',self.flush)]:
            stack.enter_context(patch.object(r,name,side_effect=function,create=True))
        stack.enter_context(patch.object(ctypes,'set_last_error',side_effect=lambda value:setattr(self,'error',value),create=True))
        stack.enter_context(patch.object(ctypes,'get_last_error',side_effect=lambda:self.error,create=True))


class RefreshLifecycleTests(unittest.TestCase):
    def invoke(self, api, function=r.windows_refresh_directory):
        with ExitStack() as stack:
            api.install(stack)
            return function(Path.cwd())

    def test_success_exact_order_flags_and_full_128_bit_id(self):
        api=APIs();result=self.invoke(api)
        self.assertEqual(api.events,ORDER)
        for args in api.opens:
            self.assertEqual(args[1:],(r.GENERIC_WRITE,7,None,3,0x02200000,None))
        self.assertEqual(result['volume_serial_number'],0xABCDEF0123456789)
        self.assertEqual(int(result['file_id'],16),(255<<120)+42)
        self.assertEqual(ctypes.sizeof(r.FILE_ID_INFO),24)
        self.assertEqual(r.FILE_ID_INFO.file_id.offset,8)
        self.assertEqual(ctypes.sizeof(r.FILE_ATTRIBUTE_TAG_INFO),8)

    def test_numeric_handle_reuse_is_a_new_owned_lifetime(self):
        class Reused(APIs):
            def create(self, *args):
                handle = super().create(*args)
                if handle == 103:
                    self.events[-1] = ('open', 101)
                    return 101
                return handle
        api = Reused();self.invoke(api)
        expected = [(op, 101 if h == 103 else h) for op, h in ORDER]
        self.assertEqual(api.events, expected)
        self.assertEqual(api.events.count(('close', 101)), 2)

    def test_every_api_zero_and_exception_stops_business_and_closes_once(self):
        stages=['open','attribute_tag','file_id','open','file_id','close_pre',
                'flush_main','close_main','open','file_id','close_post']
        for index,event in enumerate(ORDER):
            for mode in ('zero','raise'):
                with self.subTest(event=event,mode=mode):
                    api=APIs({event:mode})
                    with self.assertRaises(r.Pc022WindowsRefreshError) as caught:self.invoke(api)
                    self.assertEqual(caught.exception.stage,stages[index])
                    self.assertEqual(caught.exception.winerror,777 if mode=='zero' else 888)
                    prefix=ORDER[:index+1]
                    acquired=[h for op,h in prefix if op=='open' and not (op,h)==event]
                    if event[0]!='open':acquired=[h for op,h in prefix if op=='open']
                    attempted=[h for op,h in prefix if op=='close']
                    cleanup=[('close',h) for h in reversed(acquired) if h not in attempted]
                    self.assertEqual(api.events,prefix+cleanup)
                    self.assertEqual(len([h for op,h in api.events if op=='close']),len(set(h for op,h in api.events if op=='close')))
                    self.assertEqual(caught.exception.aggregated,[])

    def test_type_reparse_and_pre_post_drift_reject_at_exact_boundary(self):
        for name,attributes,drift,index,stage in [('type',0,None,1,'type'),('reparse',0x410,None,1,'reparse'),
                                                ('pre',16,102,4,'compare_pre'),('post',16,103,9,'compare_post')]:
            with self.subTest(name=name):
                api=APIs(attributes=attributes,drift=drift)
                with self.assertRaises(r.Pc022WindowsRefreshError) as caught:self.invoke(api)
                self.assertEqual(caught.exception.stage,stage)
                prefix=ORDER[:index+1];acquired=[h for op,h in prefix if op=='open'];closed=[h for op,h in prefix if op=='close']
                self.assertEqual(api.events,prefix+[('close',h) for h in reversed(acquired) if h not in closed])

    def test_primary_api_error_and_all_later_close_failures_are_retained(self):
        api=APIs({('id',102):'zero',('close',102):'raise',('close',101):'zero'})
        with self.assertRaises(r.Pc022WindowsRefreshError) as caught:self.invoke(api)
        error=caught.exception
        self.assertEqual((error.stage,error.winerror),('file_id',777))
        self.assertEqual([(e['stage'],e['winerror']) for e in error.aggregated],[('close_pre',888),('close_main',777)])
        self.assertEqual(api.events,ORDER[:5]+[('close',102),('close',101)])
        api=APIs({('flush',101):'raise',('close',101):'zero'})
        with self.assertRaises(r.Pc022WindowsRefreshError) as caught:self.invoke(api)
        self.assertEqual((caught.exception.stage,caught.exception.winerror),('flush_main',888))
        self.assertIsInstance(caught.exception.__cause__,OSError)
        self.assertEqual([e['stage'] for e in caught.exception.aggregated],['close_main'])
        self.assertEqual(api.events,ORDER[:8])

    def test_identity_helpers_close_failure_never_masks_type_or_reparse(self):
        for directory,function,attributes in [(True,r.handle_directory_identity,0),(False,r.handle_file_identity,16),
                                              (True,r.handle_directory_identity,0x410),(False,r.handle_file_identity,0x400)]:
            for mode in ('zero','raise'):
                api=APIs({('close',101):mode},attributes=attributes)
                with self.subTest(directory=directory,attributes=attributes,mode=mode):
                    with self.assertRaises(r.Pc022WindowsRefreshError) as caught:self.invoke(api,function)
                    self.assertEqual(caught.exception.stage,'reparse' if attributes&0x400 else 'type')
                    self.assertEqual(len(caught.exception.aggregated),1)
                    self.assertEqual(caught.exception.aggregated[0]['stage'],'identity_probe_close')
                    self.assertEqual(api.events,[('open',101),('tag',101),('close',101)])
        for function,attributes in [(r.handle_file_identity,0),(r.handle_directory_identity,16)]:
            api=APIs(attributes=attributes);identity=self.invoke(api,function)
            self.assertEqual(identity,(0xABCDEF0123456789,(255<<120)+42))
            self.assertEqual(api.events,[('open',101),('tag',101),('id',101),('close',101)])

    def test_non_pc022_primary_exception_remains_primary_with_close_note(self):
        api=APIs({('close',101):'zero'})
        with ExitStack() as stack:
            api.install(stack);stack.enter_context(patch.object(r,'_query_attribute_tag',side_effect=ValueError('primary')))
            with self.assertRaisesRegex(ValueError,'primary') as caught:r.windows_refresh_directory(Path.cwd())
        self.assertIn('close_main',caught.exception.__notes__[0])
        self.assertEqual(api.events,[('open',101),('close',101)])

    def test_platform_rejection_for_all_public_primitives(self):
        if os.name=='nt':self.skipTest('non-Windows refusal test')
        for function,args in [(r.windows_refresh_directory,(Path.cwd(),)),(r.handle_directory_identity,(Path.cwd(),)),
                              (r.handle_file_identity,(Path.cwd(),)),(r.windows_replace_file,(Path('a'),Path('b'))),
                              (r.windows_publish_hard_link,(Path('a'),Path('b'))),(r.create_hierarchy_and_refresh,(Path.cwd(),('A',)))]:
            with self.subTest(function=function.__name__),self.assertRaisesRegex(r.Pc022WindowsRefreshError,'platform'):function(*args)

    def test_raw_win32_bindings_use_fixed_width_abi(self):
        class Function:
            def __call__(self,*args):return 1
        dll=SimpleNamespace(**{name:Function() for name in ('CreateFileW','FlushFileBuffers','CloseHandle',
             'GetFileInformationByHandleEx','MoveFileExW','CreateDirectoryW','CreateHardLinkW')})
        spec=importlib.util.spec_from_file_location('isolated_refresh_bindings',r.__file__)
        module=importlib.util.module_from_spec(spec)
        with patch.object(os,'name','nt'),patch.object(ctypes,'WinDLL',return_value=dll,create=True):spec.loader.exec_module(module)
        self.assertEqual(module.GetFileInformationByHandleEx.argtypes,(ctypes.c_void_p,ctypes.c_int32,ctypes.c_void_p,ctypes.c_uint32))
        self.assertEqual(module.GetFileInformationByHandleEx.restype,ctypes.c_int32)
        self.assertEqual(module.CreateFileW.restype,ctypes.c_void_p)
        self.assertFalse(hasattr(module,'GetFileInformationByHandle'))

    def test_cross_volume_replace_and_hardlink_refuse_before_native_publish(self):
        for function,api_name in [(r.windows_replace_file,'MoveFileExW'),(r.windows_publish_hard_link,'CreateHardLinkW')]:
            with ExitStack() as stack:
                stack.enter_context(patch.object(r,'_require_nt',return_value=None))
                stack.enter_context(patch.object(r,'handle_directory_identity',side_effect=[(1,100),(2,100)] if function is r.windows_replace_file else [(2,100)]))
                stack.enter_context(patch.object(r,'handle_file_identity',return_value=(1,1)))
                native=stack.enter_context(patch.object(r,api_name,return_value=1,create=True))
                with self.assertRaisesRegex(r.Pc022WindowsRefreshError,'cross_volume'):function(Path.cwd()/'s',Path.cwd()/'t')
                self.assertEqual(native.call_count,0)

    def test_hierarchy_parent_drift_creates_nothing(self):
        with patch.object(r,'_require_nt',return_value=None), \
             patch.object(r,'handle_directory_identity',side_effect=[(1,11),(1,22)]), \
             patch.object(r,'CreateDirectoryW',create=True) as create:
            with self.assertRaisesRegex(r.Pc022WindowsRefreshError,'compare_hierarchy_parent'):
                r.create_hierarchy_and_refresh(Path.cwd(),('A','B'))
        self.assertEqual(create.call_count,0)


if __name__=='__main__':unittest.main(verbosity=2)
