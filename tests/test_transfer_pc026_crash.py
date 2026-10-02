"""Owned real worker exits at proof persistence boundaries, including Windows."""
import json
import os
import secrets
import subprocess
import sys
import time
import unittest

from tests import test_transfer_pc026_prefix as fixture
from velo_transfer import guest_service as gm
from velo_transfer.errors import TransferContentError as Error
from velo_transfer.guest_worker import process_birth, terminate_verified


class PrefixCrashTests(unittest.TestCase):
    setUp = fixture.PrefixTests.setUp
    request = fixture.PrefixTests.request
    push = fixture.PrefixTests.push
    send_chunk = fixture.PrefixTests.send_chunk
    budget = fixture.PrefixTests.budget

    def worker(self, req, mode):
        nonce = secrets.token_hex(16)
        script = r'''
import os,sys,json,time
from pathlib import Path
from velo_transfer.guest_service import GuestTransferService
from velo_transfer.windows_platform import WindowsObservation
uid,boot=json.loads(sys.argv[6])
s=GuestTransferService(sys.argv[1]) if os.name=='nt' else GuestTransferService(sys.argv[1],_observation=WindowsObservation('Windows',uid,boot),_acl_verifier=lambda p,k:True)
original=s._save
mode=sys.argv[5]
def fault(store,env,state):
 if state.get('prefix_verification') and mode=='before':os._exit(17)
 if state.get('prefix_verification') and mode=='active':
  Path(sys.argv[7]).write_text('before-proof-save')
  time.sleep(60)
 result=original(store,env,state)
 if state.get('prefix_verification') and mode=='after':os._exit(18)
 return result
s._save=fault
s._child(sys.argv[2],sys.argv[3],'verify_partial',sys.argv[4],sys.stdin.buffer)
'''
        marker = self.root/'worker-boundary.txt'
        env = os.environ.copy()
        env['PYTHONPATH'] = str(__import__('pathlib').Path(__file__).resolve().parents[1])
        env['VELOCIRAPTOR_TRANSFER_POLICY'] = str(self.policy)
        child = subprocess.Popen([getattr(sys,'_base_executable',sys.executable),'-c',script,
            str(self.policy),'trial',req['request_digest'],nonce,mode,
            json.dumps([self.observation.vm_uuid,self.observation.boot_identity]),str(marker)],
            env=env,stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        birth = process_birth(child.pid)
        def cleanup():
            if child.poll() is None:
                terminate_verified(child.pid,birth,timeout=3)
            child.wait(timeout=5)
        self.addCleanup(cleanup)
        store = self.service._store()
        with store.writer():
            lease = self.service._check_idle(store)
            item = self.service._load('trial',req['request_digest'],store)
            state = item['state']
            owner = {'transfer_id':'trial','job':'verify_partial','nonce':nonce,'pid':child.pid,
                'birth':birth,'deadline_monotonic':state['deadline_monotonic'],'stopped':False}
            state.update(owner=owner,error=None,prefix_verification=None)
            self.service._save(store,item,state)
            store.save(gm._LEASE_ID,lease['binding'],lease['revision'],{'active':owner})
        child.stdin.write((nonce+'\n').encode());child.stdin.flush();child.stdin.close()
        return child,marker,owner

    def test_real_exit_before_atomic_proof_is_not_completed(self):
        req = self.push()
        self.send_chunk(req)
        child,marker,owner = self.worker(req,'before')
        self.assertEqual(child.wait(timeout=60),17)
        status = self.service.transfer_status('trial',req['request_digest'])
        self.assertTrue(status['worker']['stopped'])
        self.assertIsNone(status['prefix_verification'])
        self.assertEqual(status['error'],'worker_result_unknown')

    def test_real_exit_after_atomic_proof_retains_complete_new_nonce(self):
        req = self.push()
        self.send_chunk(req)
        child,marker,owner = self.worker(req,'after')
        self.assertEqual(child.wait(timeout=60),18)
        status = self.service.transfer_status('trial',req['request_digest'])
        self.assertTrue(status['worker']['stopped'])
        self.assertIsNone(status['error'])
        self.assertEqual(status['prefix_verification']['worker_nonce'],owner['nonce'])
        self.assertTrue(status['prefix_verification']['completed'])
        lease=self.service._store().load(gm._LEASE_ID,self.service._lease_binding())
        self.assertIsNone(lease['state']['active'])

    def test_active_writer_blocks_chunk_and_begin_does_not_launch_another(self):
        req = self.push()
        self.send_chunk(req)
        child,marker,owner = self.worker(req,'active')
        until=time.monotonic()+60
        while not marker.exists() and time.monotonic()<until:
            self.assertIsNone(child.poll())
            time.sleep(.02)
        self.assertTrue(marker.exists())
        before=self.service._load('trial',req['request_digest'])['state']['deadline_monotonic']
        with self.assertRaises(Error) as begin_error:
            self.service.transfer_begin(req)
        self.assertEqual(begin_error.exception.code,'writer_busy')
        same=self.service.transfer_status('trial',req['request_digest'])
        self.assertEqual(same['worker']['nonce'],owner['nonce'])
        self.assertFalse(same['worker']['stopped'])
        self.assertIsNone(same['prefix_verification'])
        part=self.work/'tasks/trial/received.part'
        raw=part.read_bytes()
        with self.assertRaises(Error) as caught:
            self.send_chunk(req,4,b'e')
        self.assertEqual(caught.exception.code,'writer_busy')
        self.assertEqual(part.read_bytes(),raw)
        self.assertEqual(self.service._load('trial',req['request_digest'])['state']['deadline_monotonic'],before)
        terminate_verified(child.pid,owner['birth'],timeout=3)
        child.wait(timeout=5)
        aborted=self.service.transfer_abort('trial',req['request_digest'])
        self.assertTrue(aborted['worker']['stopped'])
        self.assertIsNone(aborted['prefix_verification'])
        self.assertEqual(aborted['error'],'transfer_cancelled')


if __name__=='__main__':
    unittest.main()
