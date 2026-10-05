"""Finite producer preservation faults; no SDK or governance PASS replacement."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tests import scenario_runner as runner


class FinalizationErrors(unittest.IsolatedAsyncioTestCase):
    async def test_header_fault_remains_primary_when_diagnostic_publication_also_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            run=Path(temporary)
            (run/'raw-mcp').mkdir();(run/'raw-mcp/capture.json').write_bytes(b'{}\n')
            diagnostic=run/'failure-classification-error.json';diagnostic.write_bytes(b'original diagnostic\n')
            primary=OSError('actual header publication fault')
            report=dict(status='failed',coverage=[],failure=dict(type='FirstSDKError',message='first SDK error'))
            with patch.object(runner,'_save_original_headers',side_effect=primary):
                try:await runner._finalize_current(report,run,run,None,object(),None,seal=False)
                except BaseException as caught:
                    self.assertIs(caught,primary)
                    self.assertTrue(any('preservation' in n for n in caught.__notes__))
                else:self.fail('producer fault was swallowed')
            self.assertEqual(json.loads((run/'report.json').read_bytes())['failure']['type'],'FirstSDKError')
            self.assertEqual(diagnostic.read_bytes(),b'original diagnostic\n')
            self.assertFalse((run/'mcp-observation-binding.json').exists())
