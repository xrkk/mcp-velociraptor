"""Historical entry points must reject current roots before reading evidence."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from tests import p06_aggregate_reports as aggregate, scenario_runner as runner

class HistoricalEntryGate(unittest.TestCase):
    def test_current_baseline_entry_rejects_before_reader(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            with patch.object(runner,'P06_REPORT_ROOT',root), patch.object(Path,'read_bytes',side_effect=AssertionError('unexpected evidence read')):
                with self.assertRaisesRegex(aggregate.AggregateError,'historical baseline cannot consume current'):
                    aggregate.verify_baseline_evidence({},root/'scene'/'run')

    def test_current_historical_aggregate_rejects_before_ledger(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            with patch.object(runner,'P06_REPORT_ROOT',root), patch.object(aggregate,'load_ledger',side_effect=AssertionError('unexpected ledger read')):
                with self.assertRaisesRegex(aggregate.AggregateError,'historical aggregate cannot consume current'):
                    aggregate.aggregate_historical(evidence_root=root,ledger_path=root/'ledger',selection_path=root/'selection')
