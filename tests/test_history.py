import json
import sys
import tempfile
import unittest
from pathlib import Path
from xml.etree import ElementTree

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from intelligence_history import process_intelligence


def fixture(entries):
    return {'schemaVersion': 1, 'vulnerabilities': [
        {'id': cve, 'epss': score, 'priority': 'High'} for cve, score in entries.items()
    ]}

class IntelligenceHistoryTests(unittest.TestCase):
    def test_initial_baseline_no_spurious_alerts(self):
        with tempfile.TemporaryDirectory() as d:
            out = process_intelligence(d, fixture({'CVE-2026-0001': .12}), '2026-10-14T00:00:00+00:00')
            self.assertEqual(out['newAlerts'], 0)
            self.assertTrue((Path(d) / 'feed.xml').exists())
            ElementTree.parse(Path(d) / 'feed.xml')

    def test_kev_addition_and_daily_epss_spike_deduped(self):
        with tempfile.TemporaryDirectory() as d:
            process_intelligence(d, fixture({'CVE-2026-0001': .10}), '2026-10-14T00:00:00+00:00')
            process_intelligence(d, fixture({'CVE-2026-0001': .10}), '2026-10-15T00:00:00+00:00')
            data=fixture({'CVE-2026-0001': .36, 'CVE-2026-0002': .50})
            result=process_intelligence(d, data, '2026-10-15T06:00:00+00:00')
            self.assertEqual(result['newAlerts'], 2)
            result=process_intelligence(d, data, '2026-10-15T12:00:00+00:00')
            self.assertEqual(result['newAlerts'], 0)
            alerts=json.loads((Path(d)/'data/alerts.json').read_text())['alerts']
            self.assertEqual({a['type'] for a in alerts}, {'new-kev', 'epss-rise'})
            snap=json.loads((Path(d)/'data/vulnerabilities.json').read_text())
            self.assertEqual(snap['schemaVersion'],2)
            self.assertEqual(len(snap['vulnerabilities'][0]['epssHistory']),2)

    def test_threshold_in_percentage_points_not_relative_percent(self):
        with tempfile.TemporaryDirectory() as d:
            process_intelligence(d,fixture({'CVE-2026-0001':.4}),'2026-10-14T00:00:00+00:00')
            process_intelligence(d,fixture({'CVE-2026-0001':.5}),'2026-10-15T00:00:00+00:00')
            self.assertEqual(json.loads((Path(d)/'data/alerts.json').read_text())['alerts'],[])

    def test_bad_history_aborts(self):
        with tempfile.TemporaryDirectory() as d:
            history=Path(d)/'data/history.json';history.parent.mkdir()
            history.write_text('{"schemaVersion":99}')
            with self.assertRaises(ValueError):
                process_intelligence(d,fixture({'CVE-2026-0001':.1}),'2026-10-15T00:00:00+00:00')

if __name__=='__main__': unittest.main()
