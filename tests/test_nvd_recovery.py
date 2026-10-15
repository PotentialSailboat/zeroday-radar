import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from collect import restore_nvd_fields, load_previous

class RecoveryTests(unittest.TestCase):
    def test_retains_previous_nvd_data(self):
        records = {'CVE-1': {'cvss': None, 'severity': None, 'published': None, 'lastModified': None}}
        previous = {'vulnerabilities': [{'id': 'CVE-1', 'cvss': 9.8, 'severity': 'CRITICAL', 'published': '2026-01-01', 'lastModified': '2026-02-01'}]}
        self.assertEqual(restore_nvd_fields(records, previous), 1)
        self.assertEqual(records['CVE-1']['cvss'], 9.8)
        self.assertEqual(records['CVE-1']['published'], '2026-01-01')

    def test_does_not_replace_existing_data(self):
        records = {'CVE-1': {'cvss': 8.1, 'severity': 'HIGH'}}
        previous = {'vulnerabilities': [{'id': 'CVE-1', 'cvss': 9.8, 'severity': 'CRITICAL'}]}
        self.assertEqual(restore_nvd_fields(records, previous), 0)
        self.assertEqual(records['CVE-1']['cvss'], 8.1)

if __name__ == '__main__':
    unittest.main()
