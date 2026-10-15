import sys, unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from prioritisation import assess, produce_priorities
class V04Tests(unittest.TestCase):
    def test_kev_separate_from_predicted_exploitation(self):
        r=assess({'id':'CVE-2026-12345','epss':.8,'cvss':9.8},'emerging')
        self.assertEqual(r['tier'],'Investigate now')
        self.assertFalse(r['kev'])
        self.assertNotIn('Confirmed exploitation (CISA KEV)',r['reasons'])
    def test_known_exploited_always_marked(self):
        r=assess({'id':'CVE-2026-12345','epss':None,'cvss':None},'kev')
        self.assertEqual(r['tier'],'Prioritise review')
        self.assertTrue(r['kev'])
    def test_ephemeral_momentum(self):
        r=assess({'id':'CVE-2026-12345','epss':.3,'cvss':8,'epssDeltaPp':26},'emerging')
        self.assertIn('EPSS rose at least 25 percentage points',r['reasons'])
    def test_combined_sorted_by_tier(self):
        out=produce_priorities([{'id':'CVE-2026-12345','epss':.8}],[{'id':'CVE-2026-12346','epss':.01}], '2026-10-15T00:00:00+00:00')
        self.assertEqual([r['kind'] for r in out['records']],['kev','emerging'])
    def test_no_fake_evidence(self):
        r=assess({'id':'CVE-2026-12345','epss':None},'emerging')
        self.assertEqual(r['evidence'],[])
        self.assertEqual(r['tier'],'Routine review')
if __name__=='__main__':unittest.main()
