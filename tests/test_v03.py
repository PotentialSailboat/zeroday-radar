import json
import sys
import tempfile
import unittest
from pathlib import Path
from xml.etree import ElementTree as ET
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from intelligence_history import build_rss, process_intelligence
import collect

class V03Tests(unittest.TestCase):
    def test_rss_uses_atom_namespace_and_stylesheet(self):
        out=build_rss([], '2026-10-15T10:00:00+00:00')
        self.assertIn(b'<?xml-stylesheet',out)
        self.assertIn(b'xmlns:atom=',out)
        self.assertNotIn(b'ns0:',out)
        root=ET.fromstring(out)
        self.assertEqual(len(root.findall('./channel/item')),0)

    def test_alert_rss_remains_machine_readable(self):
        with tempfile.TemporaryDirectory() as d:
            dataset=lambda ids: {'vulnerabilities':[{'id':c,'epss':.05} for c in ids]}
            process_intelligence(d,dataset(['CVE-2026-1234']),'2026-10-14T00:00:00+00:00')
            process_intelligence(d,dataset(['CVE-2026-1234','CVE-2026-5678']),'2026-10-15T00:00:00+00:00')
            rss=ET.parse(Path(d)/'feed.xml')
            self.assertEqual(len(rss.findall('./channel/item')),1)

    def test_new_cve_discovery_uses_bounded_request_and_does_not_label_kev(self):
        with tempfile.TemporaryDirectory() as d:
            original_root, original_out=collect.ROOT,collect.OUT
            collect.ROOT=Path(d);collect.OUT=Path(d)/'data/vulnerabilities.json'
            kev={'vulnerabilities':[{'cveID':'CVE-2026-1234','dateAdded':'2026-10-15'}]}
            discovery={'totalResults':2,'vulnerabilities':[{'cve':{'id':'CVE-2026-5678','published':'2026-10-15T00:00:00','descriptions':[{'lang':'en','value':'Testing CVE'}], 'metrics':{}}},{'cve':{'id':'CVE-2026-1234'}}]}
            def fake_fetch(url,headers=None,attempts=3):
                if url==collect.KEV:return kev
                if url.startswith(collect.EPSS):return {'data':[]}
                if 'pubStartDate=' in url:
                    self.assertIn('resultsPerPage=100',url)
                    return discovery
                return {'vulnerabilities':[]}
            try:
                with patch.object(collect,'fetch',side_effect=fake_fetch),patch.object(collect.time,'sleep'),patch.dict(collect.os.environ,{'NVD_ENRICH_LIMIT':'0'}):
                    collect.main()
                out=json.loads((Path(d)/'data/emerging.json').read_text())
                self.assertEqual([r['id'] for r in out['records']],['CVE-2026-5678'])
                self.assertFalse(out['records'][0]['kev'])
                self.assertTrue(out['sampleLimited']==False)
            finally:
                collect.ROOT,collect.OUT=original_root,original_out

if __name__=='__main__': unittest.main()
