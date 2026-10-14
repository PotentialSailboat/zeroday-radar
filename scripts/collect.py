#!/usr/bin/env python3
"""Collect CISA KEV, FIRST EPSS and bounded NVD enrichment. Python stdlib only."""
import json, os, time, urllib.request, urllib.parse, datetime, pathlib, sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
OUT=ROOT/'data'/'vulnerabilities.json'
KEV='https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
EPSS='https://api.first.org/data/v1/epss'
NVD='https://services.nvd.nist.gov/rest/json/cves/2.0'

def fetch(url, headers=None, attempts=3):
    for i in range(attempts):
        try:
            req=urllib.request.Request(url,headers={'User-Agent':'ZeroDayRadar/0.1 (open-source dashboard)',**(headers or {})})
            with urllib.request.urlopen(req,timeout=40) as r: return json.load(r)
        except Exception as e:
            if i==attempts-1: raise
            time.sleep(2**i*3)

def chunks(items,size):
    for i in range(0,len(items),size):yield items[i:i+size]

def cvss(cve):
    metrics=cve.get('metrics',{})
    for key in ('cvssMetricV40','cvssMetricV31','cvssMetricV30','cvssMetricV2'):
        for entry in metrics.get(key,[]):
            if entry.get('type')=='Primary' or len(metrics.get(key,[]))==1:
                d=entry.get('cvssData',{})
                return d.get('baseScore'),d.get('baseSeverity') or entry.get('baseSeverity')
    return None,None

def main():
    now=datetime.datetime.now(datetime.timezone.utc).isoformat()
    feed=fetch(KEV)
    entries=feed.get('vulnerabilities',[])
    if not entries: raise RuntimeError('KEV feed returned no vulnerabilities; refusing to overwrite data')
    # KEV is the authoritative scope of v0.1; sort by addition date for recent-first enrichment.
    entries.sort(key=lambda e:(e.get('dateAdded',''),e.get('cveID','')),reverse=True)
    records={e['cveID']:{'id':e['cveID'],'vendor':e.get('vendorProject',''),'product':e.get('product',''),
        'name':e.get('vulnerabilityName',''),'description':e.get('shortDescription',''),
        'dateAdded':e.get('dateAdded',''),'dueDate':e.get('dueDate',''),
        'requiredAction':e.get('requiredAction',''),'knownRansomwareCampaignUse':e.get('knownRansomwareCampaignUse','Unknown'),
        'notes':e.get('notes',''),'kev':True,'epss':None,'epssPercentile':None,'cvss':None,'severity':None,
        'nvdUrl':'https://nvd.nist.gov/vuln/detail/'+e['cveID']} for e in entries if e.get('cveID')}
    ids=list(records)
    errors=[]
    # FIRST API supports comma-separated CVE requests. Batches keep URLs reasonably short.
    for batch in chunks(ids,60):
        try:
            url=EPSS+'?'+urllib.parse.urlencode({'cve':','.join(batch)})
            response=fetch(url)
            for e in response.get('data',[]):
                r=records.get(e.get('cve'))
                if r:
                    r['epss']=float(e['epss'])
                    r['epssPercentile']=float(e['percentile'])
        except Exception as ex: errors.append('EPSS batch failed: '+str(ex))
        time.sleep(.15)
    # Enrich recent KEV entries only; NVD unauthenticated rate limits are restrictive.
    limit=max(0,min(int(os.environ.get('NVD_ENRICH_LIMIT','15')),100))
    headers={'apiKey':os.environ['NVD_API_KEY']} if os.environ.get('NVD_API_KEY') else {}
    for cve_id in ids[:limit]:
        try:
            payload=fetch(NVD+'?'+urllib.parse.urlencode({'cveId':cve_id}),headers)
            vulns=payload.get('vulnerabilities',[])
            if vulns:
                cve=vulns[0]['cve']; r=records[cve_id]
                r['cvss'],r['severity']=cvss(cve)
                r['published']=cve.get('published');r['lastModified']=cve.get('lastModified')
        except Exception as ex: errors.append('NVD '+cve_id+': '+str(ex))
        time.sleep(.65 if headers else 6.5)
    # Explainable priority tiers: all KEV are exploited, EPSS is a probability not confirmation.
    for r in records.values():
        p=r['epss']
        r['priority']='Critical' if p is not None and p>=.5 else ('High' if p is not None and p>=.1 else 'Elevated')
        r['priorityReason']='CISA KEV confirms exploitation; '+('EPSS >= 50%' if r['priority']=='Critical' else 'EPSS >= 10%' if r['priority']=='High' else 'EPSS below 10% or unavailable')
    output={'schemaVersion':1,'updatedAt':now,'sources':{'kev':KEV,'epss':EPSS,'nvd':NVD},
        'scope':'CISA KEV catalogue (not all published CVEs)','nvdEnrichedCount':sum(r['cvss'] is not None for r in records.values()),
        'warnings':errors[:25],'vulnerabilities':list(records.values())}
    OUT.parent.mkdir(parents=True,exist_ok=True)
    tmp=OUT.with_suffix('.tmp');tmp.write_text(json.dumps(output,ensure_ascii=False,separators=(',',':')),encoding='utf-8');tmp.replace(OUT)
    print(f"Saved {len(records)} KEV records; EPSS coverage {sum(r['epss'] is not None for r in records.values())}; warnings {len(errors)}")
if __name__=='__main__':
    try:main()
    except Exception as e: print('Collector failed:',e,file=sys.stderr);sys.exit(1)
