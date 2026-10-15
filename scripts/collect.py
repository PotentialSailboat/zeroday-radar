#!/usr/bin/env python3
"""Collect CISA KEV, FIRST EPSS and bounded NVD enrichment. Python stdlib only."""
import json, os, time, urllib.request, urllib.parse, urllib.error, datetime, pathlib, sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
OUT=ROOT/'data'/'vulnerabilities.json'
KEV='https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
EPSS='https://api.first.org/data/v1/epss'
NVD='https://services.nvd.nist.gov/rest/json/cves/2.0'

def fetch(url, headers=None, attempts=3):
    for i in range(attempts):
        try:
            req=urllib.request.Request(url,headers={'User-Agent':'ZeroDayRadar/0.3 (open-source dashboard)',**(headers or {})})
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

def restore_nvd_fields(records, previous):
    """Retain prior NVD enrichment when the NVD service is unavailable."""
    retained = 0
    for item in previous.get('vulnerabilities', []):
        current = records.get(item.get('id'))
        if not current:
            continue
        for field in ('cvss', 'severity', 'published', 'lastModified'):
            if current.get(field) is None and item.get(field) is not None:
                current[field] = item[field]
                if field == 'cvss':
                    retained += 1
    return retained


def load_previous(path):
    try:
        with path.open(encoding='utf-8') as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}

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
    previous = load_previous(OUT)
    retained = restore_nvd_fields(records, previous)
    errors=[]
    epss_failed_batches=0
    epss_success_batches=0
    nvd_success=0
    nvd_failed=0
    # FIRST API supports comma-separated CVE requests. Batches keep URLs reasonably short.
    for batch in chunks(ids,60):
        try:
            url=EPSS+'?'+urllib.parse.urlencode({'cve':','.join(batch)})
            response=fetch(url)
            epss_success_batches+=1
            for e in response.get('data',[]):
                r=records.get(e.get('cve'))
                if r:
                    r['epss']=float(e['epss'])
                    r['epssPercentile']=float(e['percentile'])
        except Exception as ex:
            epss_failed_batches+=1
            errors.append('EPSS batch failed: '+str(ex))
        time.sleep(.15)
    # Enrich recent KEV entries only; NVD unauthenticated rate limits are restrictive.
    limit=max(0,min(int(os.environ.get('NVD_ENRICH_LIMIT','15')),100))
    headers={'apiKey':os.environ['NVD_API_KEY']} if os.environ.get('NVD_API_KEY') else {}
    consecutive_unavailable = 0
    skipped_due_to_outage = 0
    for index, cve_id in enumerate(ids[:limit]):
        if consecutive_unavailable >= 3:
            skipped_due_to_outage = limit - index
            errors.append(f'NVD unavailable: stopped after 3 consecutive HTTP 503 responses; skipped {skipped_due_to_outage} lookups')
            break
        try:
            payload=fetch(NVD+'?'+urllib.parse.urlencode({'cveId':cve_id}),headers)
            vulns=payload.get('vulnerabilities',[])
            if vulns:
                cve=vulns[0]['cve']; r=records[cve_id]
                r['cvss'],r['severity']=cvss(cve)
                r['published']=cve.get('published');r['lastModified']=cve.get('lastModified')
            consecutive_unavailable = 0
            nvd_success+=1
        except urllib.error.HTTPError as ex:
            nvd_failed+=1
            errors.append('NVD '+cve_id+': HTTP '+str(ex.code)+' '+str(ex.reason))
            consecutive_unavailable = consecutive_unavailable + 1 if ex.code == 503 else 0
        except Exception as ex:
            nvd_failed+=1
            errors.append('NVD '+cve_id+': '+str(ex))
            consecutive_unavailable = 0
        time.sleep(.65 if headers else 6.5)
    # Retrieve the recent publication window using correct NVD pagination, then
    # choose the newest records locally (the first NVD page is oldest-first).
    emerging_path=ROOT/'data'/'emerging.json'
    previous_emerging=load_previous(emerging_path)
    window_end_dt=datetime.datetime.now(datetime.timezone.utc)
    window_start=(window_end_dt-datetime.timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%S.000')
    window_end=window_end_dt.strftime('%Y-%m-%dT%H:%M:%S.000')
    emerging={'updatedAt':now,'source':NVD,'windowDays':7,'records':[], 'status':'ok',
              'collectionComplete':False,'scannedResults':0,'totalResults':0}
    page_size=2000
    max_pages=max(1,min(int(os.environ.get('NVD_DISCOVERY_MAX_PAGES','4')),10))
    discovery_items=[]
    try:
        for page in range(max_pages):
            query=urllib.parse.urlencode({'pubStartDate':window_start,'pubEndDate':window_end,
                                          'resultsPerPage':page_size,'startIndex':page*page_size})
            found=fetch(NVD+'?'+query,headers)
            total=int(found.get('totalResults',0))
            items=found.get('vulnerabilities',[])
            discovery_items.extend(items)
            emerging['totalResults']=total
            emerging['scannedResults']=len(discovery_items)
            if len(discovery_items)>=total or not items: break
            time.sleep(.7 if headers else 6.5)
        emerging['collectionComplete']=len(discovery_items)>=emerging['totalResults']
        if not emerging['collectionComplete']:
            emerging['status']='partial'
        eligible=[]
        for item in discovery_items:
            cve=item.get('cve',{})
            cve_id=cve.get('id','')
            if not cve_id.startswith('CVE-') or cve_id in records: continue
            if cve.get('vulnStatus')=='Rejected': continue
            desc=next((d.get('value','') for d in cve.get('descriptions',[]) if d.get('lang')=='en'),'')
            score,severity=cvss(cve)
            eligible.append({'id':cve_id,'description':desc[:600], 'published':cve.get('published'),
                'lastModified':cve.get('lastModified'),'cvss':score,'severity':severity,'kev':False,
                'epss':None,'epssPercentile':None,'nvdUrl':'https://nvd.nist.gov/vuln/detail/'+cve_id})
        eligible.sort(key=lambda r:(r.get('published') or '',r['id']),reverse=True)
        emerging['records']=eligible[:250]
        emerging['sampleLimited']=(not emerging['collectionComplete']) or len(eligible)>250
        # EPSS enrich the selected cross-source discovery candidates, not just KEV.
        prior_records={r['id']:r for r in previous_emerging.get('records',[])}
        for batch in chunks([r['id'] for r in emerging['records']],60):
            try:
                resp=fetch(EPSS+'?'+urllib.parse.urlencode({'cve':','.join(batch)}))
                values={r['cve']:r for r in resp.get('data',[])}
                for r in emerging['records']:
                    value=values.get(r['id'])
                    if value:
                        r['epss']=float(value['epss']);r['epssPercentile']=float(value['percentile'])
            except Exception as ex:
                errors.append('Emerging EPSS batch: '+str(ex))
            time.sleep(.15)
        for r in emerging['records']:
            old=prior_records.get(r['id'],{}).get('epss')
            r['epssDeltaPp']=round((r['epss']-old)*100,2) if isinstance(old,(int,float)) and isinstance(r['epss'],(int,float)) else None
    except Exception as ex:
        errors.append('NVD emerging CVE discovery: '+str(ex))
        emerging=previous_emerging if previous_emerging.get('records') else emerging
        emerging['status']='stale' if emerging.get('records') else 'unavailable'
        emerging['lastAttemptAt']=now
    emerging_path.parent.mkdir(parents=True,exist_ok=True)
    emerging_path.write_text(json.dumps(emerging,ensure_ascii=False),encoding='utf-8')
    # Explainable priority tiers: all KEV are exploited, EPSS is a probability not confirmation.
    for r in records.values():
        p=r['epss']
        r['priority']='Critical' if p is not None and p>=.5 else ('High' if p is not None and p>=.1 else 'Elevated')
        r['priorityReason']='CISA KEV confirms exploitation; '+('EPSS >= 50%' if r['priority']=='Critical' else 'EPSS >= 10%' if r['priority']=='High' else 'EPSS below 10% or unavailable')
    output={'schemaVersion':1,'updatedAt':now,'sources':{'kev':KEV,'epss':EPSS,'nvd':NVD},
        'scope':'CISA KEV catalogue (not all published CVEs)','nvdEnrichedCount':sum(r['cvss'] is not None for r in records.values()),
        'warnings':errors[:25], 'sourceHealth':{'cisa':{'status':'ok','lastSuccessfulAt':now}, 'epss':{'status':'partial' if epss_failed_batches and epss_success_batches else 'unavailable' if epss_failed_batches else 'ok','successfulBatches':epss_success_batches,'failedBatches':epss_failed_batches,'lastSuccessfulAt':now if epss_success_batches else None},'nvd':{'status':'partial' if nvd_failed and nvd_success else 'unavailable' if nvd_failed else 'ok','successfulLookups':nvd_success,'failedLookups':nvd_failed,'skippedLookups':skipped_due_to_outage,'cachedCvss':retained,'lastSuccessfulAt':now if nvd_success else None},'emerging':{'status':emerging['status'],'recordCount':len(emerging['records']),'scannedResults':emerging.get('scannedResults'),'totalResults':emerging.get('totalResults'),'collectionComplete':emerging.get('collectionComplete'),'lastSuccessfulAt':emerging.get('updatedAt')}}, 'vulnerabilities':list(records.values())}
    OUT.parent.mkdir(parents=True,exist_ok=True)
    from intelligence_history import process_intelligence
    summary=process_intelligence(ROOT, output, now)
    from prioritisation import produce_priorities
    priorities=produce_priorities(output['vulnerabilities'], emerging['records'], now, emerging.get('status'))
    (ROOT/'data'/'priorities.json').write_text(json.dumps(priorities,ensure_ascii=False),encoding='utf-8')
    print(f"Saved {len(records)} KEV records; EPSS coverage {sum(r['epss'] is not None for r in records.values())}; cached CVSS values {retained}; warnings {len(errors)}; alerts added {summary['newAlerts']}")
    for error in errors[:25]:
        print('Source warning:', error, file=sys.stderr)
if __name__=='__main__':
    try:main()
    except Exception as e: print('Collector failed:',e,file=sys.stderr);sys.exit(1)
