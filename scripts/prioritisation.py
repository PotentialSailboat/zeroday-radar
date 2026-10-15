"""Transparent multi-source triage rules; decision support, not organisational risk."""
import datetime as dt

def assess(record, kind):
    epss=record.get('epss')
    score=record.get('cvss')
    delta=record.get('epssDeltaPp')
    kev=kind=='kev'
    evidence=[]
    if kev:
        evidence.append({'source':'CISA KEV','detail':'Confirmed exploitation reported in KEV'})
    if isinstance(epss,(int,float)):
        evidence.append({'source':'FIRST EPSS','detail':f'{epss*100:.2f}% predicted exploitation probability over 30 days'})
    if isinstance(score,(int,float)):
        evidence.append({'source':'NVD CVSS','detail':f'Technical severity score {score:.1f}'})
    if isinstance(delta,(int,float)) and delta>=10:
        evidence.append({'source':'EPSS history','detail':f'Probability increased {delta:.1f} percentage points over available comparison period'})
    reasons=[]
    if kev: reasons.append('Confirmed exploitation (CISA KEV)')
    if isinstance(epss,(int,float)) and epss>=.5: reasons.append('EPSS at least 50%')
    elif isinstance(epss,(int,float)) and epss>=.1: reasons.append('EPSS at least 10%')
    if isinstance(delta,(int,float)) and delta>=25: reasons.append('EPSS rose at least 25 percentage points')
    elif isinstance(delta,(int,float)) and delta>=10: reasons.append('EPSS rose at least 10 percentage points')
    if isinstance(score,(int,float)) and score>=9: reasons.append('Critical technical severity (CVSS ≥9)')
    # Keep confirmed exploitation separate from predictive urgency; no single opaque score.
    if kev and (epss is not None and epss>=.5 or isinstance(delta,(int,float)) and delta>=25): tier='Investigate now'
    elif kev: tier='Prioritise review'
    elif isinstance(epss,(int,float)) and epss>=.5 and (isinstance(score,(int,float)) and score>=7 or isinstance(delta,(int,float)) and delta>=10): tier='Investigate now'
    elif isinstance(epss,(int,float)) and epss>=.1 or isinstance(delta,(int,float)) and delta>=10: tier='Monitor closely'
    else: tier='Routine review'
    actions=['Check asset inventory and affected software versions','Confirm external exposure and business criticality','Validate vendor advisory, patch availability and compensating controls']
    if kev: actions.insert(0,'Prioritise exploitation assessment and review incident/detection telemetry')
    else: actions.insert(0,'Treat exploitation as unconfirmed; seek corroborating evidence before escalation')
    return {'id':record['id'],'kind':kind,'tier':tier,'reasons':reasons or ['Recently disclosed; no additional prioritisation signals available'],
        'evidence':evidence,'actions':actions,'epss':epss,'cvss':score,'epssDeltaPp':delta,
        'published':record.get('published') or record.get('dateAdded'),'description':record.get('description') or record.get('name',''),
        'vendor':record.get('vendor',''),'product':record.get('product',''),'nvdUrl':'https://nvd.nist.gov/vuln/detail/'+record['id'],
        'kev':kev}

def produce_priorities(kev_records, emerging_records, updated_at, emerging_status='ok'):
    results=[assess(r,'kev') for r in kev_records]+[assess(r,'emerging') for r in emerging_records]
    tiers={'Investigate now':0,'Prioritise review':1,'Monitor closely':2,'Routine review':3}
    results.sort(key=lambda r:(tiers[r['tier']],-(r['epss'] if r['epss'] is not None else -1),r['id']))
    return {'schemaVersion':1,'updatedAt':updated_at,'emergingStatus':emerging_status,'scope':'Known exploited KEV plus bounded recent NVD discovery; not full CVE coverage',
        'methodology':'Rule-based triage; exploitation confirmation is distinct from EPSS prediction and technical severity. No asset relevance is assumed.',
        'records':results}
