"""Stable change detection, bounded history and RSS generation. Python standard library only.

A baseline is created on first successful run. Alerts start with *subsequent* runs.
EPSS deltas compare against the preceding UTC daily baseline, not the last six-hour run.
"""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
from xml.etree import ElementTree as ET
ET.register_namespace('atom', 'http://www.w3.org/2005/Atom')

KEEP_DAYS = 45
KEEP_ALERTS = 200
THRESHOLD = 0.25  # probability-point difference; 0.15 -> 0.40
SITE_URL = os.environ.get('SITE_URL', 'https://potentialsailboat.github.io/zeroday-radar/').rstrip('/') + '/'

def read_json(path, fallback):
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except FileNotFoundError:
        return fallback

def save_json(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + '.tmp')
    tmp.write_text(json.dumps(obj, ensure_ascii=False, separators=(',', ':')), encoding='utf-8')
    tmp.replace(path)

def valid_history(history):
    return (isinstance(history, dict) and history.get('schemaVersion') == 1
            and isinstance(history.get('days'), dict) and isinstance(history.get('latest'), dict))

def alerts_for(previous, current, baseline, now):
    """Compare last successful collection for KEV and previous daily snapshot for EPSS."""
    messages=[]
    for cve_id, record in current.items():
        if cve_id not in previous:
            messages.append(make_alert('new-kev', cve_id, record, now,
                f'New CISA KEV entry: {cve_id}',
                'Newly observed in CISA KEV. Confirm affected assets and review vendor guidance.',
                'critical', 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'))
        old = baseline.get(cve_id)
        new = record.get('epss')
        if isinstance(old, (int,float)) and isinstance(new, (int,float)):
            delta=round(new-old, 8)
            if delta >= THRESHOLD:
                messages.append(make_alert('epss-rise', cve_id, record, now,
                    f'EPSS +{delta*100:.1f} pp: {cve_id}',
                    f'EPSS changed from {old*100:.2f}% to {new*100:.2f}% (+{delta*100:.2f} percentage points) against the previous daily baseline.',
                    'high','https://www.first.org/epss/'))
    return messages

def make_alert(kind, cve_id, record, now, title, description, priority, source):
    # Event identity includes observation time so a separate subsequent qualifying event is possible.
    key='|'.join([kind,cve_id,now])
    return {'id':hashlib.sha256(key.encode()).hexdigest()[:24], 'type':kind, 'cve':cve_id,
        'title':title,'description':description,'priority':priority,
        'detectedAt':now,'url':SITE_URL+'?cve='+cve_id,'sourceUrl':source}

def build_rss(alerts, updated_at):
    rss=ET.Element('rss', {'version':'2.0'})
    channel=ET.SubElement(rss,'channel')
    def add(parent, key, value): ET.SubElement(parent,key).text=str(value)
    add(channel,'title','ZeroDay Radar | Threat Intelligence Alerts')
    add(channel,'link',SITE_URL)
    add(channel,'description','New CISA KEV entries and significant EPSS increases. Source links are supplied for validation.')
    add(channel,'language','en-au')
    ET.SubElement(channel,'{http://www.w3.org/2005/Atom}link', {'href':SITE_URL+'feed.xml','rel':'self','type':'application/rss+xml'})
    updated=dt.datetime.fromisoformat(updated_at.replace('Z','+00:00'))
    add(channel,'lastBuildDate',updated.strftime('%a, %d %b %Y %H:%M:%S +0000'))
    for alert in sorted(alerts,key=lambda a:a['detectedAt'],reverse=True):
        item=ET.SubElement(channel,'item')
        for key,val in [('title',alert['title']),('link',alert['url']),('description',alert['description']+' Source: '+alert['sourceUrl']),('guid',alert['id'])]:
            node=ET.SubElement(item,key)
            if key=='guid': node.set('isPermaLink','false')
            node.text=val
        moment=dt.datetime.fromisoformat(alert['detectedAt'].replace('Z','+00:00'))
        add(item,'pubDate',moment.strftime('%a, %d %b %Y %H:%M:%S +0000'))
    return ET.tostring(rss,encoding='utf-8',xml_declaration=True).replace(b'?>', b'?>\n<?xml-stylesheet type="text/xsl" href="feed.xsl"?>', 1)

def process_intelligence(root, dataset, now):
    root=Path(root); data=root/'data'
    current={r['id']:r for r in dataset['vulnerabilities']}
    history_path=data/'history.json'; alert_path=data/'alerts.json'; rss_path=root/'feed.xml'
    history=read_json(history_path,None)
    if history is not None and not valid_history(history):
        raise ValueError('Invalid existing history schema; refusing to overwrite it')
    first=history is None
    history=history or {'schemaVersion':1,'days':{},'latest':{},'lastCollectedAt':None}
    existing=read_json(alert_path,{'schemaVersion':1,'alerts':[]})
    if existing.get('schemaVersion')!=1 or not isinstance(existing.get('alerts'),list):
        raise ValueError('Invalid existing alerts schema')
    today=now[:10]
    # A daily baseline is frozen at the *first* successful collection of that UTC day.
    previous_dates=sorted(x for x in history['days'] if x<today)
    prior_day=history['days'][previous_dates[-1]] if previous_dates else None
    prior_epss=(prior_day or {}).get('epss',{})
    prev=history['latest']
    new=[] if first else alerts_for(prev,current,prior_epss,now)
    # Multiple runs against an unchanged previous-day baseline should not repeat one alert.
    # Identity is based on event category and CVE within UTC day for deduplication.
    existing_ids={a['id'] for a in existing['alerts']}
    for alert in new:
        key=f"{alert['type']}|{alert['cve']}|{today}"
        alert['id']=hashlib.sha256(key.encode()).hexdigest()[:24]
    new=[a for a in new if a['id'] not in existing_ids]
    # Existing daily snapshots are immutable, even when subsequent collections refresh EPSS.
    if today not in history['days']:
        history['days'][today]={'capturedAt':now,'epss':{k:r['epss'] for k,r in current.items() if isinstance(r.get('epss'),(int,float))}}
    cutoff=(dt.date.fromisoformat(today)-dt.timedelta(days=KEEP_DAYS-1)).isoformat()
    history['days']={k:v for k,v in history['days'].items() if k>=cutoff}
    history['latest']={k:{'epss':v.get('epss')} for k,v in current.items()}
    history['lastCollectedAt']=now
    combined=sorted(new+existing['alerts'],key=lambda a:a['detectedAt'],reverse=True)[:KEEP_ALERTS]
    for r in dataset['vulnerabilities']:
        vals=[]
        for day, obj in sorted(history['days'].items()):
            val=obj.get('epss',{}).get(r['id'])
            if isinstance(val,(int,float)): vals.append({'date':day,'epss':val})
        r['epssHistory']=vals
        if len(vals)>=2: r['epssDeltaPp']=round((vals[-1]['epss']-vals[-2]['epss'])*100,2)
        else: r['epssDeltaPp']=None
    dataset['schemaVersion']=2
    dataset['alertsLastUpdatedAt']=now
    dataset['newAlerts']=len(new)
    save_json(data/'vulnerabilities.json',dataset)
    save_json(history_path,history)
    save_json(alert_path,{'schemaVersion':1,'updatedAt':now,'initialisedAt':existing.get('initialisedAt',now),'alerts':combined})
    rss_path.write_bytes(build_rss(combined,now))
    return {'newAlerts':len(new),'totalAlerts':len(combined),'dailySnapshots':len(history['days'])}
