'use strict';
const $=id=>document.getElementById(id);
const state={records:[],filtered:[],page:0,pageSize:25};
const deepLinkCve=new URLSearchParams(window.location.search).get('cve');
if(deepLinkCve && /^CVE-\d{4}-\d{4,}$/i.test(deepLinkCve)) $('search').value=deepLinkCve;
const safeText=(value)=>value==null||value===''?'—':String(value);
const fmtDate=value=>value?new Date(value.length===10?value+'T00:00:00Z':value).toLocaleDateString(undefined,{year:'numeric',month:'short',day:'numeric'}):'—';
function el(tag,text,cls){const n=document.createElement(tag);if(cls)n.className=cls;n.textContent=safeText(text);return n;}
function render(){const query=$('search').value.trim().toLowerCase(),priority=$('priority').value,sort=$('sort').value;
 state.filtered=state.records.filter(r=>(!priority||r.priority===priority)&&(!query||[r.id,r.vendor,r.product,r.name,r.description].some(v=>String(v||'').toLowerCase().includes(query))));
 state.filtered.sort((a,b)=>sort==='epss'?(b.epss??-1)-(a.epss??-1):sort==='cvss'?(b.cvss??-1)-(a.cvss??-1):String(b.dateAdded||'').localeCompare(String(a.dateAdded||'')));
 const totalPages=Math.max(1,Math.ceil(state.filtered.length/state.pageSize));state.page=Math.min(state.page,totalPages-1);
 $('results').textContent=`${state.filtered.length.toLocaleString()} matching records`;const tbody=$('rows');tbody.replaceChildren();
 for(const r of state.filtered.slice(state.page*state.pageSize,(state.page+1)*state.pageSize)){
  const tr=document.createElement('tr'),first=document.createElement('td');first.append(el('span',r.id,'cve'),el('small',r.name||r.description));tr.append(first);
  tr.append(el('td',[r.vendor,r.product].filter(Boolean).join(' / ')),el('td',fmtDate(r.dateAdded)),el('td',r.epss==null?'—':(r.epss*100).toFixed(2)+'%'),el('td',r.epssDeltaPp==null?'—':(r.epssDeltaPp>0?'+':'')+r.epssDeltaPp.toFixed(2)+' pp'),el('td',r.cvss==null?'—':r.cvss));
  const pr=document.createElement('td');pr.append(el('span',r.priority,'pill '+r.priority));tr.append(pr);
  const source=document.createElement('td'),link=el('a','NVD ↗');link.href='https://nvd.nist.gov/vuln/detail/'+encodeURIComponent(r.id);link.target='_blank';link.rel='noopener noreferrer';source.append(link);tr.append(source);tbody.append(tr);
 }
 if(!state.filtered.length){const tr=document.createElement('tr'),td=el('td','No matching vulnerabilities');td.colSpan=8;tr.append(td);tbody.append(tr);}
 $('page').textContent=`Page ${state.page+1} of ${totalPages}`;$('prev').disabled=state.page===0;$('next').disabled=state.page>=totalPages-1;
}
for(const id of ['search','priority','sort'])$(id).addEventListener('input',()=>{state.page=0;render()});
$('prev').addEventListener('click',()=>{state.page--;render()});$('next').addEventListener('click',()=>{state.page++;render()});
(async()=>{try{const response=await fetch('data/vulnerabilities.json',{cache:'no-store'});if(!response.ok)throw Error('Data not published yet (HTTP '+response.status+'). Run the GitHub Actions collector.');
const data=await response.json();if(!Array.isArray(data.vulnerabilities))throw Error('Invalid vulnerability data format');state.records=data.vulnerabilities;
$('count').textContent=state.records.length.toLocaleString();$('critical').textContent=state.records.filter(r=>r.priority==='Critical').length.toLocaleString();$('high').textContent=state.records.filter(r=>r.priority==='High').length.toLocaleString();
$('coverage').textContent=(state.records.length?100*state.records.filter(r=>r.epss!=null).length/state.records.length:0).toFixed(1)+'%';$('updated').textContent=fmtDate(data.updatedAt);
const age=(Date.now()-Date.parse(data.updatedAt))/3600000;$('health').textContent=age>24?'⚠ Data stale':'● Intelligence loaded';if(data.warnings?.length){$('error').hidden=false;$('error').textContent=`Partial source errors (${data.warnings.length}): check collector logs. Some enrichment may be missing.`;}render();
}catch(e){$('health').textContent='⚠ Data unavailable';$('error').hidden=false;$('error').textContent=e.message;$('rows').replaceChildren();const tr=document.createElement('tr'),td=el('td','No data available yet. Run the collector workflow.');td.colSpan=8;tr.append(td);$('rows').append(tr);}})();

(async()=>{try{const response=await fetch('data/alerts.json',{cache:'no-store'});if(!response.ok)throw Error('Alert history not yet published');const data=await response.json();const target=$('alerts');target.replaceChildren();const alerts=Array.isArray(data.alerts)?data.alerts.slice(0,8):[];if(!alerts.length){target.append(el('p','No new intelligence alerts recorded yet. The first successful collection establishes a baseline.'));return;}for(const a of alerts){const item=el('article','','alert-entry');item.append(el('strong',a.title),el('small',fmtDate(a.detectedAt)),el('p',a.description));const link=el('a','View CVE ↗');link.href='https://nvd.nist.gov/vuln/detail/'+encodeURIComponent(a.cve);link.target='_blank';link.rel='noopener noreferrer';item.append(link);target.append(item);}}catch(e){$('alerts').textContent='Alerts will appear after the v0.2 collector has run.';}})();

// v0.3 source status: all source-provided values are placed in text nodes.
function renderSources(health){const target=$('source-health');target.replaceChildren();for(const [key,label] of [['cisa','CISA KEV'],['epss','FIRST EPSS'],['nvd','NIST NVD enrichment'],['emerging','NVD recent CVEs']]){const info=health?.[key]||{};const card=el('article','','health-card'),title=el('strong',label),status=el('p',String(info.status||'unknown').toUpperCase()),detail=el('small',info.status==='unavailable'?'Feed unavailable; data may be incomplete':info.status==='stale'?'Showing cached discovery results':info.status==='partial'?'Partial source failures; verify against official source':'Latest collection reported successful');card.append(title,status,detail);target.append(card);}}
(async()=>{try{const response=await fetch('data/emerging.json',{cache:'no-store'});if(!response.ok)throw Error('No emerging-CVE snapshot has been published');const data=await response.json();const records=Array.isArray(data.records)?data.records:[];$('emerging-status').textContent=`${records.length} displayed of ${data.totalResults??'unknown'} published in the 7-day window · status: ${data.status||'unknown'}${data.sampleLimited?' · API result is truncated to first 100':''}`;const tbody=$('emerging-rows');tbody.replaceChildren();for(const r of records){const row=document.createElement('tr');row.append(el('td',r.id,'cve'),el('td',fmtDate(r.published)),el('td',r.cvss==null?'—':r.cvss),el('td',r.description));const td=document.createElement('td'),link=el('a','NVD ↗');link.href='https://nvd.nist.gov/vuln/detail/'+encodeURIComponent(r.id);link.rel='noopener noreferrer';link.target='_blank';td.append(link);row.append(td);tbody.append(row);}if(!records.length){const tr=document.createElement('tr'),td=el('td','No discovery records available; check source status.');td.colSpan=5;tr.append(td);tbody.append(tr);}}catch(err){$('emerging-status').textContent=err.message;}})();
(async()=>{try{const res=await fetch('data/vulnerabilities.json',{cache:'no-store'});if(res.ok){const data=await res.json();renderSources(data.sourceHealth);}}catch(err){$('source-health').textContent='Source health unavailable';}})();
