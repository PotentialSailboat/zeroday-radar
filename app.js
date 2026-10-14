'use strict';
const $=id=>document.getElementById(id);
const state={records:[],filtered:[],page:0,pageSize:25};
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
  tr.append(el('td',[r.vendor,r.product].filter(Boolean).join(' / ')),el('td',fmtDate(r.dateAdded)),el('td',r.epss==null?'—':(r.epss*100).toFixed(2)+'%'),el('td',r.cvss==null?'—':r.cvss));
  const pr=document.createElement('td');pr.append(el('span',r.priority,'pill '+r.priority));tr.append(pr);
  const source=document.createElement('td'),link=el('a','NVD ↗');link.href='https://nvd.nist.gov/vuln/detail/'+encodeURIComponent(r.id);link.target='_blank';link.rel='noopener noreferrer';source.append(link);tr.append(source);tbody.append(tr);
 }
 if(!state.filtered.length){const tr=document.createElement('tr'),td=el('td','No matching vulnerabilities');td.colSpan=7;tr.append(td);tbody.append(tr);}
 $('page').textContent=`Page ${state.page+1} of ${totalPages}`;$('prev').disabled=state.page===0;$('next').disabled=state.page>=totalPages-1;
}
for(const id of ['search','priority','sort'])$(id).addEventListener('input',()=>{state.page=0;render()});
$('prev').addEventListener('click',()=>{state.page--;render()});$('next').addEventListener('click',()=>{state.page++;render()});
(async()=>{try{const response=await fetch('data/vulnerabilities.json',{cache:'no-store'});if(!response.ok)throw Error('Data not published yet (HTTP '+response.status+'). Run the GitHub Actions collector.');
const data=await response.json();if(!Array.isArray(data.vulnerabilities))throw Error('Invalid vulnerability data format');state.records=data.vulnerabilities;
$('count').textContent=state.records.length.toLocaleString();$('critical').textContent=state.records.filter(r=>r.priority==='Critical').length.toLocaleString();$('high').textContent=state.records.filter(r=>r.priority==='High').length.toLocaleString();
$('coverage').textContent=(state.records.length?100*state.records.filter(r=>r.epss!=null).length/state.records.length:0).toFixed(1)+'%';$('updated').textContent=fmtDate(data.updatedAt);
const age=(Date.now()-Date.parse(data.updatedAt))/3600000;$('health').textContent=age>24?'⚠ Data stale':'● Intelligence loaded';if(data.warnings?.length){$('error').hidden=false;$('error').textContent=`Partial source errors (${data.warnings.length}): check collector logs. Some enrichment may be missing.`;}render();
}catch(e){$('health').textContent='⚠ Data unavailable';$('error').hidden=false;$('error').textContent=e.message;$('rows').replaceChildren();const tr=document.createElement('tr'),td=el('td','No data available yet. Run the collector workflow.');td.colSpan=7;tr.append(td);$('rows').append(tr);}})();
