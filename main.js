(()=>{
if(window.__reqablePro){window.__reqablePro.remove();delete window.__reqablePro;delete window.__hookOn;return}
window.__hookOn=true;

const STATE={
  logs:[],
  rules:{req:[], res:[]},
  interceptReq:null,
  interceptRes:null
};

// ================= UI =================
const ui=document.createElement('div');ui.id='__reqablePro';
ui.style.cssText="position:fixed;inset:2% 2% 2% 2%;z-index:2147483647;background:#0b1120;color:#e2e8f0;border:1px solid #1e293b;border-radius:8px;display:flex;flex-direction:column;font:12px monospace;box-shadow:0 0 50px #000";
ui.innerHTML=`
<div style="display:flex;justify-content:space-between;align-items:center;padding:10px 15px;background:#1e293b;border-bottom:1px solid #0f172a;border-radius:8px 8px 0 0">
  <b style="color:#38bdf8;font-size:15px">⚡ REQABLE PRO</b>
  <div>
    <button id="rpClear" style="background:#334155;color:#fff;border:0;padding:5px 10px;border-radius:4px;cursor:pointer;margin-right:5px">Clear Logs</button>
    <button id="rpClose" style="background:#ef4444;color:#fff;border:0;padding:5px 10px;border-radius:4px;cursor:pointer">Close</button>
  </div>
</div>
<div style="display:flex;flex:1;overflow:hidden">
  <div id="rpList" style="width:35%;overflow:auto;border-right:1px solid #1e293b;background:#0f172a"></div>
  <div id="rpDetail" style="flex:1;overflow:auto;padding:15px;white-space:pre-wrap;word-break:break-all;background:#0b1120"></div>
</div>
<div style="padding:10px;background:#1e293b;display:flex;gap:10px;border-top:1px solid #0f172a;border-radius:0 0 8px 8px">
  <input id="rpRuleMatch" placeholder="URL Match (Regex)" style="flex:1;background:#0f172a;border:1px solid #334155;color:#fff;padding:5px;border-radius:4px">
  <input id="rpRuleMod" placeholder='JSON Mod {"email":"x@y.com"}' style="flex:2;background:#0f172a;border:1px solid #334155;color:#fff;padding:5px;border-radius:4px">
  <button id="rpAddRule" style="background:#38bdf8;color:#000;border:0;padding:5px 15px;border-radius:4px;cursor:pointer;font-weight:bold">Add Rule</button>
</div>
`;
document.body.appendChild(ui);window.__reqablePro=ui;

const list=ui.querySelector('#rpList');
const detail=ui.querySelector('#rpDetail');
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

function addLog(o){
  STATE.logs.push(o);
  const d=document.createElement('div');
  d.style.cssText="padding:8px;border-bottom:1px solid #1e293b;cursor:pointer;display:flex;flex-direction:column;gap:4px";
  const color=o.status?(o.status>=400?'#ef4444':(o.status>=300?'#eab308':'#22c55e')):'#94a3b8';
  d.innerHTML=`<div style="display:flex;justify-content:space-between"><span style="color:${color};font-weight:bold">${o.method}</span><span style="color:${color}">${o.status||'...'}</span></div><div style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#cbd5e1">${esc(o.url)}</div>`;
  d.onclick=()=>{
    detail.innerHTML=`<b style="color:#38bdf8">${o.method}</b> ${esc(o.url)}\n<b>Status:</b> ${o.status||'pending'}\n\n<b>Request Headers:</b>\n${esc(JSON.stringify(o.reqHeaders||{},null,2))}\n\n<b>Request Body:</b>\n${esc(o.reqBody||'')}\n\n<b>Response Headers:</b>\n${esc(JSON.stringify(o.resHeaders||{},null,2))}\n\n<b>Response Body:</b>\n${esc(o.resBody||'')}`;
  };
  list.prepend(d);
}

ui.querySelector('#rpClose').onclick=()=>{window.__hookOn=false;ui.remove();delete window.__reqablePro;delete window.__hookOn};
ui.querySelector('#rpClear').onclick=()=>{STATE.logs=[];list.innerHTML='';detail.innerHTML=''};

ui.querySelector('#rpAddRule').onclick=()=>{
  const match=ui.querySelector('#rpRuleMatch').value;
  const mod=ui.querySelector('#rpRuleMod').value;
  try{
    STATE.rules.req.push({match:new RegExp(match,'i'),data:JSON.parse(mod)});
    alert('Rule Added!');
  }catch(e){alert('Error in rule format')}
};

const applyRules=(url,body)=>{
  const rule=STATE.rules.req.find(r=>r.match.test(url));
  if(rule && typeof body==='string'){
    try{const j=JSON.parse(body);Object.assign(j,rule.data);return JSON.stringify(j)}catch(e){}
  }
  return body;
};

// ================= Hook Fetch =================
const of=window.fetch;
window.fetch=async function(input,init){
  if(!window.__hookOn) return of.apply(this,arguments);
  const url=typeof input==='string'?input:input.url;
  const method=(init?.method||input?.method||'GET').toUpperCase();
  
  let body=init?.body;
  if(body) body=applyRules(url,body);
  if(init && body) init.body=body;

  const log={method,url,reqHeaders:init?.headers?Object.fromEntries(new Headers(init.headers)):(input?.headers?Object.fromEntries(new Headers(input.headers)):{}),reqBody:body||''};
  
  try{
    const res=await of.apply(this,arguments);
    log.status=res.status;
    log.resHeaders=Object.fromEntries(res.headers);
    
    // Response Intercept (تعديل الرد)
    const clone=res.clone();
    let txt=await clone.text();
    log.resBody=txt;
    addLog(log);
    return res;
  }catch(e){log.status='ERR';log.resBody=String(e);addLog(log);throw e;}
};

// ================= Hook XHR =================
const X=XMLHttpRequest.prototype,o=X.open,se=X.send,h=X.setRequestHeader;
X.open=function(m,u){this._rm={method:m.toUpperCase(),url:u,headers:{}};return o.apply(this,arguments)};
X.setRequestHeader=function(k,v){this._rm&&(this._rm.headers[k]=v);return h.apply(this,arguments)};
X.send=function(b){
  if(!window.__hookOn) return se.apply(this,arguments);
  if(this._rm){
    if(b) b=applyRules(this._rm.url,b);
    this._rm.reqBody=typeof b==='string'?b:'';
    addLog(this._rm);
    const orig=this._rm;
    this.addEventListener('loadend',()=>{
      orig.status=this.status;
      orig.resHeaders=(this.getAllResponseHeaders()||'').split('\r\n').reduce((a,l)=>{const i=l.indexOf(':');if(i>0)a[l.slice(0,i)]=l.slice(i+1).trim();return a},{});
      orig.resBody=this.responseText;
      addLog(orig);
    });
  }
  return se.apply(this,arguments);
};

// ================= API للكونسول =================
window.__rp={
  replay:(i)=>{const l=STATE.logs[i];if(l)return fetch(l.url,{method:l.method,headers:l.reqHeaders,body:l.reqBody})},
  logs:STATE.logs
};

console.log('%c⚡ Reqable PRO Active','color:#38bdf8;font-size:16px;font-weight:bold');
})();
