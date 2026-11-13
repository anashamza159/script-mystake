javascript:(()=>{
if(window.__reqable){window.__reqable.remove();delete window.__reqable;delete window.__hookOn;return}
window.__hookOn=true;

const RULES={reqs:[],resps:[]};
const LOG=[];

// ================= UI =================
const ui=document.createElement('div');ui.id='__reqable';
ui.style.cssText="position:fixed;inset:5% 5% 5% 5%;z-index:2147483647;background:#0f172a;color:#e2e8f0;border:2px solid #334155;border-radius:10px;display:flex;flex-direction:column;font:12px monospace;box-shadow:0 0 40px #000";
ui.innerHTML=`
<div style="display:flex;justify-content:space-between;align-items:center;padding:8px 12px;background:#1e293b;border-bottom:1px solid #334155;border-radius:8px 8px 0 0">
  <b style="color:#38bdf8;font-size:14px">🛰️ REQABLE-LITE</b>
  <div>
    <button id="rqClear" style="background:#334155;color:#fff;border:0;border-radius:4px;padding:4px 8px;cursor:pointer;margin-right:5px">Clear</button>
    <button id="rqClose" style="background:#ef4444;color:#fff;border:0;border-radius:4px;padding:4px 8px;cursor:pointer">Close</button>
  </div>
</div>
<div style="display:flex;flex:1;overflow:hidden">
  <div id="rqList" style="width:40%;overflow:auto;border-right:1px solid #334155"></div>
  <div id="rqDetail" style="flex:1;overflow:auto;padding:10px;white-space:pre-wrap;word-break:break-all"></div>
</div>
`;
document.body.appendChild(ui);window.__reqable=ui;

const list=ui.querySelector('#rqList');
const detail=ui.querySelector('#rqDetail');
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

function addLog(o){
  LOG.push(o);
  const d=document.createElement('div');
  d.style.cssText="padding:6px 8px;border-bottom:1px solid #1e293b;cursor:pointer;display:flex;gap:6px";
  const color=o.status?(o.status>=400?'#ef4444':(o.status>=300?'#eab308':'#22c55e')):'#94a3b8';
  d.innerHTML=`<span style="color:${color};font-weight:bold">${o.method}</span><span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(o.url)}</span><span style="color:${color}">${o.status||'...'}</span>`;
  d.onclick=()=>{detail.innerHTML=`<b style="color:#38bdf8">${o.method}</b> ${esc(o.url)}\n<b>Status:</b> ${o.status||'pending'}\n\n<b>Request Headers:</b>\n${esc(JSON.stringify(o.reqHeaders||{},null,2))}\n\n<b>Request Body:</b>\n${esc(o.reqBody||'')}\n\n<b>Response Headers:</b>\n${esc(JSON.stringify(o.resHeaders||{},null,2))}\n\n<b>Response Body:</b>\n${esc((o.resBody||'').slice(0,3000))}`;};
  list.prepend(d);
}

ui.querySelector('#rqClose').onclick=()=>{window.__hookOn=false;ui.remove();delete window.__reqable;delete window.__hookOn};
ui.querySelector('#rqClear').onclick=()=>{LOG.length=0;list.innerHTML='';detail.innerHTML=''};

// ================= Hook fetch =================
const of=window.fetch;
window.fetch=async function(input,init){
  if(!window.__hookOn) return of.apply(this,arguments);
  const url=typeof input==='string'?input:input.url;
  const method=(init?.method||input?.method||'GET').toUpperCase();
  const log={method,url,reqHeaders:init?.headers?Object.fromEntries(new Headers(init.headers)):(input?.headers?Object.fromEntries(new Headers(input.headers)):{}),reqBody:init?.body||''};
  
  // تعديل تلقائي إلا كان كاين rule
  const rule=RULES.reqs.find(r=>new RegExp(r.match).test(url));
  if(rule && init){
    try{const j=JSON.parse(init.body);Object.assign(j,rule.data);init.body=JSON.stringify(j)}catch(e){}
  }

  try{
    const res=await of.apply(this,arguments);
    log.status=res.status;
    log.resHeaders=Object.fromEntries(res.headers);
    const clone=res.clone();
    const txt=await clone.text();
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
    this._rm.reqBody=typeof b==='string'?b:'';
    const rule=RULES.reqs.find(r=>new RegExp(r.match).test(this._rm.url));
    if(rule && typeof b==='string'){
      try{const j=JSON.parse(b);Object.assign(j,rule.data);b=JSON.stringify(j);this._rm.reqBody=b}catch(e){}
    }
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

// ================= API ديال اللوحة =================
window.__reqableAPI={
  rule(match,data){RULES.reqs.push({match,data});console.log('Rule added',match,data)},
  clearRules(){RULES.reqs=[]},
  logs:()=>LOG,
  replay(log){
    return fetch(log.url,{method:log.method,headers:log.reqHeaders,body:log.reqBody||undefined});
  }
};

console.log('%c🛰️ Reqable-Lite active','color:#38bdf8;font-weight:bold;font-size:14px');
console.log('استعمل __reqableAPI.rule("editprofile", {email:"new@x.com"}) باش تزيد قاعدة تعديل تلقائية.');
console.log('استعمل __reqableAPI.logs() باش تشوف اللوغ.');
})();