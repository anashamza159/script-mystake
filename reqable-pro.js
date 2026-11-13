(()=>{
// تشغيل ثاني مرة = إغلاق الأداة وإرجاع كل شي لأصله
if(window.__reqablePro){window.__reqablePro.destroy();return}

const MAX=200000;
const OF=window.fetch;
const XP=XMLHttpRequest.prototype;
const O_OPEN=XP.open,O_SEND=XP.send,O_SET=XP.setRequestHeader;
let on=true;
const STATE={logs:[],rules:[],sel:null};

// ================= UI =================
const ui=document.createElement('div');ui.id='__reqablePro';
ui.style.cssText="position:fixed;inset:2%;z-index:2147483647;background:#0b1120;color:#e2e8f0;border:1px solid #1e293b;border-radius:8px;display:flex;flex-direction:column;font:12px monospace;box-shadow:0 0 50px #000";
ui.innerHTML=`
<div style="display:flex;justify-content:space-between;align-items:center;padding:10px 15px;background:#1e293b;border-radius:8px 8px 0 0">
  <b style="color:#38bdf8;font-size:15px">⚡ REQABLE PRO</b>
  <div>
    <button id="rpClear" style="background:#334155;color:#fff;border:0;padding:5px 10px;border-radius:4px;cursor:pointer;margin-right:5px">Clear Logs</button>
    <button id="rpClose" style="background:#ef4444;color:#fff;border:0;padding:5px 10px;border-radius:4px;cursor:pointer">Close</button>
  </div>
</div>
<div style="display:flex;flex:1;overflow:hidden;min-height:0">
  <div id="rpList" style="width:35%;min-width:160px;overflow:auto;border-right:1px solid #1e293b;background:#0f172a"></div>
  <div id="rpDetail" style="flex:1;overflow:auto;padding:15px;white-space:pre-wrap;word-break:break-all;background:#0b1120">اختر طلب من القائمة</div>
</div>
<div style="padding:10px;background:#1e293b;display:flex;gap:8px;flex-wrap:wrap;align-items:center;border-radius:0 0 8px 8px">
  <select id="rpRuleType" style="background:#0f172a;border:1px solid #334155;color:#fff;padding:5px;border-radius:4px">
    <option value="req">Request</option><option value="res">Response (fetch/JSON)</option>
  </select>
  <input id="rpRuleMatch" placeholder="URL Match (Regex)" style="flex:1;min-width:120px;background:#0f172a;border:1px solid #334155;color:#fff;padding:5px;border-radius:4px">
  <input id="rpRuleMod" placeholder='JSON Mod {"email":"x@y.com"}' style="flex:2;min-width:160px;background:#0f172a;border:1px solid #334155;color:#fff;padding:5px;border-radius:4px">
  <button id="rpAddRule" style="background:#38bdf8;color:#000;border:0;padding:5px 15px;border-radius:4px;cursor:pointer;font-weight:bold">Add Rule</button>
  <button id="rpClearRules" style="background:#334155;color:#fff;border:0;padding:5px 10px;border-radius:4px;cursor:pointer">Clear Rules</button>
  <span id="rpMsg" style="color:#94a3b8">Rules: 0</span>
</div>`;
document.body.appendChild(ui);

const $=s=>ui.querySelector(s);
const list=$('#rpList'),detail=$('#rpDetail'),msg=$('#rpMsg');
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const pretty=s=>{if(!s)return'';try{return JSON.stringify(JSON.parse(s),null,2)}catch(e){return s}};
const toObj=h=>{try{return h?Object.fromEntries(new Headers(h)):{}}catch(e){return{}}};
const setMsg=(t,bad)=>{msg.textContent=t;msg.style.color=bad?'#ef4444':'#22c55e'};
const rulesCount=()=>msg.textContent='Rules: '+STATE.rules.length;

function showDetail(o){
  STATE.sel=o;
  detail.innerHTML=`<b style="color:#38bdf8">${esc(o.method)}</b> ${esc(o.url)}
<b>Status:</b> ${o.status??'pending'}

<b>Request Headers:</b>
${esc(JSON.stringify(o.reqHeaders||{},null,2))}

<b>Request Body:</b>
${esc(pretty(o.reqBody))}

<b>Response Headers:</b>
${esc(JSON.stringify(o.resHeaders||{},null,2))}

<b>Response Body:</b>
${esc(pretty(o.resBody))}`;
}

// يضيف السطر مرة وحدة فقط، وبعدين يحدّثه (كان يتكرر مع XHR)
function update(o){
  if(!o.el){
    o.el=document.createElement('div');
    o.el.style.cssText="padding:8px;border-bottom:1px solid #1e293b;cursor:pointer;display:flex;flex-direction:column;gap:4px";
    o.el.onclick=()=>showDetail(o);
    list.prepend(o.el);
  }
  const s=o.status;
  const color=s==null?'#94a3b8':(s==='ERR'||s>=400?'#ef4444':(s>=300?'#eab308':'#22c55e'));
  o.el.innerHTML=`<div style="display:flex;justify-content:space-between"><span style="color:${color};font-weight:bold">${esc(o.method)}</span><span style="color:${color}">${s??'...'}</span></div><div style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#cbd5e1">${esc(o.url)}</div>`;
  if(STATE.sel===o)showDetail(o);
}
function addLog(o){STATE.logs.push(o);update(o)}

// ================= Rules =================
$('#rpAddRule').onclick=()=>{
  try{
    const data=JSON.parse($('#rpRuleMod').value);
    if(!data||typeof data!=='object'||Array.isArray(data))throw 0;
    STATE.rules.push({type:$('#rpRuleType').value,match:new RegExp($('#rpRuleMatch').value,'i'),data});
    setMsg('Rule added ✓ ('+STATE.rules.length+')');
  }catch(e){setMsg('Error in rule format',true)}
};
$('#rpClearRules').onclick=()=>{STATE.rules=[];rulesCount()};

const findRule=(type,url)=>STATE.rules.find(r=>r.type===type&&r.match.test(url));
function applyRule(type,url,text){
  const r=findRule(type,url);
  if(r&&typeof text==='string'){
    try{return JSON.stringify(Object.assign(JSON.parse(text),r.data))}catch(e){}
  }
  return text;
}

// ================= Hook Fetch =================
window.fetch=async function(input,init){
  if(!on)return OF.call(this,input,init);
  const isReq=typeof Request!=='undefined'&&input instanceof Request;
  const url=String(isReq?input.url:(input&&input.url)||input);
  const method=String(init?.method||(isReq?input.method:'GET')).toUpperCase();

  let body=init?.body;
  if(typeof body==='string'){
    const nb=applyRule('req',url,body);
    if(nb!==body){body=nb;init={...init,body}}
  }

  const log={method,url,status:null,
    reqHeaders:toObj(init?.headers||(isReq?input.headers:null)),
    reqBody:typeof body==='string'?body:(body?'['+(body.constructor?.name||typeof body)+']':'')};
  addLog(log);

  try{
    const res=await OF.call(this,input,init);
    log.status=res.status;
    log.resHeaders=toObj(res.headers);
    const ct=res.headers.get('content-type')||'';

    // تعديل الرد (JSON فقط)
    if(findRule('res',url)&&/json/i.test(ct)){
      const txt=await res.clone().text();
      const nt=applyRule('res',url,txt);
      log.resBody=nt.slice(0,MAX);update(log);
      if(nt!==txt)return new Response(nt,{status:res.status,statusText:res.statusText,headers:res.headers});
      return res;
    }

    update(log);
    // قراءة الرد بالخلفية عشان ما نأخر الصفحة ولا نعلّق الـ streams
    if(/event-stream/i.test(ct))log.resBody='[event-stream]';
    else if(/^(image|video|audio)\/|octet-stream/i.test(ct))log.resBody='['+ct+']';
    else res.clone().text().then(t=>{log.resBody=t.slice(0,MAX);update(log)}).catch(()=>{});
    update(log);
    return res;
  }catch(e){
    log.status='ERR';log.resBody=String(e);update(log);throw e;
  }
};

// ================= Hook XHR =================
XP.open=function(m,u){
  this._rm={method:String(m).toUpperCase(),url:String(u),status:null,reqHeaders:{}};
  return O_OPEN.apply(this,arguments);
};
XP.setRequestHeader=function(k,v){
  if(this._rm)this._rm.reqHeaders[k]=v;
  return O_SET.apply(this,arguments);
};
XP.send=function(b){
  const rm=this._rm;
  if(!on||!rm)return O_SEND.call(this,b);
  if(typeof b==='string')b=applyRule('req',rm.url,b);
  rm.reqBody=typeof b==='string'?b:(b?'['+(b.constructor?.name||typeof b)+']':'');
  addLog(rm);
  this.addEventListener('loadend',()=>{
    rm.status=this.status||'ERR';
    rm.resHeaders=(this.getAllResponseHeaders()||'').trim().split(/\r?\n/).reduce((a,l)=>{
      const i=l.indexOf(':');if(i>0)a[l.slice(0,i).trim()]=l.slice(i+1).trim();return a},{});
    try{
      const t=this.responseType;
      if(t===''||t==='text')rm.resBody=this.responseText.slice(0,MAX);
      else if(t==='json')rm.resBody=JSON.stringify(this.response);
      else rm.resBody='[responseType: '+t+']';
    }catch(e){rm.resBody='[unreadable]'}
    update(rm);
  });
  return O_SEND.call(this,b);
};

// ================= Close / Clear / Destroy =================
function destroy(){
  on=false;
  window.fetch=OF;
  XP.open=O_OPEN;XP.send=O_SEND;XP.setRequestHeader=O_SET;
  ui.remove();
  delete window.__reqablePro;
  delete window.__rp;
}
ui.destroy=destroy;
window.__reqablePro=ui;
$('#rpClose').onclick=destroy;
$('#rpClear').onclick=()=>{STATE.logs=[];STATE.sel=null;list.innerHTML='';detail.innerHTML=''};

// ================= Console API =================
window.__rp={
  logs:()=>STATE.logs,
  replay:i=>{
    const l=STATE.logs[i];if(!l)return;
    const noBody=/^(GET|HEAD)$/.test(l.method);
    return OF(l.url,{method:l.method,headers:l.reqHeaders,body:noBody||!l.reqBody?undefined:l.reqBody});
  }
};

console.log('%c⚡ Reqable PRO Active','color:#38bdf8;font-size:16px;font-weight:bold');
})();
