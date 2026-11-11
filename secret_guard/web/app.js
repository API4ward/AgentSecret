"use strict";
let device, session;
const $ = id => document.getElementById(id);
const bytes = value => new TextEncoder().encode(value);
const b64 = data => btoa(String.fromCharCode(...new Uint8Array(data))).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
const store = new Promise((resolve,reject) => {
  const r = indexedDB.open("secret-guard-device",1);
  r.onupgradeneeded = () => r.result.createObjectStore("keys");
  r.onsuccess = () => resolve(r.result); r.onerror = () => reject(new Error("设备存储不可用"));
});
async function saved(value) {
  const db = await store;
  return new Promise((resolve,reject) => {
    const tx = db.transaction("keys", value ? "readwrite" : "readonly");
    const r = value ? tx.objectStore("keys").put(value,"device") : tx.objectStore("keys").get("device");
    tx.oncomplete = () => resolve(r.result); tx.onerror = () => reject(new Error("设备存储失败"));
  });
}
async function api(path,body,auth=false) {
  const headers = {"Content-Type":"application/json"};
  if(auth) headers.Authorization = "Bearer " + session;
  const response = await fetch(path,{method:"POST",headers,body:JSON.stringify(body),credentials:"omit",redirect:"error"});
  const data = await response.json();
  if(!response.ok) throw new Error(data.error || "请求失败");
  return data;
}
async function sign(text) { return b64(await crypto.subtle.sign({name:"ECDSA",hash:"SHA-256"},device.privateKey,bytes(text))); }
function showDevice() {
  $("device-state").textContent = device ? "设备编号：" + device.id : "尚未生成设备";
  $("pairing").textContent = device ? JSON.stringify({device:device.id,jwk:device.jwk},null,2) : "";
  $("pair").disabled = Boolean(device);
}
function action(id,fn) { $(id).onclick = async () => { $("message").textContent=""; $(id).disabled=true; try{await fn();}catch(e){$("message").textContent=e.message;}finally{$(id).disabled=false;showDevice();} }; }
action("pair",async()=>{
  if(device) throw new Error("设备已存在；更换前请在桌面撤销旧设备。");
  const keys = await crypto.subtle.generateKey({name:"ECDSA",namedCurve:"P-256"},false,["sign","verify"]);
  device = {id:"device_"+crypto.randomUUID(),privateKey:keys.privateKey,jwk:await crypto.subtle.exportKey("jwk",keys.publicKey)};
  await saved(device); showDevice();
});
action("connect",async()=>{
  if(!device) throw new Error("请先生成设备并在桌面登记公钥。");
  const c=await api("/device/challenge",{device:device.id});
  const r=await api("/device/login",{device:device.id,challenge:c.challenge,signature:await sign(c.message)});
  session=r.token; $("message").textContent="设备已连接，5 分钟后需重新连接。"; await refresh();
});
function addText(parent,tag,text){const el=document.createElement(tag);el.textContent=text;parent.appendChild(el);return el;}
async function refresh(){
  if(!session) throw new Error("请先连接设备。");
  const data=await api("/pending",{},true); $("requests").replaceChildren();
  if(!data.requests.length) addText($("requests"),"p","暂无待审批请求。");
  for(const request of data.requests){
    const p=request.payload;const card=document.createElement("article");card.className="card";
    addText(card,"h2",p.kind==="reference"?"允许任务引用凭据？":"允许这一次具体使用？");
    const list=document.createElement("dl");card.appendChild(list);
    for(const [label,value] of [["项目",p.preview.project],["凭据",p.secret_id],["任务",p.task],["操作",p.kind==="reference"?"允许引用；使用时仍需批准":`读取 ${p.details.args.repo} 最近 ${p.details.args.limit} 次 workflow 状态`],["有效期",new Date(p.expires_at*1000).toLocaleString()]]){addText(list,"dt",label);addText(list,"dd",value);}
    if(p.kind==="use"){addText(list,"dt","接收方");addText(list,"dd",p.details.host);}
    const details=document.createElement("details");addText(details,"summary","查看完整冻结请求");addText(details,"pre",request.signing_text);card.appendChild(details);
    for(const decision of ["deny","approve"]){
      const button=addText(card,"button",decision==="deny"?"拒绝":p.kind==="reference"?"允许本任务引用":"仅允许这一次");button.className=decision==="deny"?"deny":"";
      button.onclick=async()=>{card.querySelectorAll("button").forEach(b=>b.disabled=true);try{
        await api("/decision",{operation_id:p.request_id,decision,signature:await sign("secret-guard/decision/v1:"+decision+":"+request.signing_text)},true);await refresh();
      }catch(e){$("message").textContent=e.message;card.querySelectorAll("button").forEach(b=>b.disabled=false);}};
    }
    $("requests").appendChild(card);
  }
}
action("refresh",refresh);
saved().then(d=>{device=d;showDevice();}).catch(e=>{$("message").textContent=e.message;});
