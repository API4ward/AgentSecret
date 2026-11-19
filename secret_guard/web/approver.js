"use strict";
// Browser approver. Credentials are stored here, encrypted under a non-extractable key.
// An approved use seals one credential to the paired injector; the relay only forwards the box.
let device, session;
const $ = id => document.getElementById(id);
const bytes = value => new TextEncoder().encode(value);
const b64 = data => btoa(String.fromCharCode(...new Uint8Array(data))).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
const unb64 = text => Uint8Array.from(atob(text.replaceAll("-", "+").replaceAll("_", "/")), c => c.charCodeAt(0));
const hex = data => [...new Uint8Array(data)].map(b => b.toString(16).padStart(2, "0")).join("");
const publicJwk = jwk => ({kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y});
const REPO = /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}$/;

const store = new Promise((resolve, reject) => {
  const r = indexedDB.open("agentsecret-approver", 1);
  r.onupgradeneeded = () => { for (const name of ["device", "secrets", "injectors"]) r.result.createObjectStore(name); };
  r.onsuccess = () => resolve(r.result); r.onerror = () => reject(new Error("设备存储不可用"));
});
async function db(name, mode, fn) {
  const tx = (await store).transaction(name, mode);
  return new Promise((resolve, reject) => {
    const r = fn(tx.objectStore(name));
    tx.oncomplete = () => resolve(r && r.result); tx.onerror = () => reject(new Error("设备存储失败"));
  });
}
const get = (name, key) => db(name, "readonly", s => s.get(key));
const put = (name, key, value) => db(name, "readwrite", s => s.put(value, key));
const all = name => db(name, "readonly", s => s.getAll());

async function api(path, body, auth = false) {
  const headers = {"Content-Type": "application/json"};
  if (auth) headers.Authorization = "Bearer " + session;
  const response = await fetch(path, {method: "POST", headers, body: JSON.stringify(body), credentials: "omit", redirect: "error"});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "请求失败");
  return data;
}
async function sign(text) { return b64(await crypto.subtle.sign({name: "ECDSA", hash: "SHA-256"}, device.signing, bytes(text))); }

// ECIES over P-256, identical to secret_guard/seal.py.
async function seal(recipientJwk, plaintext, aad) {
  const recipient = await crypto.subtle.importKey("jwk", publicJwk(recipientJwk), {name: "ECDH", namedCurve: "P-256"}, true, []);
  const ephemeral = await crypto.subtle.generateKey({name: "ECDH", namedCurve: "P-256"}, false, ["deriveBits"]);
  const epk = new Uint8Array(await crypto.subtle.exportKey("raw", ephemeral.publicKey));
  const recipientRaw = new Uint8Array(await crypto.subtle.exportKey("raw", recipient));
  const shared = await crypto.subtle.deriveBits({name: "ECDH", public: recipient}, ephemeral.privateKey, 256);
  const salt = new Uint8Array(130); salt.set(epk); salt.set(recipientRaw, 65);
  const base = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey({name: "HKDF", hash: "SHA-256", salt, info: bytes("secret-guard/seal/v1")}, base, {name: "AES-GCM", length: 256}, false, ["encrypt"]);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  return {epk: b64(epk), nonce: b64(nonce), ct: b64(await crypto.subtle.encrypt({name: "AES-GCM", iv: nonce, additionalData: aad}, key, plaintext))};
}
async function sealAad(requestText) { return bytes("secret-guard/seal/v1:" + hex(await crypto.subtle.digest("SHA-256", bytes(requestText)))); }

function addText(parent, tag, text) { const el = document.createElement(tag); el.textContent = text; parent.appendChild(el); return el; }
async function show() {
  $("device-state").textContent = device ? `设备编号：${device.id}（用户 ${device.user}）` : "尚未生成设备";
  $("pairing").textContent = device ? JSON.stringify({kind: "approver", device: device.id, user: device.user, jwk: device.jwk}, null, 2) : "";
  $("create").disabled = Boolean(device); $("user").disabled = Boolean(device);
  $("injectors").replaceChildren(); $("secrets").replaceChildren();
  for (const i of await all("injectors")) addText($("injectors"), "li", i.id);
  for (const s of await all("secrets")) addText($("secrets"), "li", `${s.alias} · 允许 ${s.repos.join("、")}`);
}
function action(id, fn) { $(id).onclick = async () => { $("message").textContent = ""; $(id).disabled = true; try { await fn(); } catch (e) { $("message").textContent = e.message; } finally { $(id).disabled = false; await show(); } }; }

action("create", async () => {
  if (device) throw new Error("设备已存在。");
  const user = $("user").value.trim();
  if (!user) throw new Error("请填写用户名。");
  const keys = await crypto.subtle.generateKey({name: "ECDSA", namedCurve: "P-256"}, false, ["sign", "verify"]);
  const vault = await crypto.subtle.generateKey({name: "AES-GCM", length: 256}, false, ["encrypt", "decrypt"]);
  device = {id: "approver_" + crypto.randomUUID(), user, signing: keys.privateKey, vault, jwk: publicJwk(await crypto.subtle.exportKey("jwk", keys.publicKey))};
  await put("device", "device", device);
});
action("connect", async () => {
  if (!device) throw new Error("请先生成设备，并在服务器和注入工具上登记公钥。");
  const c = await api("/device/challenge", {device: device.id});
  session = (await api("/device/login", {device: device.id, challenge: c.challenge, signature: await sign(c.message)})).token;
  $("message").textContent = "已连接，5 分钟后需重新连接。"; await refresh();
});
action("pair", async () => {
  if (!device) throw new Error("请先生成设备。");
  const d = JSON.parse($("injector-pairing").value);
  if (d.kind !== "injector" || d.user !== device.user || typeof d.device !== "string" || !d.jwk || !d.enc_jwk) throw new Error("配对信息无效，或用户不一致。");
  if (await get("injectors", d.device)) throw new Error("该注入工具已配对。");
  await crypto.subtle.importKey("jwk", publicJwk(d.jwk), {name: "ECDSA", namedCurve: "P-256"}, true, ["verify"]);
  await crypto.subtle.importKey("jwk", publicJwk(d.enc_jwk), {name: "ECDH", namedCurve: "P-256"}, true, []);
  await put("injectors", d.device, {id: d.device, jwk: publicJwk(d.jwk), enc_jwk: publicJwk(d.enc_jwk)});
  $("injector-pairing").value = "";
});
action("add", async () => {
  if (!device) throw new Error("请先生成设备。");
  const alias = $("alias").value.trim(), value = $("value").value;
  const repos = [...new Set($("repos").value.split(",").map(r => r.trim().toLowerCase()).filter(Boolean))].sort();
  if (!/^[A-Za-z0-9_.-]{1,64}$/.test(alias) || value.length < 8 || value.length > 4096 || !repos.length || !repos.every(r => REPO.test(r))) throw new Error("别名、密码或仓库格式无效。");
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({name: "AES-GCM", iv, additionalData: bytes(alias)}, device.vault, bytes(value));
  await put("secrets", alias, {alias, iv, ct, repos});
  $("alias").value = $("value").value = $("repos").value = "";
});

// Rules come before the prompt. Returns a problem code, or "" when approval may be offered.
async function check(entry, p) {
  const injector = await get("injectors", p.injector);
  if (!injector) return "注入工具未配对";
  const key = await crypto.subtle.importKey("jwk", injector.jwk, {name: "ECDSA", namedCurve: "P-256"}, false, ["verify"]);
  if (!await crypto.subtle.verify({name: "ECDSA", hash: "SHA-256"}, key, unb64(entry.signature), bytes("secret-guard/request/v1:" + entry.request_text))) return "注入工具签名无效";
  if (p.domain !== "secret-guard/approval/v2" || p.principal !== device.user) return "请求无效";
  if (!(p.expires_at * 1000 > Date.now())) return "请求已过期";
  const secret = await get("secrets", p.secret_id);
  if (!secret) return "本设备没有这个密码";
  if (p.kind === "reference") return "";
  const d = p.details;
  if (p.kind !== "use" || !d || !d.args || !REPO.test(d.args.repo) || !Number.isInteger(d.args.limit)) return "请求无效";
  const fixed = d.method === "GET" && d.scheme === "https" && d.host === "api.github.com" && d.port === 443
    && d.path === `/repos/${d.args.repo}/actions/runs` && d.query === `per_page=${d.args.limit}&page=1`;
  if (!fixed) return "请求与固定操作不符";
  if (!secret.repos.includes(d.args.repo)) return "该密码不允许用于这个仓库";
  return "";
}
async function decide(entry, p, decision) {
  const body = {request_id: p.request_id, decision};
  if (decision === "approve" && p.kind === "use") {
    const secret = await get("secrets", p.secret_id), injector = await get("injectors", p.injector);
    const value = await crypto.subtle.decrypt({name: "AES-GCM", iv: secret.iv, additionalData: bytes(secret.alias)}, device.vault, secret.ct);
    // Sealed to the key recorded at pairing, never to a key the relay supplies.
    body.sealed = await seal(injector.enc_jwk, value, await sealAad(entry.request_text));
  }
  body.signature = await sign("secret-guard/decision/v2:" + decision + ":" + device.id + ":" + entry.request_text);
  await api("/approver/decision", body, true);
}
async function refresh() {
  if (!session) throw new Error("请先连接服务器。");
  const data = await api("/approver/pending", {}, true); $("requests").replaceChildren();
  if (!data.requests.length) addText($("requests"), "p", "暂无待审批请求。");
  for (const entry of data.requests) {
    let p, problem;
    // Everything shown is parsed from the exact text that gets signed.
    try { p = JSON.parse(entry.request_text); problem = await check(entry, p); } catch (e) { continue; }
    const card = document.createElement("article"); card.className = "card";
    addText(card, "h2", p.kind === "reference" ? "允许任务引用密码？" : "允许这一次具体使用？");
    const list = document.createElement("dl"); card.appendChild(list);
    const d = p.details || {};
    const operation = p.kind === "reference" ? "允许引用；使用时仍需批准" : `${d.method} ${d.scheme}://${d.host}:${d.port}${d.path}?${d.query}`;
    for (const [label, value] of [["项目", p.project], ["密码", p.secret_id], ["任务", p.task], ["注入工具", p.injector], ["操作", operation], ["有效期", new Date(p.expires_at * 1000).toLocaleString()]]) { addText(list, "dt", label); addText(list, "dd", String(value)); }
    if (problem) addText(card, "p", "不能批准：" + problem).className = "hint";
    const details = document.createElement("details"); addText(details, "summary", "查看完整冻结请求"); addText(details, "pre", entry.request_text); card.appendChild(details);
    for (const decision of problem ? ["deny"] : ["deny", "approve"]) {
      const button = addText(card, "button", decision === "deny" ? "拒绝" : p.kind === "reference" ? "允许本任务引用" : "仅允许这一次"); button.className = decision === "deny" ? "deny" : "";
      button.onclick = async () => { card.querySelectorAll("button").forEach(b => b.disabled = true); try { await decide(entry, p, decision); await refresh(); } catch (e) { $("message").textContent = e.message; card.querySelectorAll("button").forEach(b => b.disabled = false); } };
    }
    $("requests").appendChild(card);
  }
}
action("refresh", refresh);
get("device", "device").then(d => { device = d; return show(); }).catch(e => { $("message").textContent = e.message; });
