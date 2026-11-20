"use strict";
// Browser approver. Credentials are stored here, encrypted under a non-extractable key.
// An approved use seals one credential to the paired injector; the relay only forwards the box.
let device, session, registered = null, relayInjectors = null, shown = null, stepsKey = "";
const $ = id => document.getElementById(id);
const bytes = value => new TextEncoder().encode(value);
const b64 = data => btoa(Array.from(new Uint8Array(data), b => String.fromCharCode(b)).join("")).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
const unb64 = text => Uint8Array.from(atob(text.replaceAll("-", "+").replaceAll("_", "/")), c => c.charCodeAt(0));
const hex = data => [...new Uint8Array(data)].map(b => b.toString(16).padStart(2, "0")).join("");
const publicJwk = jwk => ({kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y});
const REASONS = {secret_unavailable: "本设备没有这个密码", injector_not_paired: "审批端没有配对这台注入工具", policy_denied: "该密码不允许用于这个仓库",
  request_changed: "请求与固定操作不符", request_invalid: "请求格式无效", signature_invalid: "请求签名无效，可能在传输中被改动"};
const REF_TYPES = {once: "一次性：批准后只能发起一次使用申请", long: "长期：批准后 1 小时内可反复申请使用"};
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

async function api(path, body, auth = false, retry = true) {
  const headers = {"Content-Type": "application/json"};
  if (auth) headers.Authorization = "Bearer " + session;
  const response = await fetch(path, {method: "POST", headers, body: JSON.stringify(body), credentials: "omit", redirect: "error"});
  const data = await response.json();
  if (response.ok) return data;
  // The session lasts 5 minutes; sign in again with the device key instead of asking the user.
  if (auth && retry && data.error === "device_unauthorized") { await login(); return api(path, body, true, false); }
  throw Object.assign(new Error(data.error || "请求失败"), {code: data.error});
}
async function login() {
  session = null;
  try {
    const c = await api("/device/challenge", {device: device.id});
    session = (await api("/device/login", {device: device.id, challenge: c.challenge, signature: await sign(c.message)})).token;
    registered = true;
  } catch (e) {
    if (e.code !== "device_unauthorized") throw e;
    registered = false; relayInjectors = null;
    throw new Error("服务器还没有登记本设备，请先完成设置步骤第 2 步。");
  }
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

function ticks() { try { return JSON.parse(localStorage.getItem("agentsecret-steps")) || {}; } catch (e) { return {}; } }
function command(parent, text) {
  const box = document.createElement("div"); box.className = "cmd"; const pre = addText(box, "pre", text), button = addText(box, "button", "复制");
  button.onclick = async () => {
    try { await navigator.clipboard.writeText(text); button.textContent = "已复制"; }
    catch (e) { const range = document.createRange(); range.selectNodeContents(pre); getSelection().removeAllRanges(); getSelection().addRange(range); button.textContent = "已选中"; }
  };
  parent.appendChild(box);
}
// The remaining setup, in order, with what is still missing. done: true, false, or null when this page cannot tell.
async function steps() {
  const injectors = await all("injectors"), secrets = await all("secrets"), manual = ticks();
  const key = JSON.stringify([device && device.id, Boolean(session), registered, relayInjectors, injectors.map(i => i.id), secrets.length, manual]);
  if (key === stepsKey) return; stepsKey = key;
  const quote = text => "'" + text.replaceAll("'", "'\\''") + "'";
  const file = device ? "cat > approver.json <<'EOF'\n" + $("pairing").textContent + "\nEOF\n" : "";
  const known = relayInjectors && (injectors.length ? injectors.some(i => relayInjectors.includes(i.id)) : relayInjectors.length > 0);
  const list = [
    {title: "生成审批设备", done: Boolean(device), text: "在下面“审批设备”里填用户名，点“生成设备密钥”。"},
    {title: "在服务器上登记本设备，然后连接", done: Boolean(session), text: registered === false ? "服务器还没有登记本设备。在运行 relay 的机器上执行下面的命令，再点“连接服务器”。" : "在运行 relay 的机器上执行（会把本设备的公钥保存为 approver.json 并登记），再点下面的“连接服务器”。",
      commands: device ? [file + "agentsecret relay device-register --pairing-file approver.json"] : []},
    {title: "初始化注入工具，并在服务器上登记", done: session ? Boolean(known) : null, unknown: "连接服务器后可检测", text: "前两条在 agent 所在的机器上执行，最后一条在运行 relay 的机器上执行（两台机器不同时先把 injector.json 拷过去）。",
      commands: device ? ["agentsecret injector init --user " + quote(device.user) + " --relay " + location.origin + "\nagentsecret injector pairing --out injector.json", "agentsecret relay device-register --pairing-file injector.json"] : []},
    {title: "在本页配对注入工具", done: injectors.length > 0, text: "把 injector.json 的全部内容粘贴到下面“注入工具 › 配对一台注入工具”，点“配对”。", commands: ["cat injector.json"]},
    {title: "让注入工具认识本设备", manual: "pair", text: "在 agent 所在的机器上执行。没有这一步，注入工具不会接受本设备的批准。需要第 2 步保存的 approver.json。",
      commands: device ? [file + "agentsecret injector pair-approver --pairing-file approver.json"] : []},
    {title: "录入密码", done: secrets.length > 0, text: "在下面“密码”里添加至少一条，并写明允许用于哪些仓库。"},
    {title: "启动注入工具，创建任务，接上 agent", manual: "serve", text: "在 agent 所在的机器上执行。之后的请求会出现在“待审批”里。",
      commands: ["agentsecret injector serve", "agentsecret injector task-create --project <项目名> --token-file /absolute/path/run-01.token\nsecret-guard mcp --token-file /absolute/path/run-01.token"]},
  ];
  $("steps").replaceChildren();
  let missing = false;
  for (const step of list) {
    if (step.manual) step.done = manual[step.manual] ? true : null;
    const li = document.createElement("li"), next = !missing && step.done !== true;
    if (next) missing = true;
    li.className = step.done === true ? "done" : next ? "next" : "";
    addText(li, "strong", step.title);
    addText(li, "span", step.done === true ? "✓ 已完成" : next ? "← 当前缺这一步" : step.done === null ? (step.unknown || "需手动确认") : "未完成").className = "state";
    if (step.done !== true || step.manual) {
      addText(li, "div", step.text);
      for (const text of step.commands || []) command(li, text);
    }
    if (step.manual) {
      const label = addText(li, "label", " 我已执行（本页无法自动检测这一步）"), box = document.createElement("input");
      box.type = "checkbox"; box.checked = Boolean(manual[step.manual]); label.prepend(box);
      box.onchange = () => { try { localStorage.setItem("agentsecret-steps", JSON.stringify({...ticks(), [step.manual]: box.checked})); } catch (e) {} steps(); };
    }
    $("steps").appendChild(li);
  }
}
function addText(parent, tag, text) { const el = document.createElement(tag); el.textContent = text; parent.appendChild(el); return el; }
async function show() {
  $("device-state").textContent = device ? `设备编号：${device.id}（用户 ${device.user}）` : "尚未生成设备";
  $("pairing").textContent = device ? JSON.stringify({kind: "approver", device: device.id, user: device.user, jwk: device.jwk}, null, 2) : "";
  $("create").disabled = Boolean(device); $("user").disabled = Boolean(device);
  $("injectors").replaceChildren(); $("secrets").replaceChildren();
  for (const i of await all("injectors")) addText($("injectors"), "li", i.id);
  for (const s of await all("secrets")) addText($("secrets"), "li", `${s.alias} · 允许 ${s.repos.join("、")}`);
  await steps();
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
  await login(); await refresh(true);
  $("message").textContent = "已连接。本页开着时会自动获取新的请求。";
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
  // The password is the user's to manage: stored exactly as typed, never inspected. Only the alias and the repositories have a format.
  const fail = (field, text) => { $(field).focus(); throw new Error(text); };
  if (!/^[A-Za-z0-9_.-]{1,64}$/.test(alias)) fail("alias", "别名无效：用 1 到 64 个字母、数字、点、下划线或连字符。别名用来区分每一条密码。");
  if (!value) fail("value", "请输入密码。密码内容由你管理，本设备不检查格式，只负责保存、密封并转发。");
  if (bytes(value).length > 65536) fail("value", "密码超过 64 KB，超出一次密封转发的上限。");
  if (!repos.length) fail("repos", "至少要填一个允许使用的仓库，格式为 owner/name。");
  const bad = repos.filter(r => !REPO.test(r));
  if (bad.length) fail("repos", `仓库格式无效：${bad.join("、")}。应为 owner/name。`);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({name: "AES-GCM", iv, additionalData: bytes(alias)}, device.vault, bytes(value));
  await put("secrets", alias, {alias, iv, ct, repos});
  $("alias").value = $("value").value = $("repos").value = "";
});

// Rules come before the prompt. Returns a problem code, or "" when approval may be offered.
async function check(entry, p) {
  const injector = await get("injectors", p.injector);
  if (!injector) return "injector_not_paired";
  const key = await crypto.subtle.importKey("jwk", injector.jwk, {name: "ECDSA", namedCurve: "P-256"}, false, ["verify"]);
  if (!await crypto.subtle.verify({name: "ECDSA", hash: "SHA-256"}, key, unb64(entry.signature), bytes("secret-guard/request/v1:" + entry.request_text))) return "signature_invalid";
  if (p.domain !== "secret-guard/approval/v2" || p.principal !== device.user) return "request_invalid";
  if (!(p.expires_at * 1000 > Date.now())) return "expired";
  const secret = await get("secrets", p.secret_id);
  if (!secret) return "secret_unavailable";
  const d = p.details;
  if (p.kind === "reference") return d && REF_TYPES[d.type] && d.scope === "task_reference_only" && d.ttl_seconds === 3600 && Object.keys(d).length === 3 ? "" : "request_invalid";
  if (p.kind !== "use" || !d || !d.args || !REPO.test(d.args.repo) || !Number.isInteger(d.args.limit)) return "request_invalid";
  const fixed = d.method === "GET" && d.scheme === "https" && d.host === "api.github.com" && d.port === 443
    && d.path === `/repos/${d.args.repo}/actions/runs` && d.query === `per_page=${d.args.limit}&page=1`;
  if (!fixed) return "request_changed";
  if (!secret.repos.includes(d.args.repo)) return "policy_denied";
  return "";
}
// A reason marks an automatic rejection; it is signed, and the injector shows it to the caller.
async function decide(entry, p, decision, reason = "") {
  const body = {request_id: p.request_id, decision};
  if (reason) body.reason = reason;
  if (decision === "approve" && p.kind === "use") {
    const secret = await get("secrets", p.secret_id), injector = await get("injectors", p.injector);
    const value = await crypto.subtle.decrypt({name: "AES-GCM", iv: secret.iv, additionalData: bytes(secret.alias)}, device.vault, secret.ct);
    // Sealed to the key recorded at pairing, never to a key the relay supplies.
    body.sealed = await seal(injector.enc_jwk, value, await sealAad(entry.request_text));
  }
  body.signature = await sign("secret-guard/decision/v3:" + decision + ":" + reason + ":" + device.id + ":" + entry.request_text);
  await api("/approver/decision", body, true);
}
async function refresh(force = false) {
  if (!session) throw new Error("请先连接服务器。");
  const data = await api("/approver/pending", {}, true), items = [];
  relayInjectors = data.injectors || [];
  for (const entry of data.requests) {
    let p, problem;
    // Everything shown is parsed from the exact text that gets signed.
    try { p = JSON.parse(entry.request_text); problem = await check(entry, p); } catch (e) { continue; }
    if (problem === "expired") continue;
    if (problem) {
      // Rules come before the prompt: what this device can never approve is rejected now, with the reason.
      try {
        await decide(entry, p, "deny", problem);
        addText($("rejected"), "li", `${new Date().toLocaleTimeString()} · 密码 ${p.secret_id} · 项目 ${p.project} · ${REASONS[problem]}`);
        while ($("rejected").children.length > 20) $("rejected").firstChild.remove();
      } catch (e) {}
      continue;
    }
    items.push([entry, p]);
  }
  await steps();
  const key = items.map(([, p]) => p.request_id).join();
  if (!force && key === shown) return;
  shown = key; $("requests").replaceChildren();
  if (!items.length) addText($("requests"), "p", "暂无待审批请求。");
  for (const [entry, p] of items) {
    const card = document.createElement("article"); card.className = "card";
    addText(card, "h2", p.kind === "reference" ? "允许任务引用密码？" : "允许这一次具体使用？");
    const list = document.createElement("dl"); card.appendChild(list);
    const d = p.details;
    const operation = p.kind === "reference" ? `引用（${REF_TYPES[d.type]}）；每次使用仍需单独批准` : `${d.method} ${d.scheme}://${d.host}:${d.port}${d.path}?${d.query}`;
    for (const [label, value] of [["项目", p.project], ["密码", p.secret_id], ["任务", p.task], ["注入工具", p.injector], ["操作", operation], ["请求有效期", new Date(p.expires_at * 1000).toLocaleString()]]) { addText(list, "dt", label); addText(list, "dd", String(value)); }
    const details = document.createElement("details"); addText(details, "summary", "查看完整冻结请求"); addText(details, "pre", entry.request_text); card.appendChild(details);
    for (const decision of ["deny", "approve"]) {
      const button = addText(card, "button", decision === "deny" ? "拒绝" : p.kind === "reference" ? (d.type === "once" ? "允许引用一次" : "允许引用 1 小时") : "仅允许这一次"); button.className = decision === "deny" ? "deny" : "";
      button.onclick = async () => { card.querySelectorAll("button").forEach(b => b.disabled = true); try { await decide(entry, p, decision); await refresh(true); } catch (e) { $("message").textContent = e.message; card.querySelectorAll("button").forEach(b => b.disabled = false); } };
    }
    $("requests").appendChild(card);
  }
}
action("refresh", () => refresh(true));
// While the page is open and connected, new requests arrive without pressing anything.
let polling = false;
setInterval(async () => { if (!session || polling) return; polling = true; try { await refresh(); } catch (e) { $("message").textContent = e.message; } finally { polling = false; } }, 2000);
get("device", "device").then(async d => { device = d; await show(); if (device) { try { await login(); await refresh(true); } catch (e) {} await show(); } }).catch(e => { $("message").textContent = e.message; });
