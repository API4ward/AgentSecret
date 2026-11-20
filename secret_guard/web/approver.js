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
  request_changed: "请求与固定操作不符", request_invalid: "请求格式无效", rule_unknown: "这条保护规则已不在审批端上", signature_invalid: "请求签名无效，可能在传输中被改动"};
const REF_TYPES = {once: "一次性：批准后只能发起一次使用申请", long: "长期：批准后 1 小时内可反复申请使用"};
const REPO = /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}$/;

const store = new Promise((resolve, reject) => {
  const r = indexedDB.open("agentsecret-approver", 2);
  r.onupgradeneeded = () => { for (const name of ["device", "secrets", "injectors", "rules"]) if (!r.result.objectStoreNames.contains(name)) r.result.createObjectStore(name); };
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
// Small approver-side state (approval modes) lives beside the device key.
const state = async (key, fallback) => (await get("device", key)) ?? fallback;
async function plain(secret, label = "default") {
  const c = label === "default" ? secret : secret.copies[label];
  return new TextDecoder().decode(await crypto.subtle.decrypt({name: "AES-GCM", iv: c.iv, additionalData: bytes(secret.alias + (label === "default" ? "" : "\u0000" + label))}, device.vault, c.ct));
}
// Compiled matchers, identical to secret_guard/matcher.py: length, 16-bit rolling-hash tag, salted PBKDF2 digest.
// The plaintext stays here; the injector receives only what lets it recognise a credential.
const MOD = (1n << 61n) - 1n;
async function compile(alias, value, base) {
  const data = bytes(value);
  if (!data.length) return null;
  let h = 0n; for (const b of data) h = (h * base + BigInt(b)) % MOD;
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", data, "PBKDF2", false, ["deriveBits"]);
  const digest = await crypto.subtle.deriveBits({name: "PBKDF2", hash: "SHA-256", salt, iterations: 50000}, key, 256);
  return {alias, length: data.length, tag: Number(h & 0xFFFFn), salt: b64(salt), digest: b64(digest)};
}
async function publishMatchers() {
  if (!session) return;
  const random = new BigUint64Array(1); crypto.getRandomValues(random);
  const base = random[0] % (MOD - 257n) + 257n, matchers = [];
  for (const secret of await all("secrets")) for (const label of ["default", ...Object.keys(secret.copies || {})]) {
    const m = await compile(secret.alias, await plain(secret, label), base); if (m) matchers.push(m);
  }
  const text = JSON.stringify({approver: device.id, version: Date.now(), base: base.toString(), matchers});
  await api("/approver/rules", {rules_text: text, signature: await sign("secret-guard/rules/v1:" + text)}, true);
}
function mock(value) {
  const pick = pool => pool[crypto.getRandomValues(new Uint32Array(1))[0] % pool.length], low = "abcdefghijklmnopqrstuvwxyz";
  const cut = Math.max(value.slice(0, 8).indexOf("-"), value.slice(0, 8).indexOf("_")) + 1;
  return value.slice(0, cut) + [...value.slice(cut)].map(c => /[0-9]/.test(c) ? pick("0123456789") : /[a-z]/.test(c) ? pick(low) : /[A-Z]/.test(c) ? pick(low.toUpperCase()) : c).join("");
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
  for (const s of await all("secrets")) addText($("secrets"), "li", s.alias + (Object.keys(s.copies || {}).length ? ` · 副本 ${Object.keys(s.copies).join("、")}` : "") + (s.repos.length ? ` · GitHub 仓库 ${s.repos.join("、")}` : ""));
  const until = await state("allUntil", 0), rules = await state("autoRules", []);
  $("all-state").textContent = until > Date.now() ? `全部同意模式开启，到 ${new Date(until).toLocaleTimeString()} 为止。` : "当前逐条询问。";
  $("auto-rules").replaceChildren();
  rules.forEach((rule, index) => {
    const li = addText($("auto-rules"), "li", `类型 ${rule.kind} · 密码 ${rule.secret} · 工具 ${rule.tool} · 目标 ${rule.target}`), button = addText(li, "button", "移除"); button.className = "deny";
    button.onclick = async () => { await put("device", "autoRules", rules.filter((_, i) => i !== index)); await show(); };
  });
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
  await login(); await publishMatchers(); await refresh(true);
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
  const bad = repos.filter(r => !REPO.test(r));
  if (bad.length) fail("repos", `仓库格式无效：${bad.join("、")}。应为 owner/name。`);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({name: "AES-GCM", iv, additionalData: bytes(alias)}, device.vault, bytes(value));
  await put("secrets", alias, {alias, iv, ct, repos, copies: (await get("secrets", alias) || {}).copies || {}});
  $("alias").value = $("value").value = $("repos").value = "";
  await publishMatchers();
});
action("add-copy", async () => {
  // A further copy under the same alias, for example a second API key of the same service.
  const alias = $("copy-alias").value.trim(), label = $("copy-label").value.trim(), value = $("copy-value").value, secret = await get("secrets", alias);
  if (!secret) throw new Error("没有这个别名的密码，请先添加它。");
  if (!/^[A-Za-z0-9_.-]{1,64}$/.test(label) || label === "default") throw new Error("副本名无效：用 1 到 64 个字母、数字、点、下划线或连字符。");
  if (!value) throw new Error("请输入这个副本的密码。");
  const iv = crypto.getRandomValues(new Uint8Array(12));
  secret.copies = {...secret.copies, [label]: {iv, ct: await crypto.subtle.encrypt({name: "AES-GCM", iv, additionalData: bytes(alias + "\u0000" + label)}, device.vault, bytes(value))}};
  await put("secrets", alias, secret);
  $("copy-alias").value = $("copy-label").value = $("copy-value").value = "";
  await publishMatchers();
});
// Approval modes: this page answering for the user. Every answer is still an individually signed decision.
action("all-on", async () => { await put("device", "allUntil", Date.now() + Math.max(1, Number($("all-minutes").value) || 10) * 60000); });
action("all-off", async () => { await put("device", "allUntil", 0); });
action("auto-add", async () => {
  const rule = {kind: $("auto-kind").value, secret: $("auto-secret").value.trim() || "*", tool: $("auto-tool").value.trim() || "*", target: $("auto-target").value.trim() || "*"};
  await put("device", "autoRules", [...await state("autoRules", []), rule]);
});
const glob = (pattern, text) => new RegExp("^" + pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replaceAll("*", ".*").replaceAll("?", ".") + "$").test(text);
const HOOK = {reveal: "工具返回的内容里有密码；批准后以引用代替密码交给 agent", fill: "工具调用里有密码引用；批准后把引用换成密码再执行"};
function facets(p) {
  const d = p.details;
  return HOOK[p.kind] ? {kind: p.kind, names: d.secrets, tool: d.tool, target: d.target} : {kind: p.kind, names: [p.secret_id], tool: p.kind === "use" ? "github" : "", target: (d.args || {}).repo || ""};
}
// Whether a mode answers this request without the user: {why, choices} or null.
async function automatic(p) {
  const f = facets(p);
  if (await state("allUntil", 0) > Date.now()) return {why: "全部同意模式"};
  const grants = await state("grants", []), key = JSON.stringify([f.kind, f.names, p.project]);
  const g = grants.find(g => g.key === key && (g.expires === null || g.expires > Date.now()) && (g.remaining === null || g.remaining > 0));
  if (g) { if (g.remaining !== null) g.remaining -= 1; await put("device", "grants", grants); return {why: "此前选择的多次或限时允许", choices: g.choices}; }
  for (const r of await state("autoRules", [])) if ((r.kind === "*" || r.kind === f.kind) && f.names.every(n => glob(r.secret, n)) && glob(r.tool, f.tool) && glob(r.target, f.target)) return {why: "自动审批规则"};
  return null;
}

// Rules come before the prompt. Returns a problem code, or "" when approval may be offered.
async function check(entry, p) {
  const injector = await get("injectors", p.injector);
  if (!injector) return "injector_not_paired";
  const key = await crypto.subtle.importKey("jwk", injector.jwk, {name: "ECDSA", namedCurve: "P-256"}, false, ["verify"]);
  if (!await crypto.subtle.verify({name: "ECDSA", hash: "SHA-256"}, key, unb64(entry.signature), bytes("secret-guard/request/v1:" + entry.request_text))) return "signature_invalid";
  if (p.domain !== "secret-guard/approval/v2" || p.principal !== device.user) return "request_invalid";
  if (!(p.expires_at * 1000 > Date.now())) return "expired";
  const d = p.details;
  if (HOOK[p.kind]) {
    // The hook's requests name credentials by alias; every one must be stored here.
    const ok = d && Object.keys(d).length === 6 && d.scope === p.kind && ["tool", "target", "summary", "call"].every(k => typeof d[k] === "string")
      && Array.isArray(d.secrets) && d.secrets.length && d.secrets.every(a => typeof a === "string");
    if (!ok) return "request_invalid";
    for (const alias of d.secrets) if (!await get("secrets", alias)) return "secret_unavailable";
    return "";
  }
  const secret = await get("secrets", p.secret_id);
  if (!secret) return "secret_unavailable";
  if (p.kind === "reference") return d && REF_TYPES[d.type] && d.scope === "task_reference_only" && d.ttl_seconds === 3600 && Object.keys(d).length === 3 ? "" : "request_invalid";
  if (p.kind !== "use" || !d || !d.args || !REPO.test(d.args.repo) || !Number.isInteger(d.args.limit)) return "request_invalid";
  const fixed = d.method === "GET" && d.scheme === "https" && d.host === "api.github.com" && d.port === 443
    && d.path === `/repos/${d.args.repo}/actions/runs` && d.query === `per_page=${d.args.limit}&page=1`;
  if (!fixed) return "request_changed";
  if (!secret.repos.includes(d.args.repo)) return "policy_denied";
  return "";
}
// A reason marks an automatic rejection; it is signed, and the injector shows it to the caller.
// choices: {alias: "default" | "copy:<label>" | "mock" | "manual:<text>"} is what gets returned.
// grant: {times} or {seconds} answers the same kind of request again without asking.
async function resolve(alias, choice = "default") {
  const secret = await get("secrets", alias);
  if (choice === "mock") return mock(await plain(secret));
  if (choice.startsWith("manual:") && choice.length > 7) return choice.slice(7);
  if (choice.startsWith("copy:") && !(secret.copies || {})[choice.slice(5)]) throw new Error("这个别名下没有这个副本。");
  return plain(secret, choice.startsWith("copy:") ? choice.slice(5) : "default");
}
async function decide(entry, p, decision, reason = "", choices = {}, grant = null) {
  const body = {request_id: p.request_id, decision}, f = facets(p);
  if (reason) body.reason = reason;
  if (decision === "approve" && (p.kind === "use" || p.kind === "fill")) {
    const injector = await get("injectors", p.injector), picked = {};
    for (const alias of f.names) picked[alias] = await resolve(alias, choices[alias]);
    // Sealed to the key recorded at pairing, never to a key the relay supplies.
    body.sealed = await seal(injector.enc_jwk, bytes(p.kind === "use" ? picked[f.names[0]] : JSON.stringify(picked)), await sealAad(entry.request_text));
  }
  body.signature = await sign("secret-guard/decision/v3:" + decision + ":" + reason + ":" + device.id + ":" + entry.request_text);
  await api("/approver/decision", body, true);
  if (decision === "approve" && grant) await put("device", "grants", [...await state("grants", []), {key: JSON.stringify([f.kind, f.names, p.project]),
    remaining: grant.times ? grant.times - 1 : null, expires: grant.seconds ? Date.now() + grant.seconds * 1000 : null, choices}]);
}
function note(id, p, text) {
  addText($(id), "li", `${new Date().toLocaleTimeString()} · 密码 ${facets(p).names.join("、")} · 项目 ${p.project} · ${text}`);
  while ($(id).children.length > 20) $(id).firstChild.remove();
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
      try { await decide(entry, p, "deny", problem); note("rejected", p, REASONS[problem]); } catch (e) {}
      continue;
    }
    const auto = await automatic(p);
    if (auto) { try { await decide(entry, p, "approve", "", auto.choices || {}); note("automatic", p, auto.why); continue; } catch (e) {} }
    items.push([entry, p]);
  }
  await steps();
  const key = items.map(([, p]) => p.request_id).join();
  if (!force && key === shown) return;
  shown = key; $("requests").replaceChildren();
  if (!items.length) addText($("requests"), "p", "暂无待审批请求。");
  for (const [entry, p] of items) {
    const card = document.createElement("article"); card.className = "card";
    const d = p.details, f = facets(p);
    addText(card, "h2", {reference: "允许任务引用密码？", use: "允许这一次具体使用？", reveal: "agent 读到的内容里有密码，允许以引用形式交给它？", fill: "agent 要把密码填进这次调用，允许吗？"}[p.kind]);
    const list = document.createElement("dl"); card.appendChild(list);
    const operation = p.kind === "reference" ? `引用（${REF_TYPES[d.type]}）；每次使用仍需单独批准` : HOOK[p.kind] ? `${HOOK[p.kind]}。工具 ${d.tool}${d.target ? "，目标 " + d.target : ""}：${d.summary}` : `${d.method} ${d.scheme}://${d.host}:${d.port}${d.path}?${d.query}`;
    for (const [label, value] of [["项目", p.project], ["密码", f.names.join("、")], ["任务", p.task], ["注入工具", p.injector], ["操作", operation], ["请求有效期", new Date(p.expires_at * 1000).toLocaleString()]]) { addText(list, "dt", label); addText(list, "dd", String(value)); }
    // What is returned can be changed: another copy with the same name, a mock, or typed text.
    const pickers = {};
    if (p.kind === "use" || p.kind === "fill") for (const alias of f.names) {
      const row = addText(card, "label", `返回给 ${alias} 的值 `), select = document.createElement("select"), manual = document.createElement("input");
      const options = [["default", "保存的密码"], ...Object.keys((await get("secrets", alias)).copies || {}).map(l => ["copy:" + l, "副本 " + l]), ["mock", "mock：形状相同的假值，不告诉它真密码"], ["manual", "手动输入"]];
      for (const [value, text] of options) { const o = addText(select, "option", text); o.value = value; }
      manual.type = "password"; manual.hidden = true; manual.placeholder = "手动输入的值"; manual.autocomplete = "off";
      select.onchange = () => { manual.hidden = select.value !== "manual"; };
      row.append(select, manual); pickers[alias] = () => select.value === "manual" ? "manual:" + manual.value : select.value;
    }
    const details = document.createElement("details"); addText(details, "summary", "查看完整冻结请求"); addText(details, "pre", entry.request_text); card.appendChild(details);
    const run = async (decision, grant = null) => {
      card.querySelectorAll("button").forEach(b => b.disabled = true);
      try {
        const choices = Object.fromEntries(Object.entries(pickers).map(([alias, pick]) => [alias, pick()]));
        if (decision === "approve" && Object.values(choices).includes("manual:")) throw new Error("请填写手动输入的值。");
        await decide(entry, p, decision, "", choices, grant); await refresh(true);
      } catch (e) { $("message").textContent = e.message; card.querySelectorAll("button").forEach(b => b.disabled = false); }
    };
    addText(card, "button", "拒绝").className = "deny"; card.lastChild.onclick = () => run("deny");
    addText(card, "button", "允许（1 次）").onclick = () => run("approve");
    // 其他: allow the same kind of request again, n times or for a while.
    const more = document.createElement("select");
    for (const [value, text] of [["", "其他…"], ["t3", "允许 3 次"], ["t10", "允许 10 次"], ["s180", "允许 3 分钟"], ["s600", "允许 10 分钟"], ["s3600", "允许 1 小时"]]) { const o = addText(more, "option", text); o.value = value; }
    more.onchange = () => { if (more.value) run("approve", more.value[0] === "t" ? {times: Number(more.value.slice(1))} : {seconds: Number(more.value.slice(1))}); };
    card.appendChild(more);
    $("requests").appendChild(card);
  }
}
action("refresh", () => refresh(true));
// While the page is open and connected, new requests arrive without pressing anything.
let polling = false;
setInterval(async () => { if (!session || polling) return; polling = true; try { await refresh(); } catch (e) { $("message").textContent = e.message; } finally { polling = false; } }, 2000);
get("device", "device").then(async d => { device = d; await show(); if (device) { try { await login(); await publishMatchers(); await refresh(true); } catch (e) {} await show(); } }).catch(e => { $("message").textContent = e.message; });
