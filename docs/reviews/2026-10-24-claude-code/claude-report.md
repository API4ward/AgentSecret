# Secret Guard 独立验证:判定与报告

**判定:** 在兼容版 MVP 承诺的范围内,我没有找到能绕过两阶段授权、重放、跨任务、设备撤销、策略或原子消费的漏洞。我发现 1 个中低级可用性问题、1 个低级的声明与实现不符问题,以及若干低级功能缺陷和测试缺口。这不是安全认证。真实 Codex、真实 GitHub 网络、手机跨设备访问和 OS 隔离都没有验证。

**测试结果:** 我原样执行了唯一被允许的命令 `/Users/gentle/Documents/ChatGPT/AgentSecurity/.venv/bin/python -m unittest discover -v`,结果 `Ran 26 tests ... OK`,26 个全部通过,0 失败、0 错误、0 跳过。

**未执行的实验:** 因为运行器限制,我没有执行任何额外实验。下面的复现脚本都**未执行**,其中的结论是读源码和推理得出的,需要父审查者运行确认。

---

# 中文报告

## 1. 范围与方法
- 逐行阅读了 `broker.py`、`adapter.py`、`server.py`、`mcp.py`、`cli.py`、`crypto.py`、`web/app.js`、`web/index.html`、`tests/test_guard.py` 和 docs。
- 没有编辑实现,没有联网,没有读取目录外文件、凭据或环境变量。
- 文档只作为"声明",没有当作证据。

## 2. 已核实、未发现漏洞的边界(附代码依据)

| 项目 | 结论 | 依据 |
|---|---|---|
| 阶段 1 绑定 | 签名 payload 含 principal、task、agent、secret、version、policy_version、preview、nonce、expiry、device | `broker.py:167-175`、`282-284` |
| 阶段 2 绑定 | 执行时重新验证存储的签名,并比对 payload。通过 `freeze()` 重建冻结请求,覆盖 adapter 摘要、路径、查询、host 和参数 | `broker.py:305-318`、`adapter.py:33-43` |
| 过期 | 在 `decide`(经 `safe`)和 `execute` 中检查 `expires_at` | `broker.py:232`、`310` |
| 重放 | `approvals.request_id` 是主键。消息带 `decision/v1:{approve\|deny}:` 前缀,payload 含 request_id 和 nonce,所以 deny 签名不能当 approve 用 | `broker.py:31`、`284`、`287` |
| 跨任务 | `refs`、`requests`、`status` 都按 `task` 过滤 | `broker.py:200`、`207`、`220`、`250` |
| 设备撤销 | 撤销设备会停用其 refs 并删除 sessions。`session()`、`valid_ref` 和 `execute` 都复查设备是否有效 | `broker.py:149-153`、`210`、`305`、`375-378` |
| 策略 | 在 `workflow` 和 `execute` 两处都检查 user、project、repo | `broker.py:225`、`317` |
| 原子消费 | 校验与 `approved→executing` 在同一个 `BEGIN IMMEDIATE` 事务内,联网在事务之后。网络失败一律记为 `unknown`,不重试。`recover` 把崩溃留下的 `executing` 改为 `unknown` | `broker.py:297-344`、`353-357` |
| 结果泄漏 | 只透传 `id`、`status`、`conclusion`。原始响应和结构化结果都过 `check_output`。异常被吞掉,日志被禁用,HTTP 只返回固定错误码 | `adapter.py:88-100`、`broker.py:335-337`、`server.py:20-21` |
| SSRF、TLS、重定向(adapter) | 目标写死为 `api.github.com:443`。DNS 只解析一次,任何非 global 地址都拒绝,并连接解析出的那个 IP。使用默认 CA 与主机名校验。http.client 不使用代理。非 200 一律拒绝,不跟随重定向。响应上限 1 MiB | `adapter.py:46-85` |
| HTTP 隔离 | agent 与 approval 监听端口分离,路由和 body 键集合严格匹配。task token 与 session token 存在不同的表里。Host 和 Origin 校验有效。没有 OPTIONS 处理,浏览器 JSON 跨域会在预检阶段失败 | `server.py:35-42`、`73-93` |
| Web UI | 全程用 `textContent`,CSP 严格。私钥不可导出。签名的是服务端给出的 `signing_text` | `app.js:36`、`46`、`57` |

## 3. 发现(仅列有依据的)

### F1 — 中低(可用性,有源码依据,未执行):监听器无超时,TLS 握手在 accept 线程内完成
- **位置:** `server.py:20-33` 的 Handler 没有设置 `timeout`。`server.py:111` 用 `wrap_socket` 包裹监听 socket,握手在 `accept()` 里进行,而 `serve_forever` 是串行 accept 的。
- **推理:** 对 TLS 监听器(远程/手机模式)建立一个 TCP 连接后不发送 ClientHello,就能让该监听线程在握手上无限阻塞,之后所有人都无法连接。这个攻击者只需能连到端口,不需要认证。
- **对明文 HTTP 的影响:** `rfile.read(length)` 在客户端少发字节时会永远阻塞。ThreadingHTTPServer 每个连接一个线程,没有上限。这是资源耗尽式的拒绝服务,影响较小。
- **预期与观察:** 预期是慢速或半开连接不能阻塞审批服务。观察到的是没有任何超时。
- **影响范围:** 只影响可用性,不影响机密性或授权。executor 线程独立,已批准的请求仍会执行。
- **建议:** 设置 `Handler.timeout`;TLS 用 `do_handshake_on_connect=False`,在处理线程中带超时完成握手;限制并发连接数。
- **复现(未执行):**
```python
# 先启动 TLS 监听器,再运行:
import socket, time
s = socket.create_connection(("127.0.0.1", PORT)); time.sleep(60)  # 不发任何数据
# 另一个线程再 urlopen(https://...) ,预期会超时
```

### F2 — 低(声明与实现不符,基于对 stdlib 行为的推理,未执行):MCP bridge 的"拒绝重定向"可能无效
- **位置:** `mcp.py:26-33`。
- **推理:** `build_opener(...)` 已经装入默认的 `HTTPRedirectHandler`。之后用 `add_handler` 追加 `NoRedirect` 时,两者的 `handler_order` 相同,`bisect.insort` 把新 handler 排在后面。我推理 `http_error_30x` 会先由默认 handler 处理,并会跟随重定向。默认 handler 复制重定向请求的头时会保留 `Authorization`,所以 bearer task token 会被转发到重定向目标。
- **实际影响:** 低。broker URL 由操作者配置,而能让配置的 broker 返回重定向的一方本来就能直接拿到这个 token。这主要是"注释和文档声称做了"与实际行为不符。
- **建议:** 构造 opener 时传入 `NoRedirect()` 实例并替换默认 handler,而不是事后 `add_handler`。要加测试。
- **复现(未执行):**
```python
# 起两个本地 HTTP server:A 返回 307 Location: http://127.0.0.1:B/reference;B 记录收到的 Authorization 头。
# 调用 mcp.call("http://127.0.0.1:A", "TOKEN", "guard.request_reference", {"alias": "x"})
# 预期:抛错且 B 未收到请求;如果推理成立,B 会收到 "Bearer TOKEN"。
```

### F3 — 低(设计缺口):阶段 2 的签名没有绑定引用 id
- **位置:** `broker.py:167-175` 的 payload 里没有 `ref`。`ref` 只存在于未签名的 `requests.ref` 列(`191-192`),`execute` 用的是 `row["ref"]`(`312`)。
- **推理:** 阶段 2 签名不覆盖"用的是哪一个阶段 1 授权"。在 broker 数据库可信的前提下无法被外部利用,但与"阶段 2 完整绑定阶段 1"的表述并不严格一致。
- **相关功能表现:** 若旧 ref 被撤销后又批准了新 ref,旧 use 请求会因 `reference_invalid` 失败,即使存在有效的新 ref。
- **建议:** 把 `ref` id 与 ref 的批准设备放进 payload。

### F4 — 低(功能与运维)
1. `revoke` 对不存在的 identity 也成功,并打印"Revoked"(`broker.py:365-384`、`cli.py:76-78`)。拼错 id 会让操作者误以为已撤销。建议检查 `rowcount`。
2. `add_secret` 不校验字符集(`broker.py:74`),而 `fetch` 拒绝 ASCII 33 到 126 以外的字符(`adapter.py:67`)。含空白或换行的凭据能入库,但每次执行都会静默变成 `unknown`。
3. 过期的 use 请求在 `execute` 里被标记为 `revoked` 而不是 `expired`(`broker.py:310-311`、`322-323`),审计和状态语义不精确。
4. `check_output` 对原始响应做子串匹配(`broker.py:346-351`)。如果短凭据(8 位以上)碰巧出现在 GitHub 响应里的 workflow 名称中,调用已经发生,结果却变成 `unknown`(误报,方向安全)。
5. 并发上限 `pending>=20` 把永远停留在 `approved` 的 reference 请求也计入(`broker.py:187`)。影响仅限同一任务自身。
6. 错误码区分了 `secret_unavailable` 和 `policy_denied`(`broker.py:156-158`、`163-164`),已认证的 agent 可以枚举 alias 是否存在(信息泄漏很小)。
7. 无认证的 `/device/challenge` 可对已知 device id 占满 5 个未消费 challenge 名额,阻止合法登录 60 秒(`broker.py:126-128`)。device id 带 UUID,可利用性低。
8. `expected_host` 等于 `host:port`(`server.py:106`)。绑定 `0.0.0.0` 后用域名访问,或使用 443 端口(Host 头不带端口)时,会被 `host_denied`。远程 TLS 模式因此比声明的更难用。只有一半是推理,未执行。
9. MCP 工具名带点号,如 `guard.request_reference`(`mcp.py:8-10`)。部分客户端的工具名约束是 `[A-Za-z0-9_-]`。**未验证假设**,需用真实 Codex 确认。
10. MCP 对未知方法返回 `-32600` 而不是 `-32601`,解析错误也不是 `-32700`(`mcp.py:68-72`)。`tools/call` 的所有 HTTP 失败都折叠成 `broker_request_failed`,agent 看不到 `policy_denied` 等原因(`mcp.py:66-67`)。行长检查发生在整行读入之后(`mcp.py:45`)。

## 4. 已接受的 MVP 限制(不算漏洞)
- 没有 OS 隔离,agent 若与 broker 同机同用户,可读取 DB 和 key。
- 没有 passkey 或用户验证,批准是手动点击。
- 已批准的 reference 任意设备都可批准同一用户的请求,agent 身份没有运行时强制。
- 审计表没有哈希链,也不记录 device id。
- adapter 摘要只覆盖 `adapter.py` 这一个文件。
- 有数据库写权限的人可以篡改状态,但无法伪造设备签名。

## 5. 测试缺口("通过 ≠ 授权完整")
- MCP 只测了 `initialize` 和 `tools/list`,指向不可达的 URL。`tools/call`、错误路径、重定向、过大响应、畸形 JSON-RPC 都没有测试。
- `test_signature_tamper_and_replay` 的重放被拒绝,是因为请求状态已不是 pending,不是因为签名绑定。没有测试"把 A 请求的签名用在 B 请求上"和"deny 签名当 approve 用"。
- 没有测试 login challenge 过期、session 过期、任务过期、多设备、阶段 2 批准后撤销 ref(设备撤销测试只部分覆盖)。
- 没有测试 TLS 监听器、Host 头、超大 body、`Transfer-Encoding`、慢连接。
- `PinnedTLS` 只测了 DNS 拒绝,没测证书和主机名校验。没有 IPv4-mapped IPv6 用例。`serve()` 的 executor 与 flock 没有测试。
- 反射测试用的是 stub transport,并没有用真实的 `fetch`。
- 没有测试 `revoke` 对不存在 id 的行为。

## 6. 额外复现脚本(全部**未执行**,请父审查者运行)
```python
# R1: revoke 对不存在 id 静默成功(预期 F4.1)
from secret_guard.broker import Broker; import tempfile
b = Broker(tempfile.mkdtemp()); b.revoke("task", "nonexistent")  # 不报错

# R2: 含空白凭据入库但执行必然 unknown(F4.2)
b.add_secret("a", "tok en 12345", ["acme/x"], "u", "p")  # 成功;之后 fetch 抛 invalid credential

# R3: 签名跨请求/跨意图(测试缺口)
# 创建两个 pending 请求,用 A 的 signing_text 对 B 调用 decide,预期 signature_invalid;
# 再用 deny 前缀的签名调用 approve,预期 signature_invalid。
```

## 7. 未验证项
真实 Codex MCP 调用、真实 GitHub 网络与 TLS 证书链、手机跨设备 HTTPS、浏览器实际行为、OS 隔离、F2 的 stdlib 行为和 F1 的握手阻塞,均**未实际运行**。本报告不构成任何安全认证。