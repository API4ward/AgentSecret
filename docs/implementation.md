# 实现与验收状态

日期：2026-09-28。版本：0.1.0，MCP 兼容版协议闭环原型。

## 实现映射

| 设计内容 | 实现 | 状态 |
|---|---|---|
| 独立 broker / vault | `secret_guard/broker.py`，AES-256-GCM + SQLite | 已实现；本地 vault key，无外部 Secret Manager |
| 两阶段授权 | ReferenceGrant + 签名 use approval + 原子消费 | 已实现 |
| 完整请求绑定 | principal/task/agent/device/secret/version/adapter digest/URL/args/body/header/policy/preview/nonce/expiry | 已实现；执行时重新验证存储的原始签名 |
| 独立设备配对 | 浏览器生成密钥，桌面 CLI 手动注册公钥 | 已实现原型；无自动注册接口 |
| 手机授权 | HTTPS 下可访问响应式审批网页 | 浏览器原型；非原生 App/passkey，无硬件用户验证 |
| 固定 GitHub adapter | workflow runs GET，Actions read，schema 白名单 | 已实现；真实 GitHub 凭据联调未运行 |
| 结果过滤与审计 | buffer ≤1 MiB、精确/常见编码匹配、固定结果字段、无异常回显 | 已实现支持路径；非任意编码保证 |
| MCP 接入 | 3 个具名工具，STDIO JSON-RPC | 已实现；线协议与本地 HTTP 测试通过；真实 Codex 调用未运行 |
| Claude Code 接入 | `claude-config` 生成按次 `--mcp-config`；`examples/claude_e2e.py` | 已实现；Claude Code 2.1.311 headless 假凭据闭环通过，子 agent 共享 task 身份已确认；见 [claude-code.md](claude-code.md) |
| 故障恢复 | durable executing → unknown；无自动重试 | 已实现 |
| 策略和撤销 | user/project/repo、task/device/secret/operation 撤销、版本变更失效 | 已实现 |
| OS/网络边界、清洗工作区 | 设计第 9 节第二阶段 | 尚未实现 |
| 严格消息保护与 Codex 适配 | 设计第 9 节第三阶段 | 尚未实现 |
| issue 创建、更多 adapter | 后续有副作用操作 | 尚未实现；本版仅只读 |

## 运行边界

broker DB、AES key、源码、可信 CLI 与审批页面代码属于受信任边界。数据库修改不能作为用户批准；use 执行仍复验设备签名。完整宿主控制不在威胁模型内，数据库和源码完整性仍需 OS 边界。

task token 是独立运行的代理身份凭据，其 hash 存库；设备 session token 只在审批浏览器内存，私钥存于可信 origin。兼容版无法从官方 Codex 获取不可伪造的逐 thread/fork 身份，不能把手动 per-task 启动流程宣传为已经完成的运行时强制隔离。

生产网络只允许固定 GitHub HTTPS；adapter 一次解析 DNS，要求所有解析地址为 public，连接冻结 IP 并验证 `api.github.com` TLS 身份。禁用代理与重定向。该检查仅覆盖 adapter 连接，不限制 agent 的其他网络路径。

审批签名消息：`secret-guard/decision/v1:{approve|deny}:{canonical_payload}`。服务端生成排序键、ASCII JSON，浏览器对服务端原始 `signing_text` 字节签名。冻结参数详情和相同内容的摘要均可查看。登录签名用途域不同，challenge 一次性。签名授权保留服务端，不提供 MCP approve/get_secret/export 工具。

每个 use 请求的批准 payload 与签名独立保存。原子事务验证有效引用、设备、任务、凭据版本、策略与源码摘要；提交 executing 和 consumed 审计后发起一次网络请求。签名不能重放到另一个 request_id。另一个 daemon 被 POSIX 文件锁拒绝；trusted CLI 可在运行中撤销或轮换凭据。

## 测试方法

`python -m unittest discover -v` 覆盖：两阶段闭环、加密存储、无明文返回、引用与 use 过期、登录/审批重放、伪造批准、跨任务引用、跨用户/项目与仓库策略、拒绝合并、并发与跨 broker 原子消费、完整冻结参数篡改、adapter 摘要改变、凭据轮换、四种撤销、反射秘密及常见编码、错误消息清洗、崩溃 unknown 恢复、状态查询不执行、URL 注入、HTTP 端口分离/额外批准字段/Origin 拒绝、远程 TLS 要求与 MCP 线协议。

2026-11-11 补充：MCP bridge 重定向不再转发 task token（2026-10-24 审查 F2），新增 302/307 回归测试与 `claude-config` 测试，共 28 项。

测试结果记录在 [validation.md](validation.md)。这些是假凭据、假 GitHub transport 的协议测试，不能代替独立目标服务观察或严格运行环境测试。真实 Codex MCP、真实 GitHub 网络、手机跨设备 HTTPS、硬件用户验证、原生输入/工具/压缩/fork 等验收均未运行。

## 后续严格版本必须完成

1. 把 broker/审批浏览器与 worker 放入独立 OS 安全域；固定挂载、凭据路径与 egress，阻止 direct-network 与 HOME 读取绕过。
2. 实现工作区准入：历史/子模块/链接/二进制/缓存/环境都检查，已纳管值投影为占位符；原始文件不挂载 worker。未知候选隔离。
3. 实现自有 App Server 客户端；先观察当前固定 Codex 版本的输入、工具输出、持久化和模型调用顺序，再定位内核过滤点。不能由 PostToolUse 或事件流过滤代替入口边界。
4. 绑定真实 task/fork/subagent 生命周期；新增任务独立 ReferenceGrant，恢复/摘要重新校验权限。
5. 用 passkey/设备安全区实现每次审批的用户验证，完成可信双端配对、推送、设备管理与防审批轰炸的产品流程。
6. 使用独立观测目标完成设计第 10 节全量 canary 矩阵，覆盖 DNS/重定向/直接出网、崩溃恢复与所有支持输入入口；失败或未支持路径禁用。
