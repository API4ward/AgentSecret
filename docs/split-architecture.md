# 拆分部署：审批端、server、注入工具

日期：2026-11-20。状态：协议原型，全部用假凭据和假 GitHub transport 验证。v0.1 的单进程 broker（`secret-guard` 命令）保持不变，本页描述的是并存的新部署方式（`agentsecret` 命令）。

## 三个部件

| 部件 | 代码 | 保存什么 | 能看到密码明文吗 |
| --- | --- | --- | --- |
| 审批端 | `secret_guard/approver.py`（终端版）、`secret_guard/web/approver.*`（浏览器版） | 全部密码、每条密码允许的仓库、已配对注入工具的公钥 | 能，全部 |
| server | `secret_guard/relay.py`、`secret_guard/split_server.py` | 已登记设备的公钥、待批请求、审计 | 不能 |
| 注入工具 | `secret_guard/injector.py` | 任务 token 的哈希、已配对审批端的公钥、请求状态 | 只在执行一次请求期间，在内存里 |

agent 仍然通过原有的 MCP bridge（`secret-guard mcp`）连接，三个工具和调用顺序不变，只是对面从 broker 换成了注入工具。

## 一次操作的经过

1. agent 调用 MCP 工具，注入工具用 adapter 冻结请求，用设备密钥对规范化的请求文本签名，提交给 server。
2. server 核对注入工具的签名和会话，把请求放入该用户的待批队列。
3. 审批端取回待批请求，自己做三项检查后才提供“批准”：请求来自配对过的注入工具且签名有效；本机有这条密码；请求能用本机的 adapter 从参数重建，并且仓库在该密码允许的范围内。不通过的请求不会等人处理：审批端立即拒绝并附上签名的原因，调用方在 `/reference`、`/workflow` 或 `/status` 的返回里看到 `reason` 和 `message`（见“拒绝原因”）。
4. 用户批准后，审批端对决定签名。如果是具体使用，审批端取出这一条密码，加密给配对时记下的注入工具公钥，并绑定这次请求的摘要。
5. server 核对审批端签名后转发。密封包只交付一次，交付后 server 不再保留。
6. 注入工具用配对时记下的审批端公钥验签，再次重建并核对请求，原子地把请求标为执行中，然后解开密码、发出请求、过滤结果。

引用授权（第一阶段）走同样的路径，只是批准不携带密码。

## 引用类型

申请引用时用 `type` 选择，MCP 工具 `guard.request_reference` 有同名参数，默认 `once`。

| 类型 | 含义 |
| --- | --- |
| `once`（一次性） | 批准后只能发起一次使用申请，申请后即失效。状态里的 `uses_left` 为 1 或 0。 |
| `long`（长期） | 批准后 1 小时内可反复用来申请使用。 |

两种类型的每次使用都仍需单独批准。到期时间在注入工具收到批准时确定（批准时刻加 1 小时，不超过任务本身的期限），在状态里以 `expires_at` 返回。

## 拒绝原因

| `reason` | `message` | 谁判定 |
| --- | --- | --- |
| `secret_unavailable` | 本设备没有这个密码 | 审批端，自动 |
| `injector_not_paired` | 审批端没有配对这台注入工具 | 审批端，自动 |
| `policy_denied` | 该密码不允许用于这个仓库 | 审批端，自动 |
| `request_changed` / `request_invalid` / `signature_invalid` | 请求与固定操作不符 / 格式无效 / 签名无效 | 审批端，自动 |
| `user_denied` | 用户拒绝了这次请求 | 用户 |
| `approver_not_paired` | 注入工具没有配对作出决定的审批端 | 注入工具 |
| `no_response` | 审批端在有效期内没有响应 | 注入工具 |

- 原因由审批端签名，注入工具只在验签通过后才显示，server 编不出原因。
- `agentsecret injector serve` 会让 agent 的这次调用最多等 2 秒；审批端在线时，自动拒绝的原因直接出现在这次调用的返回里。审批端不在线时仍然返回 `pending`，120 秒后变为 `expired`（`no_response`）。
- 同一用户有多台审批端时，只有全部审批端都判定不能批准，请求才算拒绝；其中一台有这条密码就仍然等它批准。
- 用户亲手拒绝的请求在任务内保持拒绝。自动拒绝的原因可以修复（补录密码、完成配对），修复后同样的调用会发起新的请求。
- 代价：agent 能借 `secret_unavailable` 判断某个别名在审批端是否存在。

## 密码内容

审批端不解释也不限制密码内容：任意字符、任意长度按原样保存，只拒绝空值。唯一的上限是一次密封转发的 64 KB。别名（1 到 64 个字母、数字、点、下划线、连字符）用来区分每条密码，校验失败时分别提示是别名、密码还是仓库的问题。只读 GitHub adapter 发请求时仍要求 token 是可见 ASCII，这是 adapter 的限制，不符合时该次使用结果为 `unknown`。

## 签名与密封

- 注入工具签名的内容：`secret-guard/request/v1:` + 请求文本。
- 审批端签名的内容：`secret-guard/decision/v3:` + `approve|deny` + `:` + 原因代码（批准和手动拒绝时为空） + `:` + 审批端设备编号 + `:` + 同一段请求文本。双方都对原始文本签名，不需要重新序列化 JSON。
- 密封：P-256 临时密钥 ECDH，HKDF-SHA256，AES-256-GCM，附加数据是请求文本的 SHA-256。Python 实现在 `secret_guard/seal.py`，浏览器实现用 WebCrypto，两者已互通验证。

## 使用

三个部件可以在三台机器上。下面的例子都在本机，状态目录默认在 `~/.local/share/agentsecret/` 下。

```sh
# server
agentsecret relay init
agentsecret relay serve                        # http://127.0.0.1:8780，同时提供浏览器审批端页面

# 注入工具（agent 所在的机器）
agentsecret injector init --user alice --relay http://127.0.0.1:8780
agentsecret injector pairing --out injector.json

# 审批端（终端版；浏览器版打开 server 地址，页面顶部的“设置步骤”按顺序列出剩余步骤和可复制的命令，并标出当前缺哪一步）
agentsecret approver init --user alice --relay http://127.0.0.1:8780
agentsecret approver pairing --out approver.json
agentsecret approver pair-injector --pairing-file injector.json
agentsecret approver secret-add github-ci --repo acme/payments

# 互相登记公钥
agentsecret relay device-register --pairing-file injector.json
agentsecret relay device-register --pairing-file approver.json
agentsecret injector pair-approver --pairing-file approver.json

# 运行
agentsecret injector serve                     # agent API 在 http://127.0.0.1:8765
agentsecret approver run                       # 在终端逐条批准或拒绝
agentsecret injector task-create --project payments --token-file /absolute/path/run-01.token
secret-guard mcp --token-file /absolute/path/run-01.token
```

配对文件只含公钥。server 不在本机时必须用 `--cert`/`--key` 启动，设备只接受 https 地址。

## 已验证

`python -m unittest tests.test_split`，18 条，全部使用进程内或本机回环的 server：

| 检查 | 结果 |
| --- | --- |
| 两阶段闭环；密码不出现在 server 的任何收发内容、server 数据库、注入工具数据库和返回给 agent 的结果里 | 通过 |
| 控制 server 的人登记自己的审批设备并“批准” | 注入工具拒绝，不发请求 |
| server 把上一次的密封包重放给另一次请求 | 解封失败，不发请求 |
| 密封包只有配对的注入工具能打开；只交付一次 | 通过 |
| server 改写队列里的请求 | 审批端判定签名无效 |
| 未配对的注入工具、未知密码、策略外的仓库 | 审批端不提供批准，自动拒绝，调用方拿到原因 |
| server 伪造拒绝原因；另一台审批端有这条密码 | 原因不显示；请求继续等待并可被批准 |
| 一次性引用用过即失效；长期引用 1 小时内可反复使用，每次单独批准 | 通过 |
| 短密码、含空格和换行、非 ASCII、60 KB 的密码 | 原样保存，60 KB 的密码完成密封转发 |
| 拒绝保持、过期、跨任务引用、撤销审批端、结果回显密码、崩溃恢复为 unknown | 通过 |
| 原有 MCP bridge 直接连注入工具 | 通过 |
| HTTP 往返，server 没有注册、导出类路由 | 通过 |

浏览器审批端另用无头 Chromium 手动跑通了一遍：照页面“设置步骤”打印的命令逐条执行完成登记和配对，录入假密码（含空格的 3 字符密码），批准一次性引用和一次使用，Python 注入工具解开并使用了页面密封的密码；未知密码和策略外仓库的请求被页面自动拒绝，调用方拿到了原因。这一遍没有纳入自动测试。

## 与架构文档的差别和未完成项

- **注入工具到 server 是轮询，不是长连接。** 注入工具每秒主动询问一次，同样可以待在 NAT 后面。标准库没有 WebSocket，原型先不引入依赖。
- **没有推送。** 审批端要开着页面或终端程序；页面连接后每 2 秒自动取一次请求。
- **设置步骤里有两步页面检测不到**（注入工具 `pair-approver`、`injector serve`），需要手动勾选。
- **没有账号系统。** 设备由 server 管理员用命令行登记。
- **没有备份和恢复。** 密码只在审批端一份，状态目录或浏览器存储丢失就全部丢失。
- **审批端没有每次批准的生物识别确认。** 浏览器版的密钥和密码在浏览器存储里，只能用假凭据。
- **注入工具只过滤它这次用到的那一条密码的回显。** v0.1 的 broker 知道全部密码，可以全部比对；注入工具不保存密码，做不到。
- **凭据更新不会自动作废已发的引用。** 审批端每次批准时取当前值。
- **只有一个只读 GitHub adapter**，没有出网代理式的注入。
- agent 与注入工具同一系统用户时，注入工具的状态目录（设备私钥、任务数据库）需要靠 hook 或 OS 隔离保护。hook 分支的受保护路径还没有指向这个目录。
- 2026-10-24 审查确认的 TLS 握手阻塞问题仍在 agent 监听端口上。
