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
3. 审批端取回待批请求，自己做三项检查后才提供“批准”：请求来自配对过的注入工具且签名有效；本机有这条密码；请求能用本机的 adapter 从参数重建，并且仓库在该密码允许的范围内。不通过的请求只能拒绝。
4. 用户批准后，审批端对决定签名。如果是具体使用，审批端取出这一条密码，加密给配对时记下的注入工具公钥，并绑定这次请求的摘要。
5. server 核对审批端签名后转发。密封包只交付一次，交付后 server 不再保留。
6. 注入工具用配对时记下的审批端公钥验签，再次重建并核对请求，原子地把请求标为执行中，然后解开密码、发出请求、过滤结果。

引用授权（第一阶段）走同样的路径，只是批准不携带密码。

## 签名与密封

- 注入工具签名的内容：`secret-guard/request/v1:` + 请求文本。
- 审批端签名的内容：`secret-guard/decision/v2:` + `approve|deny` + `:` + 审批端设备编号 + `:` + 同一段请求文本。双方都对原始文本签名，不需要重新序列化 JSON。
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

# 审批端（终端版；浏览器版打开 server 地址，在页面上完成同样的步骤）
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

`python -m unittest tests.test_split`，13 条，全部使用进程内或本机回环的 server：

| 检查 | 结果 |
| --- | --- |
| 两阶段闭环；密码不出现在 server 的任何收发内容、server 数据库、注入工具数据库和返回给 agent 的结果里 | 通过 |
| 控制 server 的人登记自己的审批设备并“批准” | 注入工具拒绝，不发请求 |
| server 把上一次的密封包重放给另一次请求 | 解封失败，不发请求 |
| 密封包只有配对的注入工具能打开；只交付一次 | 通过 |
| server 改写队列里的请求 | 审批端判定签名无效 |
| 未配对的注入工具、未知密码、策略外的仓库 | 审批端不提供批准 |
| 拒绝保持、过期、跨任务引用、撤销审批端、结果回显密码、崩溃恢复为 unknown | 通过 |
| 原有 MCP bridge 直接连注入工具 | 通过 |
| HTTP 往返，server 没有注册、导出类路由 | 通过 |

浏览器审批端另用无头 Chromium 手动跑通了一遍：页面生成密钥、配对、录入假密码、批准，Python 注入工具解开并使用了页面密封的密码；策略外的请求在页面上只有“拒绝”按钮。这一遍没有纳入自动测试。

## 与架构文档的差别和未完成项

- **注入工具到 server 是轮询，不是长连接。** 注入工具每秒主动询问一次，同样可以待在 NAT 后面。标准库没有 WebSocket，原型先不引入依赖。
- **没有推送。** 审批端要开着页面或终端程序。
- **没有账号系统。** 设备由 server 管理员用命令行登记。
- **没有备份和恢复。** 密码只在审批端一份，状态目录或浏览器存储丢失就全部丢失。
- **审批端没有每次批准的生物识别确认。** 浏览器版的密钥和密码在浏览器存储里，只能用假凭据。
- **注入工具只过滤它这次用到的那一条密码的回显。** v0.1 的 broker 知道全部密码，可以全部比对；注入工具不保存密码，做不到。
- **凭据更新不会自动作废已发的引用。** 审批端每次批准时取当前值。
- **只有一个只读 GitHub adapter**，没有出网代理式的注入。
- agent 与注入工具同一系统用户时，注入工具的状态目录（设备私钥、任务数据库）需要靠 hook 或 OS 隔离保护。hook 分支的受保护路径还没有指向这个目录。
- 2026-10-24 审查确认的 TLS 握手阻塞问题仍在 agent 监听端口上。
