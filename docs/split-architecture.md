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

## agent 碰到密码的三种情况

| 情况 | 谁发起 | 结果 |
| --- | --- | --- |
| agent 主动要求使用密码 | agent 调用 MCP 工具 | 上面的两阶段流程，密码由注入工具代为注入，明文不进入 agent |
| 工具返回的内容里有密码（`reveal`） | hook，在模型看到结果之前 | 触发审批。批准后，内容里的密码被换成引用 `{{secretref:别名}}` 再交给 agent；拒绝或无人应答则这段内容不给 agent |
| 工具调用的参数里有引用（`fill`） | hook，在工具执行之前 | 触发审批。批准后，引用被换成密码，只出现在这一次工具调用的输入里 |

本产品不提供沙盒或 OS 隔离。hook 管的是经过 agent 工具调用的内容。

### 审批端保存明文，agent 机器上只有匹配程序

审批端把每条密码（含同名副本）编译成一个匹配器，对整套匹配器签名（`secret-guard/rules/v1:` + 文本，带递增版本号），经 server 下发。注入工具只接受已配对审批端签名的版本，版本号不能回退，每 5 秒同步一次。匹配器在 `secret_guard/matcher.py`（浏览器审批端用 WebCrypto 做同样的编译），每条包含：

- 密码的字节长度；
- 滚动哈希的 16 位标记，用来快速排除绝大多数位置；
- 加盐的 PBKDF2-HMAC-SHA256 摘要（5 万次迭代），用来确认真正命中。

匹配器里没有明文，也不能反解。但它本质上是一个“是不是这条密码”的判定器：能读到注入工具状态目录的人可以拿它离线试猜测。高熵的密码（API key）不受影响；像 `18year` 这样短而可猜的值，保护强度只有 PBKDF2 的计算成本，16 位标记还会再泄露 16 比特。少于 4 字节的密码不编译，也就检测不到。匹配只认原样的字节，base64、URL 编码、拆开写的密码检测不到。

### hook 做什么

`agentsecret injector claude-config`（Claude Code）和 `codex-config`（Codex）生成的配置在 PreToolUse 和 PostToolUse 两个事件上安装同一个 hook（`secret_guard/claude_hook.py`）。

```sh
agentsecret injector claude-config --token-file /absolute/path/run-01.token \
  --out /absolute/path/run-01.mcp.json --settings-out /absolute/path/run-01.settings.json
claude --mcp-config /absolute/path/run-01.mcp.json --strict-mcp-config --settings /absolute/path/run-01.settings.json
```

- **工具执行之后（PostToolUse）**：hook 把工具结果交给本机的注入工具扫描。没有命中就原样放行。命中则提交一次 `reveal` 请求，最多等 110 秒；批准后用 `updatedToolOutput` 把结果里的密码换成引用，否则把含密码的那段文字换成一句“已扣留”的说明。注入工具不可达时同样扣留。
- **工具执行之前（PreToolUse）**：调用碰到 AgentSecret 自己的状态时直接拒绝。参数里有 `{{secretref:别名}}` 时提交一次 `fill` 请求；批准后审批端把值密封给注入工具，hook 取走一次，用 `updatedInput` 换进参数。值只在注入工具和 hook 的内存里经过，不写盘。拒绝或超时则拦下这次调用。

请求里只有别名、工具名、目标（文件路径或 URL）和调用摘要，没有密码。

### 三个场景

| 场景 | 经过 |
| --- | --- |
| secret 检测 | 审批端存 `age` = `18year`。`example/qa.txt` 内容是 `I am 18year old.`。agent 读这个文件，hook 在内容到达 agent 之前检出密码并触发审批；批准后 agent 看到 `I am {{secretref:age}} old.`。之后 agent 写出含 `{{secretref:age}}` 的内容时再次审批，批准后落盘的是 `18year`。 |
| 网站登录 | agent 让浏览器工具提交 `{"password": "{{secretref:shop_password}}"}`，审批端看到工具名和登录地址；批准后浏览器工具拿到真实密码。登录后的页面如果回显了密码，agent 看到的仍是引用。 |
| 填写配置 | 用 DeepSeek 启动 Codex：agent 把 `experimental_bearer_token = "{{secretref:DEEPSEEK_API_TOKEN}}"` 写进 `~/.codex/config.toml`，审批端看到目标文件并询问；批准后文件里是真实的 key。agent 再读这个文件，看到的还是引用。 |

### 审批模式和审批面板

```sh
agentsecret approver secret-add DEEPSEEK_API_TOKEN                 # 保存的密码
agentsecret approver secret-add DEEPSEEK_API_TOKEN --label team    # 同名的另一个副本
agentsecret approver mode all --minutes 10                         # 10 分钟内全部同意
agentsecret approver mode ask                                      # 恢复逐条询问
agentsecret approver auto-add --kind fill --secret 'DEEPSEEK_*' --tool Write --target '*/.codex/config.toml'
agentsecret approver auto-list
```

- **按钮**：拒绝、允许（1 次）、其他。“其他”可以选允许 n 次或允许一段时间（3 分钟、10 分钟等）；之后同一项目里、同一类请求、同一组密码的请求自动批准，直到次数用完或时间到。
- **修改返回的密码**：批准 `fill` 或 MCP 的使用请求时，可以改成返回同名的另一个副本、mock（形状相同的假值，不告诉它真密码但也不拒绝），或手动输入的值。
- **all**：一段时间内所有能批准的请求都自动批准。
- **auto**：规则由请求类型、密码别名、工具名、目标四项组成，每项可用 `*` 通配，全部符合就自动批准。

这些模式都是审批端替用户作答：每个请求仍然单独签名，server 和注入工具看到的协议没有变化。所以审批端（`approver run` 或浏览器页面）必须在运行，自动批准才会发生。确定不能批准的请求（没有这条密码等）仍然立即拒绝并带原因。终端审批端在提示处输入 `yes`、`3x`、`10m`，再选择返回值。

### 已知缺口

- **只验证了 hook 进程本身。** 测试给真实的 hook 进程喂 Claude Code 文档里的事件格式，并执行它返回的 `updatedInput` / `updatedToolOutput`；没有在真实的 Claude Code 或 Codex 会话里跑过。工具结果的字段形状是按文档和常见结构处理的（递归替换所有字符串），真实会话里如果 `updatedToolOutput` 要求别的形状，需要调整。
- **改不了 agent 的最终回答。** hook 只能改工具的输入和输出。agent 在回复里写 `{{secretref:age}}`，用户看到的就是引用本身。
- 批准 `fill` 时 hook 返回 `permissionDecision: allow`，这次调用不再走 Claude Code 自己的权限询问。
- 填进去的密码会出现在那次工具调用的效果里（写进文件、发给网站）。之后的工具结果里如果再出现，会再次被换成引用；但 Claude Code 的会话记录是否保存改写后的输入没有验证。
- 网站登录用本地假网站和模拟的浏览器工具调用验证，没有接真实的浏览器 agent。
- 手动输入的返回值配合“允许 n 次/一段时间”时会保存在审批端（终端版加密保存，浏览器版在浏览器存储里）。
- 注入工具没有运行时，装了 hook 的 agent 读不到任何工具结果（全部扣留），带引用的调用全部拦下。
- 每兆字节内容的扫描在本机约 1 秒（纯 Python）；单次最多扫描 4 MB，超过则扣留。

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

`python -m unittest discover`，67 条（1 条因本机没有 Codex 跳过），全部使用进程内或本机回环的 server：

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
| 匹配器签名下发；server 伪造或回放旧版本；明文不在线路、server 和注入工具的文件里 | 注入工具只认已配对审批端的新版本；通过 |
| 三个场景（`tests/test_scenarios.py`，真实 hook 进程）：检测、替换为引用、还原；DeepSeek 配置；本地假网站登录 | 通过 |
| 允许 n 次、允许一段时间、全部同意、规则自动审批；返回副本、mock、手动输入 | 通过 |
| 拒绝、无人应答、注入工具不可达 | 内容扣留，带引用的调用被拦下 |

浏览器审批端另用无头 Chromium 手动跑通了一遍：照页面“设置步骤”打印的命令逐条执行完成登记和配对，录入假密码（含空格的 3 字符密码），批准一次性引用和一次使用，Python 注入工具解开并使用了页面密封的密码；未知密码和策略外仓库的请求被页面自动拒绝，调用方拿到了原因。这一遍没有纳入自动测试。2026-11-20 又用同样的方式在浏览器审批端上跑了场景 1 和场景 3：页面录入 `age` 和 `DEEPSEEK_API_TOKEN`（含副本 team），读 `qa.txt` 时页面出现审批卡片，批准后 hook 返回 `I am {{secretref:age}} old.`；写配置时依次选了副本、mock、手动输入加“允许 3 次”、全部同意模式和自动审批规则，结果都符合预期，server 和注入工具的数据库里没有明文。

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
- agent 与注入工具同一系统用户时，注入工具的状态目录（设备私钥、任务数据库）靠 hook 保护：`injector claude-config` / `codex-config` 生成的 hook 已把它列为直接拒绝的路径。同账户下有意绕过 hook 的进程不在防护范围内。
- 2026-10-24 审查确认的 TLS 握手阻塞问题仍在 agent 监听端口上。
