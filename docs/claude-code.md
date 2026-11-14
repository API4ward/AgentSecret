# Claude Code 接入与保证范围

日期：2026-11-11。验证版本：Claude Code 2.1.311（headless `claude -p`），实际模型 `claude-sonnet-5-5`。全部使用合成凭据和假 GitHub transport。

Secret Guard 的 MCP 服务器不区分客户端，Claude Code 通过同一个 STDIO bridge 接入，broker 侧无需改动。本页说明接入方式、已实测的行为，阻止 Claude 直接读取密钥的 hook 防线，以及子 agent 对任务身份的影响。

## 为一次任务建立连接

broker 的建立、凭据登记和审批设备配对与 [README](../README.md) 相同。每次 Claude Code 运行单独创建 task 和配置文件：

```sh
.venv/bin/secret-guard task-create --user alice --project payments \
  --agent claude-code --token-file /absolute/path/run-01.token
.venv/bin/secret-guard claude-config \
  --token-file /absolute/path/run-01.token --out /absolute/path/run-01.mcp.json \
  --settings-out /absolute/path/run-01.settings.json
claude --mcp-config /absolute/path/run-01.mcp.json --strict-mcp-config \
  --settings /absolute/path/run-01.settings.json
```

`--settings-out` 生成的设置文件装有 PreToolUse hook，阻止 Claude 用自带工具读取 broker 状态和 token，见下文“hook 防线”。token 和 broker 状态目录必须放在工作区之外。

`claude-config` 生成的文件只包含 token 文件的路径，不包含 token，权限 0600，拒绝覆盖已有文件。broker 不在默认地址时给 `claude-config` 加 `--url`。生成内容如下：

```json
{"mcpServers": {"secret_guard": {"type": "stdio",
  "command": "/absolute/path/AgentSecurity/.venv/bin/python",
  "args": ["-m", "secret_guard.cli", "mcp", "--url", "http://127.0.0.1:8765",
           "--token-file", "/absolute/path/run-01.token"],
  "env": {"PYTHONPATH": "/absolute/path/AgentSecurity"}}}}
```

接入规则：

- 只通过 `--mcp-config` 按次传入。不要用 `claude mcp add` 把它登记到 user 或 project 范围，也不要写进仓库的 `.mcp.json`，否则所有会话共用同一个 token，任务身份失效。
- `--strict-mcp-config` 让本次运行忽略其他来源的 MCP 配置，避免无关 MCP 服务器进入同一会话。
- 无人值守运行可加 `--allowedTools "mcp__secret_guard__*"` 预先放行这三个工具。这只是 Claude Code 自己的工具权限，与 broker 审批无关，放行后每个操作仍需审批设备签名。
- 任务结束后执行 `secret-guard revoke task task_...` 并删除 token 与配置文件。

Claude Code 会把工具名里的点替换为下划线并加上服务器前缀，模型实际看到的是：

| MCP 工具名 | Claude Code 中的名称 |
|---|---|
| `guard.request_reference` | `mcp__secret_guard__guard_request_reference` |
| `guard.github_workflow_runs` | `mcp__secret_guard__guard_github_workflow_runs` |
| `guard.operation_status` | `mcp__secret_guard__guard_operation_status` |

闭环与 README 一致：申请引用，审批设备批准，查询状态得到 `secretref://…`，发起 workflow 请求，审批设备批准，查询状态得到结果。

## 已实测

`python -m examples.claude_e2e` 启动临时 broker、单任务配置和一次真实的 `claude -p`，由脚本内的合成审批设备通过审批端口对 pending 请求签名。结果摘要在 [reviews/2026-11-11-claude-code-e2e](reviews/2026-11-11-claude-code-e2e/)。

| 检查 | 结果 |
|---|---|
| Claude Code 加载按次配置并列出 3 个工具 | PASS |
| 申请引用、批准、取得引用、发起操作、批准、取得结果 | PASS，审计事件为 requested, approved, requested, approved, consumed, succeeded |
| 假 transport 只被调用一次且拿到登记的凭据 | PASS |
| 合成凭据和 task token 未出现在 Claude Code 的全部 stream-json 输出与 stderr 中 | PASS |
| 子 agent 使用父会话取得的引用发起操作（`--subagent`） | PASS，且 broker 只看到同一个 task |

审批由脚本自动签名，这验证的是协议闭环，不是人在审批页面上核对请求。交互模式下由人在浏览器批准的流程本次未运行。

## 对任务身份的影响

broker 认的身份是 **持有该 token 的 MCP bridge 进程**，不是 Claude Code 内部的任何对象。

- **子 agent 共享身份（已实测）。** 子 agent 复用父会话的 MCP 连接，可以直接使用父会话拿到的引用，broker 审计里只有一个 task，无法区分调用来自主循环还是子 agent。一次引用授权因此覆盖本次运行内的所有子 agent。审批页面上的每次 use 仍然逐条显示完整请求，这是目前唯一的逐操作控制点。
- **恢复和分叉（未实测，按机制推断）。** `--resume`、`--continue`、`--fork-session` 如果沿用同一个配置文件，就是同一个 task。如果换了新 token，历史对话里的旧引用会被 broker 以跨任务为由拒绝（`test_cross_task_reference_and_status` 覆盖 broker 侧）。
- **后台 agent、agent teams、worktree（未实测）。** 只要是用同一个配置文件启动的进程就共用身份。要隔离就必须各自 `task-create`。
- **上下文压缩（未实测）。** 引用和 operation_id 是不透明字符串，压缩后丢失只会导致重新申请，相同的 pending 请求会被 broker 合并。

结论与 Codex 兼容版相同：身份粒度是独立 MCP 进程，Claude Code 没有向 STDIO MCP 服务器提供不可伪造的会话或子 agent 标识，逐子 agent 隔离需要运行时适配，当前不能承诺。

## hook 防线：阻止 Claude 读取密钥

MCP 只提供了一条不接触明文的调用路径，它不能阻止 Claude 用自带的 Read、Grep、Bash 直接打开 broker 的文件。这件事由 hook 负责：`claude-config --settings-out` 生成的设置文件注册一个匹配全部工具的 PreToolUse hook（`secret_guard/claude_hook.py`），调用触及受保护路径时以退出码 2 拒绝，工具不会执行。

受保护路径：broker 状态目录（全局参数 `--state`）、本次的 token 文件、生成的 MCP 配置和设置文件、`secret_guard` 包目录（防止会话中改掉 hook 自身），以及用 `--protect` 追加的路径，例如审批浏览器 profile 和设备密钥：

```sh
.venv/bin/secret-guard --state /absolute/path/state claude-config ... \
  --settings-out /absolute/path/run-01.settings.json --protect /absolute/path/approval-profile
```

各工具的判定：

| 工具 | 拒绝条件 |
|---|---|
| Read、Edit、Write、NotebookEdit、未知工具 | 任一参数解析后落在受保护路径内，含相对路径、`..`、符号链接、大小写变体 |
| Grep、Glob | 搜索根在受保护路径内，或是其上级目录；Glob 模式能匹配到受保护路径 |
| Bash 及其他带 `command` 参数的工具 | 见下 |
| `mcp__secret_guard__*` | 放行 |

Bash 命令按以下规则检查，任一命中即拒绝：

- 命令文本（去掉引号和反斜杠后）出现受保护路径、受保护文件的文件名，或可信 CLI 的名字（`secret-guard`、`secret_guard`、`guardctl`）。agent 不应运行可信 CLI 或导入该包。
- 任一词展开 `~`、`$HOME`、环境变量和命令内赋值的变量后，解析到受保护路径内，或解析到其上级目录（`grep -r x ~`、`find /`、`cd ~`）。相对路径同时按命令里出现的每个绝对路径解析，以覆盖 `cd dir && cat 相对路径`。
- 通配符（`*`、`?`、`[]`、`{}`）能匹配到受保护路径或其上级。
- 引号内嵌的绝对路径（如 `python -c "open('/…')"`）同样检查。
- shell 的当前目录在受保护路径内或是其上级时，全部 Bash 调用被拒绝。因此 token 和状态目录要放在工作区之外，也不要在主目录下直接启动 Claude。

设置文件同时写入 `permissions.deny` 规则作为第二层。hook 读不到输入、参数不合法或内部出错时一律拒绝。

规则偏严，会误伤一些正常命令，例如 `cd ~`、`ls ..`（上级目录包含受保护路径时）和任何提到 `secret-guard` 字样的命令。

### hook 挡不住什么

hook 是对工具参数的字符串检查，和 agent 运行在同一个 OS 账户下，不是安全边界。已知挡不住的情况：

- 路径在运行时才拼出来，命令文本里没有它。例如 `python3 -c 'open(chr(47)+…)'`、base64 解码后执行、先写脚本文件再运行、由未知变量或命令替换给出路径。测试 `test_known_bypass_is_documented_not_blocked` 记录了这一点。
- 不经过 Claude 工具的进程：其他 MCP 服务器、agent 启动的后台进程、已在运行的程序。
- hook 自身的运行环境同账户可写：Python 解释器、虚拟环境、用户级 Claude Code 设置。用户或项目设置里的 `disableAllHooks` 会让它失效。
- token 文件必须对 MCP bridge 可读，所以同账户的任何进程都能读。token 只能申请操作和查询本任务状态，不能批准、不能取明文。
- 会话记录 `~/.claude/projects/*.jsonl` 里有引用、operation_id 和操作结果，没有凭据。

所以 hook 的作用是拦住模型的直接读取和常见变形，包括被提示注入后顺手去读文件的情况。它不能对付有意绕过的攻击者。需要这条保证时使用[隔离部署](isolation.md)，那里 agent 所在的容器根本没有挂载 broker 状态，无论命令怎么写都读不到。两者可以叠加。

审批、过滤和身份判定仍然不放在 hook 里：项目级 hook 来自工作区内容，不可信。

## 未覆盖

真实 GitHub 网络、人在审批页面上的交互批准、Claude 桌面应用、Claude Agent SDK、远程（HTTP）MCP 传输、插件分发、worker 与 broker 的 OS 隔离。README 的“保证范围”一节同样适用于 Claude Code。
