# Claude Code 接入与保证范围

日期：2026-11-11。验证版本：Claude Code 2.1.311（headless `claude -p`），实际模型 `claude-sonnet-5-5`。全部使用合成凭据和假 GitHub transport。

Secret Guard 的 MCP 服务器不区分客户端，Claude Code 通过同一个 STDIO bridge 接入，broker 侧无需改动。本页说明接入方式、已实测的行为，以及 Claude Code 的子 agent、权限和 hooks 对任务身份与保证范围的影响。

## 为一次任务建立连接

broker 的建立、凭据登记和审批设备配对与 [README](../README.md) 相同。每次 Claude Code 运行单独创建 task 和配置文件：

```sh
.venv/bin/secret-guard task-create --user alice --project payments \
  --agent claude-code --token-file /absolute/path/run-01.token
.venv/bin/secret-guard claude-config \
  --token-file /absolute/path/run-01.token --out /absolute/path/run-01.mcp.json
claude --mcp-config /absolute/path/run-01.mcp.json --strict-mcp-config
```

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

## 权限和 hooks 不构成边界

- **权限规则。** 可以在按次的 `--settings` 里用 `permissions.deny` 禁止读取 broker 状态目录和审批浏览器 profile，这能挡住模型的误操作，但不是安全边界：Bash、hooks、其他 MCP 服务器和子进程都以同一 OS 用户运行，绕过文件工具即可读取。真正的隔离依赖 OS 安全域（实现状态文档的后续第 1 项）。
- **token 文件对 agent 可读。** bridge 以 agent 的用户身份运行，agent 能读到 token 文件。token 只能申请操作和查询本任务状态，不能批准、不能取明文。泄漏的后果是他人可冒用本任务申请操作并消耗审批注意力，已批准的引用也可被其使用来发起仍需逐次审批的 use 请求。
- **hooks。** PreToolUse/PostToolUse hook 能看到 MCP 工具的入参和结果，即引用、operation_id 和已过滤的结果，看不到凭据。hook 是 worker 安全域内的 shell 命令，项目级 hook 来自工作区内容，不可信，因此不能把审批、过滤或身份判定放在 hook 里。PostToolUse 也不能替代入口过滤，这与产品设计的结论一致。本次没有编写或测试任何 hook。
- **会话记录。** Claude Code 把对话写入 `~/.claude/projects/` 下的 jsonl，其中会有引用、operation_id 和操作结果。引用绑定任务且会过期，结果是白名单字段，凭据不会进入记录（实测输出流中未出现）。

## 未覆盖

真实 GitHub 网络、人在审批页面上的交互批准、Claude 桌面应用、Claude Agent SDK、远程（HTTP）MCP 传输、插件分发、worker 与 broker 的 OS 隔离。README 的“保证范围”一节同样适用于 Claude Code。
