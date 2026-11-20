# Codex 接入：两层保护

日期：2026-11-14。验证版本：codex-cli 0.166.0，macOS。全部使用合成 canary。

## 用法

```sh
.venv/bin/secret-guard task-create --user alice --project payments \
  --token-file /absolute/path/run-01.token
.venv/bin/secret-guard --state /absolute/path/state codex-config \
  --token-file /absolute/path/run-01.token --out /absolute/path/run-01.codex
/absolute/path/run-01.codex exec "任务描述"
```

`codex-config` 生成一个只供这一次任务使用的启动脚本（权限 0700，拒绝覆盖），内容是 `exec codex -c … "$@"`。所有配置通过 `-c` 传入，不写 `~/.codex/config.toml`。脚本里只有 token 文件的路径，没有 token。`--protect` 追加受保护路径，`--codex` 指定 codex 可执行文件，`--url` 指定 broker 地址。

## 第 1 层：阻止 Codex 读取本地密码

受保护路径与 Claude Code 相同：broker 状态目录（`--state`）、token 文件、启动脚本、`secret_guard` 包目录和 `--protect` 追加的路径。

**沙箱权限配置（主要机制）。** 脚本定义权限配置 `secret_guard`，继承内置的 `:workspace`，并把每个受保护路径设为 `none`，再设为默认配置：

```toml
[permissions.secret_guard]
extends = ":workspace"
[permissions.secret_guard.filesystem]
"/absolute/path/state" = "none"
"/absolute/path/run-01.token" = "none"
default_permissions = "secret_guard"
```

Codex 用 macOS seatbelt 沙箱运行模型发起的每条 shell 命令，读取禁令由内核执行，和命令怎么写无关。实测运行时拼接路径、符号链接、`cp`、`ls` 都得到 `Operation not permitted`。这一点比 Claude Code 的 hook 强：Claude Code 没有等价的读取禁令，只能检查工具参数。

MCP bridge 由 Codex 自身在沙箱外启动，所以仍能读到 token 文件。

**PreToolUse hook（补充）。** Codex 0.166.0 的 hooks 功能为 stable，输入输出格式与 Claude Code 相同，脚本注册的是同一个 `secret_guard/claude_hook.py`，规则见 [claude-code.md](claude-code.md)。它在沙箱之外多挡一层，并拒绝运行 `secret-guard` 可信 CLI。

### 限制

- **hook 在 Codex 下未实测。** 本机 Codex 的工具执行当前不可用：不带任何 Secret Guard 配置的 `codex exec` 执行 shell 命令也报 `timed out negotiating with the code-mode host`，因此没有一次真实的模型工具调用可以用来验证 hook 是否触发，也没有验证经 MCP 的完整闭环。Codex 可能要求先在 `/hooks` 里信任该 hook 才运行它。在这之前，Codex 的第 1 层应视为只靠沙箱。
- 沙箱只约束模型发起的命令。加了 `-s danger-full-access` 或 `--dangerously-bypass-approvals-and-sandbox` 就没有这层保护。交互模式下模型可以申请让某条命令脱离沙箱，批准与否由用户决定，不要批准读取受保护路径的命令。
- 读取禁令的实测只在 macOS 上做过。Linux 上 Codex 用 Landlock 和 seccomp，未验证。
- 其他 MCP 服务器、Codex 的 hosted 工具不经过沙箱。
- 沙箱和 hook 都在 agent 所在的 OS 账户内配置。有意绕过整个 Codex 的进程不在防护范围内，本产品不提供沙盒。

## 第 2 层：通过 MCP 使用密码

脚本注册 `secret_guard` MCP 服务器，工具和闭环与 [README](../README.md) 相同。身份粒度是独立 MCP 进程的 broker task，每次任务单独 `task-create` 和 `codex-config`，结束后 `revoke task` 并删除 token 和脚本。
