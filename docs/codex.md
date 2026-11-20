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

**PreToolUse / PostToolUse hook（补充）。** Codex 0.166.0 的 hooks 功能为 stable，输入格式与 Claude Code 相同，输出格式有差别（见下文），脚本注册的是同一个 `secret_guard/claude_hook.py`，规则见 [claude-code.md](claude-code.md)。它在沙箱之外多挡一层，并拒绝运行 `secret-guard` 可信 CLI。

### 限制

- **hook 已在真实 Codex 会话里实测**：2026-11-19 在 Linux 容器里（见 [e2e-docker.md](e2e-docker.md)），2026-11-20 在 macOS 本机（codex-cli 0.166.0）。结论见下一节。
- 沙箱只约束模型发起的命令。加了 `-s danger-full-access` 或 `--dangerously-bypass-approvals-and-sandbox` 就没有这层保护。交互模式下模型可以申请让某条命令脱离沙箱，批准与否由用户决定，不要批准读取受保护路径的命令。
- Linux 上 Codex 的沙箱依赖 bubblewrap 和用户命名空间。读取禁令已在 Docker 容器里实测有效，但容器要加 `--security-opt seccomp=unconfined`，否则沙箱起不来、命令无法执行。
- 其他 MCP 服务器、Codex 的 hosted 工具不经过沙箱。
- 沙箱和 hook 都在 agent 所在的 OS 账户内配置。有意绕过整个 Codex 的进程不在防护范围内，本产品不提供沙盒。

## hook 在真实 Codex 里的表现

2026-11-20 用真实 `codex exec` 会话和测试值 `18year` 验证，可用 `AGENTSECRET_REAL_CODEX=1 python -m unittest tests.test_scenarios` 重跑。

- **Codex 不运行未被信任的 hook，也不提示。** 用 `-c` 传入的 hook 在 `codex exec` 里没有地方可以信任，所以启动脚本带上 `--dangerously-bypass-hook-trust`。不带它时 hook 一次都不会被调用，密码原样到达模型。
- **Codex 不接受 `updatedToolOutput`。** 它把这种回答判为无效（`PostToolUse Failed`），然后把原始结果交给模型。它接受的是 `{"decision":"block","reason":…}`：`reason` 会取代工具结果。hook 带 `--agent codex` 时按这种格式回答，批准后模型看到 `{{secretref:别名}}`，拒绝或 hook 出错时看到“已扣留”。
- **填入可用。** shell 命令和 `apply_patch` 里的引用都会触发 fill 审批，批准后经 `updatedInput` 换成密码再执行。
- **没有挡住的：**
  - 输出被变形后匹配不到。实测 `rev example/qa.txt` 不触发审批，模型自己把它还原出了密码。base64、逐字符拆开等同理。匹配器只认原样的字节。
  - Codex 自己把命令的原始输出和填入后的命令写进 `~/.codex/sessions/` 下的会话记录（`event_msg`），终端里也会显示。交给模型的那一份（`response_item`）只有引用。
  - 路径规则有误拦：`sed 's/./&_/g' example/qa.txt` 被判成“触及受保护路径”而拒绝。

## 第 2 层：通过 MCP 使用密码

脚本注册 `secret_guard` MCP 服务器，并设 `default_tools_approval_mode="approve"`（否则 `codex exec` 会拒绝所有 MCP 调用；真正的审批在独立设备上），工具和闭环与 [README](../README.md) 相同。身份粒度是独立 MCP 进程的 broker task，每次任务单独 `task-create` 和 `codex-config`，结束后 `revoke task` 并删除 token 和脚本。
