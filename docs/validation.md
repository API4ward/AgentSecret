# 本地验收记录

日期：2026-09-28。环境：macOS、Python 3.14.6、cryptography 46.0.5、Codex CLI 0.151.0。

| 检查 | 结果 | 证据范围 |
|---|---|---|
| `python -m unittest discover -v` | **26/26 PASS** | 合成凭据、假 transport；含两个 ephemeral HTTP listener |
| 独立浏览器设备生成、公钥桌面登记、WebCrypto 签名登录 | PASS | Codex in-app browser 实际点击；P-256 非导出私钥存 IndexedDB |
| 第一阶段引用卡片、签名批准、返回引用 | PASS | 合成 `demo-github`，独立 broker task |
| MCP HTTP bridge 发起 workflow 请求 | PASS | `guard.github_workflow_runs` 固定 `demo/example` |
| 第二阶段完整冻结请求显示、签名批准 | PASS | 实际浏览器显示 host/path/query/digests/nonce/expiry 后批准 |
| 后台 executor 完成并返回结果 | PASS | `succeeded`；workflow ID 101，completed/success；无 GitHub 网络调用 |
| 重复执行已成功操作 | PASS | `execute(operation_id)` 返回 false |
| 页面截图视觉检查 | PASS | 桌面窗口中卡片、详情和批准/拒绝按钮可读，无重叠 |
| `node --check secret_guard/web/app.js` | PASS | JavaScript 语法 |
| Python compileall | PASS | broker、CLI、MCP、server、tests、demo |
| wheel 构建与静态资源检查 | PASS | wheel 含所有模块和 html/js/css |
| 安装后 CLI 从项目外运行 `--help` | PASS | 标准安装模式；无需依赖当前目录 |

本机 editable 安装生成的 `.pth` 文件带 macOS hidden 属性，Python 3.14 跳过加载；因此 README 使用标准 wheel 安装，避免依赖 editable finder。源码修改后需要重新安装才能更新已安装 CLI；从项目目录以 `python -m secret_guard.cli` 运行可直接使用源码。

测试不使用真实用户凭据，临时演示设备已撤销，演示 daemon 已停止。真实 GitHub/TLS/跨设备手机联调、真实 Codex 工具调用、OS worker 隔离与严格消息入口矩阵 **NOT_RUN / 尚未实现**；详见 [实现状态](implementation.md)。以上协议测试不能视为完整产品安全认证。

## 2026-11-11 Claude Code 接入

环境：macOS、Python 3.14、Claude Code 2.1.311，实际模型 `claude-sonnet-5-5`。分支 `claude-support`。

| 检查 | 结果 | 证据范围 |
|---|---|---|
| `python -m unittest discover` | **28/28 PASS** | 原 26 项加 MCP 重定向回归、`claude-config` 生成与启动 |
| 重定向回归测试在修复前的 `mcp.py` 上运行 | FAIL（符合预期） | 证明测试能检出 2026-10-24 审查的 F2 |
| `python -m examples.claude_e2e` | PASS | 真实 `claude -p`，按次 `--mcp-config --strict-mcp-config`；合成凭据、假 transport、合成审批设备自动签名 |
| `python -m examples.claude_e2e --subagent` | PASS | 子 agent 用父会话的引用发起操作；broker 审计只有一个 task |
| 合成凭据、task token 不在 Claude Code 输出中 | PASS | 两次运行的完整 stream-json 与 stderr |

结果摘要见 [reviews/2026-11-11-claude-code-e2e](reviews/2026-11-11-claude-code-e2e/)，分析见 [claude-code.md](claude-code.md)。人在审批页面上批准、恢复/分叉/后台 agent、hooks、真实 GitHub 均 **NOT_RUN**。运行未修改全局 Claude Code 配置；它加载了本机用户已有的 Claude Code 设置和登录。

## 2026-11-11 OS 隔离验收

环境：macOS 26.3、Docker 29.2.0（Docker Desktop，arm64）、宿主 Python 3.14.6、镜像 python:3.12-slim。

| 检查 | 结果 | 证据范围 |
|---|---|---|
| `python -m unittest discover -v` | **38/38 PASS** | 合并 Claude Code 接入后的 28 项加 `tests/test_isolation.py` 10 项 |
| 恶意 worker 探针（无网络） | PASS，0 项突破 | 14 项真实尝试：读 broker 状态、全盘扫 canary、进程环境、挂载、篡改、提权、审批端口、直接出网、socket 越权 |
| 恶意 worker 探针（出网代理） | PASS，0 项突破 | 另加 12 个白名单外 CONNECT/GET 请求全部被拒 |
| 对照组：同一探针在 broker 容器内 | 读到 vault key、数据库和明文标记 | 证明探针能发现可读状态 |
| 两阶段闭环跨边界 | PASS | worker 内 MCP 经 socket，宿主设备密钥经 127.0.0.1 发布端口签名，假上游 |
| worker 退出后 task 撤销、token 删除 | PASS | 数据库 `active=0`，任务目录为空 |
| 白名单主机可用性 | PASS（手动） | `SG_EGRESS_ALLOW=example.com` 时经代理完成 TLS 握手；不在自动测试内 |

全部使用合成 canary 和假上游。真实 agent（Codex/Claude）在 worker 内运行、清洗工作区、VM 级隔离 **NOT_RUN / 尚未实现**。
