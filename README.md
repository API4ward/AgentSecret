# Secret Guard for Codex

可运行的 **MCP 兼容版 v0.1**：受信任 broker 保存凭据，Codex 仅持有任务 token 和批准后获得的不透明引用。独立审批设备对冻结操作签名，broker 在执行前复验签名、策略、凭据版本和 adapter 源码摘要，并原子消费一次性许可。

实现依据：[产品设计](codex-secret-guard-product-design.md)。本版覆盖其第一条只读 GitHub 闭环；[实现与验收状态](docs/implementation.md)说明已验证和未实现的部分。

## 安装与测试

需要 Python 3.11+；本机验证使用 Python 3.14.6。本版 daemon 单实例锁使用 POSIX `fcntl`，支持 macOS/Linux。

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
.venv/bin/python -m pip install --no-build-isolation --no-deps .
.venv/bin/python -m unittest discover -v
```

所有测试使用合成凭据和假上游。不会要求真实 GitHub token，不调用模型 API。

可用 `.venv/bin/python -m examples.demo` 启动完整假凭据演示。审批页为 `http://127.0.0.1:8876`，agent API 为 8875；它会输出临时状态目录和 task token 文件路径并预先创建引用请求。配对用户填 `demo`，凭据 alias 为 `demo-github`，仓库为 `demo/example`。演示 transport 完全不访问 GitHub；停止后用 revoke 撤销演示设备，避免将同一浏览器 origin 的设备密钥用于真实部署。

## 建立受信任 broker

在可信桌面终端执行，凭据通过隐藏输入读取，不放入命令参数。默认状态目录为 `~/.local/share/secret-guard`，目录权限 0700，vault key 与 SQLite 文件权限 0600。AES-256-GCM 绑定 alias 与版本。密钥和数据库位于同一可信宿主，磁盘加密和宿主权限仍由操作系统负责。

```sh
.venv/bin/secret-guard init
.venv/bin/secret-guard secret-add github-ci \
  --user alice --project payments --repo acme/payments
.venv/bin/secret-guard serve
```

GitHub 凭据应仅拥有目标仓库的 Actions read 权限。唯一 adapter 固定执行 `GET https://api.github.com/repos/{owner}/{repo}/actions/runs`，固定 headers 与 API 版本 `2026-03-10`，禁止自定义 URL、认证 header、代理、重定向及自动重试。返回仅包含 workflow 数字 ID、状态和结论；外部自由文本不透传。

agent API 在 `http://127.0.0.1:8765`，审批页面在 `http://127.0.0.1:8766`。两端路由与认证分离；无注册设备、修改策略或导出凭据的 HTTP 接口。状态查询不会触发执行，后台 executor 执行已批准操作。

## 配对审批设备

1. 在独立可信浏览器打开 `http://127.0.0.1:8766`，点击“生成设备密钥”。私钥通过 WebCrypto 生成，标为不可导出并保存在该 origin 的 IndexedDB。
2. 展开“桌面配对信息”，核对设备编号。将其中 `jwk` 对象保存到 `device.json`；文件只包含公钥。
3. 在可信桌面终端登记，随后页面点击“连接已注册设备”。没有此桌面步骤，页面不能自注册。

```sh
.venv/bin/secret-guard device-register \
  --device device_页面显示的编号 --user alice --jwk-file /absolute/path/device.json
```

浏览器使用 P-256/SHA-256，签名编码为 WebCrypto 的 64 字节 `r || s`；服务端严格校验。登录使用 60 秒的一次性 challenge，审批 session 5 分钟到期。批准和拒绝都签名，签名用途域不同于登录用途域。

**手机远程访问**需要可信 HTTPS origin。`serve --host guard.example.com --cert /path/cert.pem --key /path/key.pem` 要求该域名解析为宿主绑定地址，访问 `https://guard.example.com:8766`；默认无 TLS 时拒绝非 loopback 绑定。agent 端口也会绑定该地址，部署时应由网络规则仅允许可信 worker 访问 agent 端口。此原型没有推送、原生 App、passkey、生物识别验证或反向代理适配。浏览器设备密钥证明持有密钥，不能证明每次签名都经过硬件用户验证。

## 为一次任务建立 MCP 连接

每个 broker task 单独生成 token 文件；该 token 只能申请操作，不能批准或读取明文。身份来自可信 CLI，模型不能通过提交 user/project/task_id 改变身份。

```sh
.venv/bin/secret-guard task-create --user alice --project payments \
  --token-file /absolute/path/run-01.token
```

在该次独立 Codex 运行的专用配置中填入如下内容。路径必须为绝对路径。不要把 broker 的 vault、状态目录或审批浏览器 profile 挂载给 worker。

```toml
[mcp_servers.secret_guard]
command = "/absolute/path/AgentSecurity/.venv/bin/python"
args = ["-m", "secret_guard.cli", "mcp", "--token-file", "/absolute/path/run-01.token"]
cwd = "/absolute/path/AgentSecurity"
```

Codex 官方支持 [STDIO MCP 配置](https://learn.chatgpt.com/docs/extend/mcp)。本仓库提供协议实现和接入示例，未修改你的全局 Codex 配置。不要将同一配置/token 用于多个 Codex 任务。此兼容版的身份粒度是**独立 MCP 进程的 broker task**，无法认证官方客户端内部 thread/fork/subagent 身份；同一进程内创建新任务、fork 或子 agent 的独立权限隔离仍待运行时适配。因此它不能用共享全局 MCP 配置兑现逐原生任务隔离承诺。

闭环调用：

```text
guard.request_reference({"alias":"github-ci"})
  → pending + operation_id
  → 在审批设备批准“允许本任务引用”
guard.operation_status({"operation_id":"…"})
  → approved + secretref://…
guard.github_workflow_runs({"ref":"secretref://…","repo":"acme/payments","limit":10})
  → pending + operation_id
  → 在审批设备核对完整请求并批准一次
guard.operation_status({"operation_id":"…"})
  → executing / succeeded / unknown
```

引用在任务内最长 8 小时，操作审批 2 分钟有效，task 最长 8 小时。凭据策略绑定 user、project、repo 和唯一固定 adapter。相同 pending 请求合并；拒绝在同一任务内保持，不因模型重试再弹窗。最多 20 个 pending/approved 请求。`unknown` 不会重执行，需要用户核对；如要重新申请，必须产生新的人工授权。

## 可选：隔离部署（broker 与 agent 分属不同容器）

隔离部署是可选模式，不需要 Docker 也能按上面的本机流程使用全部功能，默认行为没有变化。区别在于保证范围：本机流程中 broker 和 agent 同属一个用户，agent 可以直接读 vault。需要这条边界时，改用 `isolation/` 下的容器部署：broker 独占状态卷，每个任务的 agent 运行在无网络、非 root、只读根文件系统的 worker 容器里，只能通过一个 Unix socket 调用 agent API。

```sh
isolation/guardctl up
isolation/guardctl broker secret-add github-ci --user alice --project payments --repo acme/payments
isolation/guardctl run --user alice --project payments --workspace /absolute/path/project -- <agent 命令>
```

worker 内的 MCP 命令为 `python -m secret_guard.cli mcp --url "$SECRET_GUARD_URL" --token-file "$SECRET_GUARD_TOKEN_FILE"`。结构、出网白名单、绕过测试结果和不在保证范围内的事项见 [OS 隔离部署](docs/isolation.md)。

## 撤销与审计

```sh
.venv/bin/secret-guard activity
.venv/bin/secret-guard revoke task task_...
.venv/bin/secret-guard revoke operation op_...
.venv/bin/secret-guard revoke device device_...
.venv/bin/secret-guard revoke secret github-ci
```

再次 `secret-add` 更新凭据时递增版本并撤销旧引用与待执行审批。操作在事务中进入 executing 后视为已经开始，之后撤销不能保证取消外部请求。重启将 executing 恢复为 unknown，不恢复许可。审计只记录状态事件和随机任务/请求标识，不记录凭据、参数、返回原文或异常详情。

## 保证范围

已实现受支持 broker 路径中的凭据代理与精确操作授权；结果整体缓冲、校验后才返回。对登记值和常见 base64/hex/URL 编码进行泄漏检查，再通过极小结果 schema；这不构成任意编码检测保证。

**尚未实现严格版**：清洗工作区、输入/附件/原生工具输出过滤、Codex 内核及持久化/压缩/fork 适配。worker/broker OS 隔离与受控出网仅在[隔离部署](docs/isolation.md)下成立；不使用隔离部署时，相同用户权限的 agent 仍可能读取 broker 文件或审批浏览器状态，不能声称“所有消息永不泄漏”或抵御已控制宿主/审批设备的攻击者。请以假凭据验证此原型；真实部署必须先建立设计文档规定的安全域。详见 [实现状态](docs/implementation.md)。
