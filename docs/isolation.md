# OS 隔离部署

日期：2026-11-11。对应设计第 4 节信任边界、第 9 节第二阶段中的“凭据和 worker 隔离、受控出网、假凭据绕过测试”，以及第 10 节验收表的第 2、3、6 行。清洗工作区和严格消息保护仍未实现。

## 机制选择

| 方案 | 结论 | 原因 |
|---|---|---|
| 两个同用户进程（v0.1 现状） | 不成立 | agent 可直接读 vault key、数据库和审批浏览器状态 |
| 独立系统用户 | 未采用 | 需要管理员权限建用户；不解决出网和审批端口可达问题 |
| macOS `sandbox-exec` | 未采用 | 已被 Apple 标记弃用，仅 macOS 可用，仍是同一用户，规则易漏 |
| **容器：broker 与每个 worker 分属不同容器** | **采用** | 文件系统、进程、网络、用户四个命名空间同时分开；macOS 和 Linux 行为一致；与设计第 4 节“独立 VM/容器”一致 |
| 每个 worker 一台独立 VM | 后续可选 | 边界更强，成本更高；当前接口（socket + 每任务 token）换成 VM 不需要改协议 |

## 边界结构

```text
可信宿主（审批浏览器、guardctl、Docker 控制权）
  │ 127.0.0.1:8766（仅宿主 loopback）
  ▼
broker 容器 ── sg-state 卷（vault.key、guard.sqlite3；只有 broker 挂载）
  │ agent.sock（sg-agent 卷，Unix socket，仅 agent 角色路由）
  ▼
worker 容器（每任务一个）── 只读挂载 agent.sock 与本任务 token；默认无网络
  │ 可选：worker-net（internal）
  ▼
egress 容器 ── 默认拒绝的 CONNECT 白名单代理
```

- **凭据路径**：vault key 和数据库在 `sg-state` 卷，只挂载进 broker。worker 的挂载表里没有它。
- **agent 通道**：agent API 只在 Unix socket 上监听，没有 TCP 端口。task token 不经过任何网络。socket 权限 0660，属组 `sgagent`；worker 以只读方式挂载。
- **审批通道**：审批 listener 只在 broker 容器内，发布到宿主 `127.0.0.1`。worker 没有到它的路由；socket 上也没有审批、配对或导出路由。Host/Origin 仍固定校验 `127.0.0.1:<port>`。
- **任务身份**：`guardctl run` 在 broker 域内创建 task，token 写入该任务专属子目录，worker 只挂载自己的子目录。worker 退出时撤销 task 并删除 token。一个 worker 容器对应一个 task。
- **worker 加固**：非 root（uid 10002）、丢弃全部 capability、`no-new-privileges`、只读根文件系统、`/tmp` 与 HOME 为 tmpfs、pid 上限。不继承宿主环境变量，不挂载宿主 HOME、Docker socket、SSH agent。
- **出网**：默认 `--network none`。加 `--egress` 时 worker 只在 internal 网络上，唯一出口是 `egress` 代理：只接受 `CONNECT host:443`，主机名必须精确命中 `SG_EGRESS_ALLOW`，解析出的所有地址必须是公网地址，并连接到已检查的那个地址。

## 使用

所有命令在可信宿主上执行。配置都在仓库的 `isolation/` 目录内。

```sh
isolation/guardctl up                      # 构建镜像并启动 broker
isolation/guardctl broker secret-add github-ci --user alice --project payments --repo acme/payments
isolation/guardctl broker device-register --user alice --device device_xxx --jwk-file /dev/stdin < device.json
isolation/guardctl run --user alice --project payments --workspace /path/to/project -- <agent 命令>
isolation/guardctl broker activity
isolation/guardctl down                    # 停止；destroy 会连同 vault 一起删除
```

审批页面仍是 `http://127.0.0.1:8766`（可用 `SG_APPROVAL_PORT` 修改）。worker 内的 MCP 配置：

```sh
python -m secret_guard.cli mcp --url "$SECRET_GUARD_URL" --token-file "$SECRET_GUARD_TOKEN_FILE"
```

`guardctl run` 会设置这两个变量（`unix:///run/secret-guard/agent/agent.sock` 与 `/run/secret-guard/task/token`）。

需要模型 API 等出网时：

```sh
SG_EGRESS_ALLOW=api.example.com isolation/guardctl up --egress
isolation/guardctl run --egress --user alice --project payments -- <agent 命令>
```

自带 agent 的镜像用 `--image` 指定，镜像内需要安装 `secret_guard` 包；worker 固定以 `10002:10002` 加附加组 `10003` 运行，不依赖镜像里的用户定义。`--workspace` 目录必须能被运行 Docker 的宿主账号读取。

## 绕过测试

`isolation/bypass_probe.py` 在 worker 内扮演恶意 agent，每项都是真实尝试（open、connect、write），不是读配置。`tests/test_isolation.py` 用一次性 compose 项目、合成 canary 和假上游运行它。

| 尝试 | 结果 |
|---|---|
| 读取 vault key、数据库、状态目录内的明文标记 | 路径不存在，读取失败 |
| 全文件系统扫描 canary（约 5400 个可读文件） | 未命中 |
| 读取其他进程的 environ/cmdline，查找 broker 进程 | broker 进程不可见，无 canary |
| 宿主环境变量中的 canary 是否进入 worker | 未进入 |
| 挂载表中的状态卷、Docker socket；宿主 HOME、其他任务目录 | 均不存在；只能看到本任务的 token |
| 改写 adapter 源码、socket 目录、token、根文件系统；删除 socket | 全部被拒绝 |
| 提权：setuid(0)、capability | uid 10002，CapEff/CapBnd 为 0，NoNewPrivs=1 |
| TCP 连接审批端口（loopback、broker、host.docker.internal、网关等） | 全部不可达 |
| 直接出网（TCP、UDP DNS、外部域名解析） | 全部失败 |
| 经 agent socket 调用审批、配对、导出路由，或附加 `approved=true` | 全部 403/404，请求保持 pending，无引用 |
| 经代理访问白名单外主机、宿主审批端口、元数据地址、非 443 端口、明文 GET | 全部被代理拒绝 |

**对照组**：同一个探针在 broker 容器内运行时，能读到 vault key、数据库并扫出明文标记。这说明 worker 内的“未命中”来自边界，而不是探针看不见。

**功能验证**：两阶段闭环在边界两侧跑通。worker 内的 MCP bridge 经 socket 申请引用和 workflow，宿主侧设备密钥经发布端口签名批准，假上游返回结果；全程输出不含 canary。

## 不在保证范围内

- **控制 Docker 的宿主账号属于可信域。** 能访问 Docker socket 的宿主进程可以 `docker exec` 进 broker。边界只对通过 `guardctl run` 启动的 agent 成立；直接在宿主上运行 agent 不受保护。
- **容器共享同一个 Linux 内核。** 在 macOS 上所有容器位于 Docker Desktop 的同一台 VM 内，broker 与 worker 之间是命名空间隔离，不是 VM 隔离。容器逃逸和内核漏洞不在范围内。
- **工作区原样挂载。** 工作区里的 `.env`、git 历史等对 agent 可见；清洗工作区（设计 3.1）未实现。
- **白名单内的主机可以收到 agent 发出的任何数据**；agent 自己的模型 API 凭据在 worker 内。出网控制是主机级别，不检查内容。
- **任务身份粒度是一个 worker 容器**，不能区分容器内的 thread、fork 或子 agent。
- 审批浏览器 profile 在宿主上，worker 看不到；宿主上同用户的其他进程仍可读取。
- 2026-10-24 审查确认的 TLS 握手阻塞和 TCP 路径上的 MCP 重定向问题未在此处修改。socket 路径使用不跟随重定向的 `http.client`。
