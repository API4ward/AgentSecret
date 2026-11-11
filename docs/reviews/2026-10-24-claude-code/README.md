# Claude Code 独立验证与本地复核

日期：2026-10-24。工具：Claude Code 2.1.287；官方连接实际报告模型为 `claude-sonnet-5-5`。审查范围为本仓库源码、测试及产品说明的临时副本；19 个文件与 [SHA-256 清单](source-manifest.json)一致。实现源码未修改。

## 结论

Claude Code 自行运行原有测试，**26/26 PASS，耗时 1.361 秒**；审查范围内未找到已证实的两阶段授权绕过。这不能证明不存在漏洞。它提出的额外问题最初来自静态分析，原始报告明确标记了未执行项。随后 Codex 用合成数据和本地服务复核如下：

| 项目 | 本地复核结果 | 影响与范围 |
|---|---|---|
| F1：TLS 握手阻塞 | **确认**。正常 HTTPS 请求先返回 200；另开一个 TCP 连接但不发送 ClientHello，合法客户端超时；关闭该连接后恢复 200 | 可连接端口的未认证请求方可阻塞对应监听器。`server.py:111` 在监听 socket 上使用默认同步握手且无超时 |
| F2：MCP 重定向 | **确认**。源服务器返回 302，第二个本地服务器收到转发的 `Authorization: Bearer SYNTHETIC_TASK_TOKEN` | 泄露的是任务 bearer token，非 vault 中的原始凭据。需要配置的 broker 端返回重定向；其本来就接收此 token，因此不能据此声称任意第三方可窃取真实密码。`mcp.py:26-33` 的默认 redirect handler 仍先运行 |
| F4.1：撤销不存在的任务 | **确认**。不报错、静默返回成功 | 操作者拼错标识时可能误以为已撤销 |
| F4.2：凭据字符集 | **确认入库部分**。含空格的合成 token 被接受 | adapter 明确拒绝此字符集；本次未额外完成该 token 的完整审批/网络执行 |
| 跨请求使用签名 | **正确拒绝**：`signature_invalid` | 补足 Claude 指出的测试缺口，使用同一用户/项目下两个独立 task 的请求 |
| 把 deny 签名用于 approve | **正确拒绝**：`signature_invalid` | 签名用途绑定有效 |

原始 Claude 报告的 F2 示例使用 307；本地复核使用 **302 + POST 转 GET**，实际确认 Authorization 被转发。两者不能当作相同的已执行实验。

F3 的“阶段 2 未签入 ref id”属于加固建议：当前 ref 保存在可信数据库且仍做任务、凭据版本、有效期和撤销校验；未证实外部攻击者可借此绕过授权。其余静态问题和兼容性猜测保留原始置信度，不计为已复现漏洞。

## 证据与复现

- [Claude 原始报告](claude-report.md)：保留原始内容，额外实验的“未执行”状态对应 Claude 自身执行范围。
- [Claude 执行证据](execution-evidence.json)：实际模型、唯一 Bash 命令、测试原始输出；最终会话 permission_denials 为空。
- [审查提示](review-prompt.txt)：范围、禁止读取凭据/环境、不得改源码、唯一允许命令等约束。
- [父审查者复现脚本](parent_reproductions.py)与[实际结果](parent-reproduction-results.json)：仅使用 loopback、临时目录、合成 token 和临时自签测试证书；客户端显式信任此证书，未关闭证书校验。

从仓库根目录复现补充检查：

```sh
PYTHONPATH=. .venv/bin/python docs/reviews/2026-10-24-claude-code/parent_reproductions.py
```

脚本会启动临时 HTTP/TLS 监听器，通常需允许本地网络绑定。结束时关闭监听器并移除临时证书、数据库。两项主要问题**尚未修复**；报告不是修复后回归证明。

## 尚未验证

真实 Codex MCP 调用、真实 GitHub/API TLS、跨设备手机、浏览器重测和 OS 运行时隔离均未在此次审查中验证。原有 26 项测试包含 stub transport，因此不能证明凭据在真实端到端系统所有数据出口中均不可见。

首次 Claude Code 使用既有火山引擎配置，因 CodingPlan 订阅失效未执行审查。最终进程仅临时移除了第三方 provider/token/model 覆盖，使用既有官方 OAuth；全局配置和凭据未修改。一次授予不受限 Bash 的尝试被自动审批以超出验证范围、可触及无关文件为由拒绝；最终采用 Read/Glob/Grep 和唯一固定 unittest 命令完成审查，未绕过该拒绝。
