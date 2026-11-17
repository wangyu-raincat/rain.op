# AgentLeakWatch —— agent 敏感信息外泄审计

**rain.op Day 42 · 监测向。审计 agent 轨迹里的敏感信息外泄：凭据、个人身份信息、系统提示、内网资产、敏感文件内容。**

agent 的调用链可以完全合规，但一条工具结果里带出的密钥、一个手机号、一段系统提示，照样会顺着推理与最终回答漏出去。AgentLeakWatch 就是事后审计这件事：读 agent 的运行轨迹，定位“哪里漏的、漏给了谁”，按会话打 0–100 风险分。

## 它和仓库里其他 agent 的关系

| agent | 分工 |
| --- | --- |
| Day 34 MCPGuard | 调用时拦截：危险调用当场拦下 |
| Day 40 ToolChainWatch | 事后审计调用链：调用顺序有没有“走偏” |
| **Day 42 AgentLeakWatch（本工具）** | 事后审计内容：输出里有没有不该出现的东西 |
| Day 36 AgentIncidentDesk | 事件台账：汇总各类异常事件出日报 |

四个工具可以串起来用：MCPGuard 负责事前拦截，ToolChainWatch 与 AgentLeakWatch 分别从“链”和“内容”两个角度做事后审计，检出的高危事件再进 AgentIncidentDesk 的台账。

## 快速上手

```bash
python leakwatch.py --demo
```

演示是一条被植入 5 类外泄的轨迹（5 条记录），预期输出高危评级：

```text
AgentLeakWatch 外泄审计报告 · 来源：内置演示轨迹
记录总数：5 · 风险分：100/100 · 评级：高危
结论：已确认外泄或高危凭据进入输出：立即轮换涉事凭据，冻结相关 agent 的外部调用并人工复核整条轨迹
检出 7 条告警：
[1] [高危] secret_leak（+40 分）
[2] [高危] secret_leak（+50 分）
[3] [中危] pii_leak（+25 分）
[4] [高危] pii_leak（+35 分）
[5] [中危] system_prompt_leak（+30 分）
[6] [中危] internal_asset_leak（+20 分）
[7] [高危] file_content_leak（+45 分）
```

高危时按设计返回退出码 1；出现此退出码表示检出高危外泄。

审计自己的轨迹：

```bash
python leakwatch.py -i trace.jsonl
python leakwatch.py -i trace.jsonl --json report.json   # 报告写成 JSON
python leakwatch.py -i trace.jsonl --strict             # 严格模式：低危也计入风险分
```

自带示例轨迹 `sample_trace.jsonl` 与演示内容相同，可直接跑：

```bash
python leakwatch.py -i sample_trace.jsonl
```

## 轨迹格式（JSONL，每行一条记录）

```json
{"ts": "2026-11-17T09:00:01", "agent": "researcher", "kind": "tool_result", "tool": "read_file", "channel": "internal", "text": "..."}
```

| 字段 | 说明 |
| --- | --- |
| `kind` | `tool_call`（一次工具调用）/ `tool_result`（工具返回）/ `reasoning`（中间推理）/ `final_answer`（最终回答） |
| `channel` | `internal`（只在内部流转）/ `external`（已发往外部：发给用户、调外部 API、写公开渠道）。外泄到 `external` 的告警分数上浮、级别升一级 |
| `tool` / `args` | 工具名与参数；`tool_call` 的 `args.path` 用于判断是否读了敏感文件 |
| `text` / `result` | 待审计的文本内容 |

## 五组检测规则

| 规则 | 检出内容 | 基础分 |
| --- | --- | --- |
| `secret_leak` | AWS Key、`sk-` 密钥、GitHub/Slack 令牌、私钥 PEM 头、明文密码、Bearer 令牌 | 40 |
| `pii_leak` | 身份证号、手机号、邮箱、银行卡号（形态匹配） | 25 |
| `system_prompt_leak` | 最终回答/推理复述系统提示或内部指令片段 | 30 |
| `internal_asset_leak` | 内网 IP、内部域名、内网 URL、SSH 目录与系统敏感文件路径 | 15 |
| `file_content_leak` | 先读敏感文件，后续输出出现同一来源的敏感内容 | 35 |

风险分按会话汇总（上限 100）：≥70 高危，40–69 中危，>0 低危，0 正常。默认模式下低危不计入风险分，`--strict` 会计入。

## JD 关键词

数据外泄防护（DLP）、提示注入防御、最小权限、工具调用审计、人工审批点、审计留痕、Agent 工程化落地、评测通过率。适合作为 agent 上线前的安全审计环节：跑一遍历史轨迹，确认没有凭据与个人信息随输出外泄，再放行。

## 边界与提醒

- 正则匹配只认形态，可能误报：示例密钥、测试数据、文档里的占位值都会命中，复核时先看上下文再定性。
- PII 只做形态匹配，不校验号码真实性；身份证、手机号等示例均为虚构占位值。
- 审计结论只针对输入的这一条轨迹，不代表 agent 本身可信或不可信；高危结论的下一步永远是人工复核，不是自动封禁。
- 本工具只读轨迹文件做分析，不发起任何网络请求，不调用外部 API。
