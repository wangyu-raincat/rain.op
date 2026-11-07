# PromptInjectionWatch（提示注入检测）

> 方向：监测 / 审计向 · AI 安全
> 关键词：**提示注入检测、Agent 安全、工具调用审计**

读 LLM 应用的对话 / 调用日志（JSONL），用规则 + 打分检出提示注入并分级（高 / 中 / 低），输出检测报告；可当作 agent 安全评测的基线工具。

## 背景

提示注入（Prompt Injection）已进入 **MITRE ATT&CK 的 AI 攻击技术**（ML 模型攻击矩阵）：攻击者把恶意指令藏进用户输入、文档、网页或工具返回里，诱使模型违背原始指令——套取系统提示词、执行危险工具调用、外发数据。对 Agent 来说，注入不只是"说错话"，而是**工具调用劫持**的入口，所以检测要和工具调用审计放在一起做。

## 检测维度

| 维度 | 检出什么 |
| --- | --- |
| 指令覆盖 | "忽略以上指令""从现在开始执行我的新指令"类 |
| 角色劫持 | 冒充 system / 开发者 / 管理员，"切换到开发者模式" |
| 分隔符伪造 | 伪造 ```system、[SYSTEM]、\|im_start\| 等分隔符，伪造系统消息 |
| 敏感信息套取 | 套取系统提示词、API Key、内部指令 |
| 越狱模板 | DAN、"无限制模式"、"假设你没有任何限制" |
| 工具调用劫持 | 诱导调用 shell、删文件、外发数据（shell_exec / curl / send_email 等） |
| 间接注入 | 恶意指令藏在文档 / 网页 / 工具返回里（source 为 doc / web / tool_output 时额外加权） |

每条命中给出规则名和分数；总分 ≥ 50 为高危，≥ 25 为中危，其余为低危。

## 快速开始

```bash
python promptwatch.py --demo
```

演示用自带 `sample_log.jsonl`（12 条：正常请求、直接注入、间接注入、越狱模板、工具调用劫持），预期输出：

```text
分析日志: 12 条 | 命中: 7 条 | 最高分: 120
分级: 高危 5 条 | 中危 0 条 | 低危 2 条
[1] [高危] 分数 120  id=005 role=user source=doc
    维度: 分隔符伪造、工具调用劫持、间接注入（藏在外部内容里）
    规则: delimiter-forgery, tool-call-hijack, indirect-injection, dangerous-tool-call, untrusted-source
...
```

检出高危条目时返回退出码 1（方便接 CI / 定时巡检），否则返回 0。

## 用自己的日志

日志为 JSONL，每行一条：

```json
{"id": "001", "ts": "2026-11-05T09:00:00", "role": "user",
 "content": "...", "source": "chat", "tool_calls": []}
```

- `role`：user / assistant / tool / system
- `source`：chat（直接对话）/ doc（文档内容）/ web（网页内容）/ tool_output（工具返回）
- `tool_calls`：本条触发的工具调用，如 `[{"name": "shell_exec", "args": {...}}]`

```bash
python promptwatch.py -i mylog.jsonl
python promptwatch.py -i mylog.jsonl -o report.json   # 报告写成 JSON
```

## 局限

- 规则匹配是启发式：会误报（如正常讨论"忽略指令"这个话题）、也会漏报（改写、编码、拆分后的注入）。
- 适合做**评测基线 / 巡检初筛**，高危条目仍需人工复核；生产上应与人工审批点、工具白名单、最小权限配合使用。

## 文件

- `promptwatch.py` — 主程序（纯标准库）
- `sample_log.jsonl` — 演示日志（12 条）
- `requirements.txt` — 无第三方依赖
