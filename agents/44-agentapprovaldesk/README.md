# AgentApprovalDesk — 智能体人工审批审计台

> rain.op Day 44 · 监测向 · 对口 JD 关键词：**人工审批点、最小权限、工具调用审计、权限过滤、审计留痕、评测通过率、Agent 工程化落地**

人工审批点是 agent 安全的最后一道闸：删文件、跑 shell、对外发数据、
改配置、轮换密钥这类高危操作，理论上都要先有人点头再执行。但
“批了”不等于“批对了”——自批自审、批完改参、被拒仍执行、批的人
没资格、批完拖太久才执行，都是审批链上真实出现过的绕过形态。
AgentApprovalDesk 读 agent 的审批台账（JSONL），做七组审计，输出
合规率、SLA 达成率与逐条违规清单。

与 Day 34 MCPGuard（调用时拦截）不同：这里是事后审计——调用已经
发生，从台账上定位审批链哪里被绕过、哪一类绕过最常见。
与 Day 40 ToolChainWatch（调用链异常）不同：这里只盯审批环节——
调用链可以完全“正常”，但批的人不对、批的内容被偷换，照样是绕过。
与 Day 36 AgentIncidentDesk（事件台账）不同：这里输出的是一次审批
审计报告，可直接作为台账的一条事件来源；要汇总多类事件、分级与
算 SLA 请用 AgentIncidentDesk。

## 快速上手

```bash
# 内置演示：10 条审批请求，植入 7 类违规
python approvaldesk.py --demo

# 审计自己的台账文件（默认读 sample_approvals.jsonl）
python approvaldesk.py -i approvals.jsonl

# 把报告写成 JSON
python approvaldesk.py -i approvals.jsonl --json report.json

# 审批 SLA 改为 8 小时、批准有效期改为 12 小时
python approvaldesk.py -i approvals.jsonl --sla-hours 8 --ttl-hours 12
```

## 七组审计规则

| 规则 | 含义 | 级别 |
| --- | --- | --- |
| no_approval_exec | 高危操作没有任何批准就执行，审批链被完全绕过 | 高危 |
| self_approval | 审批人与申请人是同一人，自批自审 | 中危 |
| rejected_exec | 审批已拒绝，操作仍被执行，拒绝没有约束力 | 高危 |
| param_drift | 批完改参：执行参数与批准参数不一致，等于批了个空壳 | 高危 |
| unauthorized_approver | 审批人角色不在该操作的审批角色白名单里，越权审批 | 中危 |
| approval_timeout | 审批等待超过 SLA（默认 24 小时）仍未决 | 低危 |
| stale_approval | 批准超过有效期（默认 24 小时）后才执行，拿旧批文办新事 | 中危 |

操作与审批角色的映射（最小权限）见程序内的 `REQUIRED_ROLES`：
删文件/跑 shell 须 sre-lead 或 security-lead 批，读密钥/轮换密钥/
对外发数据须 security-lead（或 data-owner）批；`delete_file`、
`exec_shell`、`send_external`、`rotate_secret`、`read_secret`
五类操作无论台账怎么标都强制要求审批。

## 示例输出

```text
AgentApprovalDesk 审批审计报告 · 来源：内置演示台账
================================================================
审批请求：10 条（已决 8 条） · 风险分：100/100 · 评级：高危
合规率：30.0% · SLA（24h 内决断）达成率：100.0%
结论：审批链存在可被绕过的缺口：立即冻结涉事 agent 的高危操作，
人工复核全部高危告警并补齐审批记录

检出 8 条违规：

[1] [高危] no_approval_exec（+40 分）
    请求 APR-0002（ops-agent 执行 exec_shell，风险 critical）：高危操作
    在没有任何批准的情况下执行，审批链被完全绕过。

[4] [高危] param_drift（+30 分）
    请求 APR-0005：批完改参，执行参数与批准参数不一致
    （path：'/tmp/cache' → '/data/prod.db'）。审批人点头的是 A，
    实际执行的是 B，等于批了个空壳。
```

（以上为默认演示输出节选，`--demo` 共检出 8 条违规；演示里
APR-0008 同时命中越权审批与过期执行两条，属于同一请求的两次违规。）

## 台账格式

JSONL，每行一条审批请求，字段说明：

| 字段 | 含义 |
| --- | --- |
| req_id / agent / action / tool | 请求编号、发起 agent、操作、所用工具 |
| risk | low / medium / high / critical |
| requested_by / approved_by / approver_role | 申请人、审批人、审批人角色 |
| status | approved / rejected / pending / expired / executed_without_approval |
| requested_at / decided_at / executed_at | 申请 / 决断 / 执行时间（ISO 8601） |
| approved_params / executed_params | 批准参数 / 实际执行参数（比对用） |
| requires_approval | 该操作是否要求审批（五类高危操作恒为 true） |

`sample_approvals.jsonl` 就是演示用的同一份台账，可直接拿去改。

## 与 rain.op 其他 agent 的配合

- 调用时拦截与白名单见 Day 34 **MCPGuard**；
- agent 安全评测与通过率见 Day 35 **AgentEvalBench**；
- 异常事件台账与 SLA 见 Day 36 **AgentIncidentDesk**；
- 智能体治理与合规见 Day 37 **AgentGovQA**；
- 工具调用链异常检测见 Day 40 **ToolChainWatch**；
- 敏感信息外泄事后审计见 Day 42 **AgentLeakWatch**；
- 智能体隐私与数据治理见 Day 43 **AgentPrivacyQA**。

## 边界与说明

- 纯标准库，离线运行，不调用任何外部 API；演示数据均为虚构占位值，
不对应任何真实人员或真实操作。
- 审计结论只针对这份台账：台账本身若缺记录（如未记 `executed_at`），
漏检的违规不会出现在这里，先保证台账完整再谈合规率。
- 同一请求命中多条规则时按规则分别计分、风险分封顶 100；合规率按
“未命中任何违规的请求占比”计算。
- 审批角色白名单与 SLA/有效期默认值是示例工程实践，具体落地时按
组织制度调整 `REQUIRED_ROLES` 与 `--sla-hours` / `--ttl-hours`。
