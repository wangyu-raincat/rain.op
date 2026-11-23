# AgentApprovalDesk — 智能体人工审批审计台

`rain.op` 每日安全小 Agent 系列 Day 44：**监测向**。

一句话：读 Agent 的审批台账（JSONL），用七组规则事后审计审批链有没有被绕过——无审批执行、自批自审、已拒仍执行、批后改参、越权审批、审批超时、审批过期后执行——输出 0–100 风险分、合规率与 SLA 达成率。纯 Python 标准库，离线可运行，不调用任何外部 API。

> 对口 JD 关键词：**人工审批点、最小权限、工具调用审计、权限过滤、审计留痕、评测通过率、Agent 工程化落地**

## 它解决什么问题

人工审批点是 agent 安全的最后一道闸：删文件、跑 shell、对外发数据、改配置、轮换密钥这类高危操作，理论上都要先有人点头再执行。但"批了"不等于"批对了"——自批自审、批完改参、被拒仍执行、批的人没资格、批完拖太久才执行，都是审批链上真实出现过的绕过形态。

与 Day 34 MCPGuard（调用时拦截）不同：这里是**事后审计**——调用已经发生，从台账上定位审批链哪里被绕过、哪一类绕过最常见。与 Day 40 ToolChainWatch（调用链异常）不同：这里只盯审批环节——调用链可以完全"正常"，但批的人不对、批的内容被偷换，照样是绕过。与 Day 36 AgentIncidentDesk（事件台账）不同：这里输出的是一次审批审计报告，可直接作为台账的一条事件来源。

## 核心功能

- **七组审批绕过审计**：覆盖审批链上最常见的七种失效形态（见下表），逐条给出证据化说明。
- **风险评分与评级**：违规按规则加权计分（封顶 100），给出正常 / 低危 / 中危 / 高危评级与处置结论。
- **合规率与 SLA 达成率**：合规率 = 未命中任何违规的请求占比；SLA 达成率 = 已决请求中在时限内决断的占比。
- **审批角色白名单**：每类高危操作规定可批角色（最小权限），五类操作（删文件 / 跑 shell / 对外发数据 / 轮换密钥 / 读密钥）无论台账怎么标都强制要求审批。
- **双格式报告**：控制台报告 + 可选 JSON 报告，可直接作为 Day 36 AgentIncidentDesk 的事件来源。

## 七组审计规则

| 规则 | 含义 | 级别 | 分值 |
| --- | --- | --- | --- |
| no_approval_exec | 高危操作没有任何批准就执行，审批链被完全绕过 | 高危 | 40 |
| self_approval | 审批人与申请人是同一人，自批自审 | 中危 | 25 |
| rejected_exec | 审批已拒绝，操作仍被执行，拒绝没有约束力 | 高危 | 40 |
| param_drift | 批完改参：执行参数与批准参数不一致，等于批了个空壳 | 高危 | 30 |
| unauthorized_approver | 审批人角色不在该操作的审批角色白名单里，越权审批 | 中危 | 25 |
| approval_timeout | 审批等待超过 SLA（默认 24 小时）仍未决 | 低危 | 15 |
| stale_approval | 批准超过有效期（默认 24 小时）后才执行，拿旧批文办新事 | 中危 | 20 |

操作与审批角色的映射（最小权限）见程序内的 `REQUIRED_ROLES`：删文件 / 跑 shell 须 sre-lead 或 security-lead 批，读密钥 / 轮换密钥须 security-lead 批，对外发数据须 security-lead 或 data-owner 批。

## 快速开始

环境：Python 3.8+，无第三方依赖（见 `requirements.txt`）。

```bash
cd agents/44-agentapprovaldesk

# 内置演示：10 条审批请求，植入 7 类违规
python approvaldesk.py --demo

# 审计自己的台账文件（不带 -i 时默认读 sample_approvals.jsonl）
python approvaldesk.py -i approvals.jsonl

# 把报告写成 JSON
python approvaldesk.py -i approvals.jsonl --json report.json

# 审批 SLA 改为 8 小时、批准有效期改为 12 小时
python approvaldesk.py -i approvals.jsonl --sla-hours 8 --ttl-hours 12
```

退出码：风险分 ≥ 70（高危）时返回 1，其余返回 0；台账文件不存在或无合法记录时返回 2。演示模式检出高危违规，返回 1 属预期行为。

## 真实演示输出

`python approvaldesk.py --demo` 实测输出（节选）：

```text
AgentApprovalDesk 演示：10 条审批请求，植入 7 类违规

================================================================
AgentApprovalDesk 审批审计报告 · 来源：内置演示台账
================================================================
审批请求：10 条（已决 8 条） · 风险分：100/100 · 评级：高危
合规率：30.0% · SLA（24h 内决断）达成率：100.0%
结论：审批链存在可被绕过的缺口：立即冻结涉事 agent 的高危操作，人工复核全部高危告警并补齐审批记录
操作分布：delete_file×2, exec_shell×2, send_external×2, modify_config×1, read_secret×1, deploy×1, rotate_secret×1
违规分类：no_approval_exec×1, self_approval×1, rejected_exec×1, param_drift×1, unauthorized_approver×2, approval_timeout×1, stale_approval×1

检出 8 条违规：

[1] [高危] no_approval_exec（+40 分）
    请求 APR-0002（ops-agent 执行 exec_shell，风险 critical）：高危操作在没有任何批准的情况下执行，审批链被完全绕过。台账已明确标注 executed_without_approval。

[4] [高危] param_drift（+30 分）
    请求 APR-0005：批完改参，执行参数与批准参数不一致（path：'/tmp/cache' → '/data/prod.db'）。审批人点头的是 A，实际执行的是 B，等于批了个空壳。

[6] [中危] unauthorized_approver（+25 分）
    请求 APR-0008（操作 rotate_secret）：审批人 alice 的角色是 sre-lead，但该操作要求审批角色为 security-lead。越权审批：批的人没有资格为这件事背书。
```

10 条演示请求共检出 8 条违规（APR-0008 同时命中越权审批与过期执行两条，属于同一请求的两次违规）。

## 台账格式

JSONL，每行一条审批请求，字段说明：

| 字段 | 含义 |
| --- | --- |
| req_id / agent / action / tool | 请求编号、发起 agent、操作、所用工具 |
| risk | low / medium / high / critical |
| requested_by / approved_by / approver_role | 申请人、审批人、审批人角色 |
| status | approved / rejected / pending / expired / executed_without_approval |
| requested_at / decided_at / executed_at | 申请 / 决断 / 执行时间（ISO 8601，可带时区；无时区按 UTC 处理） |
| approved_params / executed_params | 批准参数 / 实际执行参数（比对用） |
| requires_approval | 该操作是否要求审批（五类高危操作恒为 true） |

`sample_approvals.jsonl` 就是与内置演示相同的那份台账，可直接拿去改。非法 JSON 行会被跳过并在 stderr 提示，不中断整批审计。

## 项目结构

```text
44-agentapprovaldesk/
├── approvaldesk.py          # 主程序：台账读取、七组审计、评分与报告
├── sample_approvals.jsonl   # 示例台账（与内置演示相同，10 条）
├── requirements.txt         # 依赖说明（纯标准库，无第三方包）
└── tests/
    ├── conftest.py
    └── test_approvaldesk.py   # 14 个用例：七组规则逐条正例、去重、评分与台账读取
```

## 设计要点

- **规则互相去重、避免一罪多罚**：每组审计是独立函数，但交叉情形有明确归属——已拒仍执行的记录只记 `rejected_exec`，不再叠加 `no_approval_exec` 与 `param_drift`；同一请求命中多条不同规则则分别计分，让风险分反映"绕过方式的多样性"而非重复计数。
- **审批必要性三重判定**：`needs_approval()` 依次看台账自带标记、操作是否属于强制审批清单、风险等级是否高危——台账把 `requires_approval` 标成 false 也不能给高危操作开豁免口。
- **时间处理统一归一化**：所有时间先经 `parse_time()` 解析为带时区的 datetime（无时区按 UTC），SLA 与批准有效期的比较不会被 `Z` / `+08:00` / 裸时间混写坑到；解析失败的记录跳过该项检查而不是让整批审计崩掉。

## 测试

```bash
pip install pytest   # 仅测试需要
python -m pytest tests/ -q
# 14 passed
```

覆盖：时间解析（Z / 时区偏移 / 无时区 / 非法值）、参数比对（改值 / 新增字段 / 非 dict 退化）、审批必要性三重判定、完全合规记录零告警、空台账、七组规则逐条命中（含已拒仍执行不重复扣分）、演示台账整体回归（风险分 100、合规率 30.0%、违规分类计数）、台账读取跳过坏行。

## 与 rain.op 其他 agent 的配合

- 调用时拦截与白名单见 Day 34 **MCPGuard**；
- agent 安全评测与通过率见 Day 35 **AgentEvalBench**；
- 异常事件台账与 SLA 见 Day 36 **AgentIncidentDesk**；
- 智能体治理与合规见 Day 37 **AgentGovQA**；
- 工具调用链异常检测见 Day 40 **ToolChainWatch**；
- 敏感信息外泄事后审计见 Day 42 **AgentLeakWatch**；
- 智能体隐私与数据治理见 Day 43 **AgentPrivacyQA**。

## 边界与说明

- 纯标准库，离线运行，不调用任何外部 API；演示数据均为虚构占位值，不对应任何真实人员或真实操作。
- 审计结论只针对这份台账：台账本身若缺记录（如未记 `executed_at`），漏检的违规不会出现在这里，先保证台账完整再谈合规率。
- 同一请求命中多条规则时按规则分别计分、风险分封顶 100；合规率按"未命中任何违规的请求占比"计算。
- 审批角色白名单与 SLA / 有效期默认值是示例工程实践，具体落地时按组织制度调整 `REQUIRED_ROLES` 与 `--sla-hours` / `--ttl-hours`。
