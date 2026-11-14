# SkillPoisonQA — 智能体技能与工具供应链投毒离线问答

> rain.op Day 39 · RAG 向 · 对口 JD 关键词：**提示注入、工具调用审计、权限过滤、引用溯源、MCP、最小权限、人工审批点、Agent 工程化落地**

agent 的能力来自工具与技能，投毒也最爱藏在这里：一个被下毒的 MCP server、
一个夹带隐藏指令的技能包、一段被改写的工具描述，都能让 agent 在不知不觉中
替攻击者干活。SkillPoisonQA 回答「工具与技能会不会被投毒、怎么防」的问题：
投毒藏在哪、长什么样、怎么发现、发现了怎么办。12 张知识卡片全部离线，
词项检索 + 抽取式回答，**每句答案强制带来源编号与投毒类型**，并附一条可执行的自查动作。

与 Day 37 AgentGovQA（治理怎么做）不同：这里讲攻击面怎么来 —— 是「防住之前先认清敌人」的配套工具。
与 Day 34 MCPGuard（调用时拦截）不同：这里管调用之前 —— 工具与技能进门之前有没有被下毒。

## 快速上手

```bash
# 内置演示：4 个典型的技能与工具投毒问题
python skillpoisonqa.py --demo

# 提问
python skillpoisonqa.py --ask "第三方 MCP server 怎么防投毒？"
python skillpoisonqa.py --ask "技能包怎么查" --category "技能投毒"

# 列出全部 12 张知识卡片
python skillpoisonqa.py --list

# 投毒自查清单（12 项，逐项确认）
python skillpoisonqa.py --checklist
python skillpoisonqa.py --checklist --json checklist.json
```

## 示例输出

```text
问题：第三方 MCP server 怎么防投毒？

[1] MCP server 投毒：工具箱里的特洛伊木马（匹配分 27）
MCP server 投毒是指攻击者发布一个看似正常的 MCP server，在工具描述或工具实现里预埋恶意指令
来源：SP-01《MCP server 投毒：工具箱里的特洛伊木马》· 投毒类型 MCP 投毒
自查动作：只从官方登记处或内部评审清单引入 MCP server；接入前读完 server 源码与工具描述，锁定版本号并做哈希校验
```

## 知识库覆盖的 12 种投毒类型

| 投毒类型 | 卡片 | 核心问题 |
| --- | --- | --- |
| MCP 投毒 | SP-01 | 恶意 MCP server 在工具描述与实现里预埋指令 |
| 技能投毒 | SP-02 | 技能包脚本里藏读凭据、外发数据的隐藏指令 |
| 工具描述劫持 | SP-03 | 改写工具描述误导 agent 的调用行为 |
| 依赖投毒 | SP-04 | 仿冒包名与依赖更新投毒，锁版本 + 验哈希 |
| 工具输出注入 | SP-05 | 工具返回数据里夹带指令，数据与指令分离 |
| 提示词泄露 | SP-06 | 系统提示词被套出，密钥与流程随之泄露 |
| 权限越界 | SP-07 | 无害描述背后的过大工具权限 |
| 沙箱隔离 | SP-08 | 工具执行关进沙箱，投毒损害不出笼子 |
| 来源验证 | SP-09 | 签名与哈希确认工具真是那个人发的 |
| 人工审批 | SP-10 | 五类高危调用的最后一道刹车 |
| 审计溯源 | SP-11 | 调用链留痕，投毒发生后讲清来龙去脉 |
| 应急处置 | SP-12 | 止血、定损、清毒、复盘四步 |

## 自查清单怎么用

`--checklist` 打印 12 项投毒自查动作；`--json checklist.json`
把清单写成 JSON，逐项确认后把 `done` 改为 `true`，全部 done
方可上线。清单是自查工具，不是安全背书，具体供应链安全要求以
组织内部规定为准。

## 与 rain.op 其他 agent 的配合

- MCP 工具调用审计与拦截见 Day 34 **MCPGuard**；
- 注入/越权评测集与通过率见 Day 35 **AgentEvalBench**；
- 异常事件台账与 SLA 见 Day 36 **AgentIncidentDesk**；
- 智能体治理与合规见 Day 37 **AgentGovQA**；
- 长期记忆污染审计见 Day 38 **AgentMemoryGuard**；
- 提示注入检测见 Day 32 **PromptInjectionWatch**。

## 边界与说明

- 纯标准库，离线运行，不调用任何外部 API；知识库是通用工程实践
整理，不针对任何具体厂商政策。
- 检索是词项匹配（中文单字 + 二元字串），不是语义检索；换词提问
可能命中不同卡片，`--category` 可限定投毒类型缩小范围。
- 回答是抽取式引用，不生成新观点；卡片内容需要定期随实践更新。
