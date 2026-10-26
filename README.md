# rain.op 🛡️ Python 网络安全工具集

**从合成流量告警到离线安全问答，用小而独立的 Python 程序理解检测规则与知识检索。**

![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white) ![Offline demos](https://img.shields.io/badge/Demos-offline-2EA44F) ![Focus](https://img.shields.io/badge/Focus-traffic%20%2B%20security%20QA-5B5BD6)

适合网络安全入门者、Python 学习者，以及想阅读和改造规则的蓝队同学。每个工具放在独立目录，附中文说明；先运行演示，再查看输入格式和实现。

*A collection of small Python security tools for learning traffic analysis and offline security QA. Start with heuristic flow detection or BM25 retrieval with extractive answers; the two demos below use only the Python standard library and need no LLM API key.*

[30 秒上手](#30-秒上手) · [选择入口](#先选一个入口) · [完整索引](#-agent-索引) · [提建议](https://github.com/wangyu-raincat/rain.op/issues)

## 先选一个入口

| 你想做什么 | 从这里开始 | 会看到什么 |
| --- | --- | --- |
| 看懂流量异常检测 | [FlowScan](agents/01-flowscan/) | 合成流量 → 端口扫描 / SYN Flood / 周期外联告警 → JSON |
| 了解离线检索问答 | [SecQA](agents/02-secqa/) | 24 条安全知识 → BM25 检索 → 原文句子与引用 |

## 30 秒上手

前提：已安装 Git 和 Python 3.8+。下面两个演示无需安装第三方包，无需 API Key。

```bash
git clone https://github.com/wangyu-raincat/rain.op.git
cd rain.op
python agents/01-flowscan/flowscan.py --demo
```

FlowScan 生成 **1,860 条合成流量**，输出 **3 条告警**，并在当前目录写入 `alerts.json`：

```text
FlowScan 流量异常检测报告  |  分析流量: 1860 条
发现 3 条告警:
[1] [高危] 端口扫描
[2] [高危] SYN Flood 攻击
[3] [中危] 内网 Beacon（疑似 C2 心跳）
JSON 告警已写入: alerts.json
```

> 以上为默认演示输出节选。检测到高危告警时，FlowScan **按设计返回退出码 1**；演示里出现此退出码表示告警被触发。它分析流量记录，不会向示例 IP 发起网络探测。

在仓库根目录继续体验离线问答：

```bash
python agents/02-secqa/secqa.py --demo
python agents/02-secqa/secqa.py --ask "什么是 SQL 注入？如何防御？"
```

SecQA 会输出抽取式回答、知识条目编号和 BM25 得分。它通过词项匹配检索本地 `kb.json`，再抽取相关句子；可以替换知识库，不调用大模型。知识库覆盖和中文分词较简单，补充条目可能弱相关，引用和得分用于检查检索来源。

若系统中的命令是 `python3`，请相应替换 `python`；Windows 也可使用 `py -3`。

## 使用自己的数据

- **FlowScan**：`python agents/01-flowscan/flowscan.py -i flows.csv -o alerts.json`。CSV 字段与规则阈值见 [FlowScan 说明](agents/01-flowscan/README.md)。
- **SecQA**：`python agents/02-secqa/secqa.py --ask "你的问题" --kb my_kb.json`。JSON 知识库格式见 [SecQA 说明](agents/02-secqa/README.md)。

## 演示与使用边界

流量规则可能误报或漏报，合成样本的告警结果不代表真实环境的检测效果；离线知识库也不代表最新情报。涉及具体 CVE、受影响版本与修复建议时，请以厂商公告和权威漏洞记录复核。下面保留各子目录的现有主题索引，未表示所有漏洞信息均已独立核验。

## 📦 Agent 索引
| 编号 | 名称 | 一句话介绍 | 方向 |
| --- | --- | --- | --- |
| 01 | [FlowScan](agents/01-flowscan/) | 轻量流量异常检测：识别端口扫描、SYN Flood、内网 Beaconing，自带流量生成器做演示 | 流量监测 |
| 02 | [SecQA](agents/02-secqa/) | 离线安全知识问答：BM25 检索 + 抽取式回答，内置 24 条 Web/系统/应急知识，纯标准库 | RAG |
| 03 | [FileProbe](agents/03-fileprobe/) | 针对 CVE-2026-21589 的 HTTP 日志检测：识别 Atlassian 产品未授权文件读取的路径遍历/敏感文件探测，输出告警 | 流量监测 |
| 04 | [PhishHunt](agents/04-phishhunt/) | 钓鱼邮件智能分析：10 类特征提取 + BM25 检索钓鱼知识库，输出风险评分、证据链与引用，纯标准库 | RAG |
| 05 | [DNSTunnel](agents/05-dnstunnel/) | DNS 隧道/数据渗出检测：6 组启发式特征打分（超长子域名、高熵载荷、TXT 滥用等），输出告警 | 流量监测 |
| 06 | [VulnQA](agents/06-vulnqa/) | 离线漏洞情报问答：BM25 检索 20 条高危 CVE 知识库，按编号/自然语言提问，输出漏洞情报卡片，纯标准库 | RAG |
| 07 | [WebAttack](agents/07-webattack/) | Web 攻击检测：6 组启发式规则识别访问日志中的 SQLi/XSS/遍历/命令注入/敏感文件扫描，按 IP 打分告警，纯标准库 | 流量监测 |
| 08 | [MITRE-QA](agents/08-mitre/) | MITRE ATT&CK 战术技战术离线问答：BM25 检索 18 条真实 ATT&CK 技术，按编号/自然语言提问，输出战术卡片，纯标准库 | RAG |
| 09 | [PatroniWatch](agents/09-patroniwatch/) | 针对 CVE-2026-76268 的日志检测：识别打向 Patroni REST API 的未认证配置变更、API 路径探测与命令注入载荷，按 IP 打分告警，纯标准库 | 流量监测 |
| 10 | [VulnIntel-QA](agents/10-vulnintel/) | 2026年10月高危漏洞情报离线问答：BM25 检索 4 条真实 CVE，查影响范围/利用条件/修复版本/在野利用，纯标准库 | RAG |
| 11 | [GitLintWatch](agents/11-gitlintwatch/) | 针对 CVE-2026-97229 的日志检测：识别打向 GitLab CI lint 端点的未授权探测、正则形态/编码异常，按 IP 打分告警，纯标准库 | 流量监测 |
| 12 | [LiveFire-QA](agents/12-livefire/) | 「正在着火的漏洞」离线问答：BM25 检索 5 条在野利用/暂无补丁的高危漏洞，按威胁状态分流查「最该先修哪个」「没补丁怎么缓」，纯标准库 | RAG |
| 13 | [SEGWatch](agents/13-segwatch/) | 针对 CVE-2026-76519 的网关沦陷检测：沦陷指示器/附件路径穿越/异常外联/暴露面自查四组规则，按网关打 0–100 风险分，纯标准库 | 流量监测 |
| 14 | [SupplyChain-QA](agents/14-supplychain/) | 供应链投毒事件速查：Rank Math SEO PRO 投毒事件（CVE-2026-111862）研判/自查/处置/防护，BM25 检索 + 投毒窗口研判，纯标准库 | RAG |
| 15 | [CollaboraWatch](agents/15-collaborawatch/) | 针对 CVE-2026-110447 的利用链检测：proxy.php 命令注入指纹/shx* webshell 落地/webhook.site 外联/版本自查五组规则，按 IP 打 0–100 风险分，纯标准库 | 流量监测 |
| 16 | [NextJS-QA](agents/16-nextjsqa/) | Next.js 10-14 双 RCE 沦陷速查：输版本号判是否中招、给升级路径（sharp 同步检查），BM25 检索 3 漏洞卡片 + 自查/处置清单，纯标准库 | RAG |
| 17 | [DrupalWatch](agents/17-drupalwatch/) | 针对 CVE-2026-108097 的 Field UI RCE 检测：callable 命名载荷/文件读取探测/webshell 落地七组规则，按 IP 打 0–100 风险分，纯标准库 | 流量监测 |
| 18 | [PHPatchWatch](agents/18-phppatchwatch/) | 针对 CVE-2026-109618/109619（PHP2Shell 双 RCE）的暴露面盘点：版本标识判定补丁就绪度，0–100 风险分 + 升级建议，纯标准库 | 流量监测 |
| 19 | [RansomQA](agents/19-ransomqa/) | 勒索软件应急响应离线问答：以 AA26-293A（SafePay）联合通告为核心情报，18 张情报+Playbook 卡片，BM25 检索 + 抽取式回答，纯标准库 | RAG |
| 20 | [GitLabWatch](agents/20-gitlabwatch/) | 针对 CVE-2026-110264（GitLab CVSS 10.0 Onigmo 未认证 RCE）的利用探测：.org 渲染请求/渲染错误爆发/病态载荷/高频重试，按 IP 打 0–100 风险分 + 升级建议，纯标准库 | 流量监测 |
| 21 | [NodeShell-QA](agents/21-nodeshell-qa/) | Node2Shell（CVE-2026-111497）离线问答：输版本号判是否中招、给修复版本，BM25 检索 9 张情报卡片，纯标准库 | RAG |
| 22 | [ActuatorWatch](agents/22-actuatorwatch/) | Spring Boot Actuator 暴露面探测检测：敏感端点枚举/env 窃取/危险写操作/SpEL 注入链，按 IP 打 0–100 风险分，纯标准库 | 流量监测 |

## 📐 项目约定与参与

- 每个工具在 `agents/NN-英文名/` 下自成一体，含中文 README、主程序和演示入口。
- 尽量使用 Python 标准库；各模块的参数、输入格式与限制以目录内说明为准。
- 发现误报、知识条目过时或示例运行问题，欢迎 [提交 Issue](https://github.com/wangyu-raincat/rain.op/issues)，附工具名、运行命令、Python 版本及脱敏后的输入/输出。
- 欢迎补充小而可读的检测规则、可追溯的知识条目和可复现的演示。若项目对你有帮助，也欢迎 Star 收藏。

