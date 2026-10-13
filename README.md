# rain.op 🛡️ 每日网络安全小 Agent

![daily](https://img.shields.io/badge/updated-daily-brightgreen) ![python](https://img.shields.io/badge/python-3.8%2B-blue)

每天一个网络安全方向的小 agent，**RAG** 与**流量监测**两个方向交替。

每个 agent 独立目录、小而精、**离线可运行**（演示模式不依赖外部 API Key），clone 下来就能跑。

One tiny security agent per day, alternating between RAG and traffic monitoring. Self-contained, offline-friendly, pure Python.

## 🚀 快速开始

```

git clone https://github.com/wangyu-raincat/rain.op.git

cd rain.op/agents/01-flowscan

python flowscan.py --demo

```

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

## 📐 约定

- 每个 agent 在 `agents/NN-英文名/` 下自成一体，含中文 README、主程序、演示模式。

- 尽量只用 Python 标准库，保证 clone 下来就能跑。

- 每天更新，欢迎 star & 提 issue 交流。
