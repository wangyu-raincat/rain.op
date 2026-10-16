# rain.op 🛡️ 每日网络安全小 Agent

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Stars](https://img.shields.io/github/stars/wangyu-raincat/rain.op)](https://github.com/wangyu-raincat/rain.op/stargazers)
[![Last commit](https://img.shields.io/github/last-commit/wangyu-raincat/rain.op)](https://github.com/wangyu-raincat/rain.op/commits/main)

每天一个网络安全方向的小 Agent，**流量监测**与 **RAG 离线问答**交替更新。每个 Agent 独立目录、离线可运行；演示模式不访问网络，也不需要 API Key。

One tiny security agent per day, alternating between traffic monitoring and offline RAG. Self-contained, pure Python, no third-party packages.

## 这是什么

`agents/` 下目前有 12 个纯 Python 小工具，分成两类：

- **流量监测**：用启发式规则读取本地日志或内置合成样本，标出扫描、洪泛、DNS 隧道、Web 攻击，以及若干已公开 CVE 在访问日志里留下的探测痕迹，并给出告警。
- **RAG**：用 BM25 在该 Agent 自带的知识库里检索，输出抽取式回答或情报卡片。知识库在仓库里，不联网。

知识库要么是同目录的 `kb.json`（SecQA、PhishHunt），要么写在主程序里。01 与 03 另有 `gen_sample.py`，可以单独生成样本日志。

## 环境

- Python 3.8 或更高版本。脚本的 shebang 是 `python3`；若 `python` 已指向 3.8+，也可以用 `python`。
- 无第三方依赖，不需要 `pip install`。部分目录里的 `requirements.txt` 只说明这一点。

## 快速开始

```bash
git clone https://github.com/wangyu-raincat/rain.op.git
cd rain.op/agents/01-flowscan
python3 flowscan.py --demo
```

上面这条命令会在当前目录写入 `alerts.json`。演示数据里包含高危告警，因此退出码为 1。其他 Agent 同样支持演示：进入对应目录，执行 `python3 <入口> --demo`。日志格式、提问方式和其余参数写在该目录的 README 里。

## Agent 索引

| 编号 | 名称 | 方向 | 入口 | 做什么 |
| --- | --- | --- | --- | --- |
| 01 | [FlowScan](agents/01-flowscan/) | 流量监测 | `flowscan.py` | 端口扫描、SYN Flood、内网 Beaconing |
| 02 | [SecQA](agents/02-secqa/) | RAG | `secqa.py` | 24 条安全知识，BM25 + 抽取式回答 |
| 03 | [FileProbe](agents/03-fileprobe/) | 流量监测 | `fileprobe.py` | CVE-2026-21589：Atlassian 路径遍历 / 敏感文件探测 |
| 04 | [PhishHunt](agents/04-phishhunt/) | RAG | `phishhunt.py` | 钓鱼邮件评分；BM25 检索 16 条知识 |
| 05 | [DNSTunnel](agents/05-dnstunnel/) | 流量监测 | `dnstunnel.py` | DNS 隧道 / 渗出的 6 组启发式特征 |
| 06 | [VulnQA](agents/06-vulnqa/) | RAG | `vulnqa.py` | 20 条高危 CVE 情报卡片 |
| 07 | [WebAttack](agents/07-webattack/) | 流量监测 | `webattack.py` | 访问日志里的 SQLi / XSS / 遍历 / 命令注入等，按 IP 打分 |
| 08 | [MITRE-QA](agents/08-mitre/) | RAG | `mitre.py` | 18 条 ATT&CK 技术卡片 |
| 09 | [PatroniWatch](agents/09-patroniwatch/) | 流量监测 | `patroniwatch.py` | CVE-2026-76268：Patroni REST API 未认证变更与探测 |
| 10 | [VulnIntel-QA](agents/10-vulnintel/) | RAG | `vulnintel.py` | 4 条 2026-10 高危 CVE（影响、条件、修复版本、在野状态） |
| 11 | [GitLintWatch](agents/11-gitlintwatch/) | 流量监测 | `gitlintwatch.py` | CVE-2026-97229：GitLab CI lint 未授权探测，按 IP 打分 |
| 12 | [LiveFire-QA](agents/12-livefire/) | RAG | `livefire.py` | 5 条在野利用或暂无补丁的条目，按威胁状态查看 |

## 目录

```text
agents/
├── 01-flowscan/       flowscan.py、gen_sample.py
├── 02-secqa/          secqa.py、kb.json
├── 03-fileprobe/      fileprobe.py、gen_sample.py
├── 04-phishhunt/      phishhunt.py、kb.json
├── 05-dnstunnel/      dnstunnel.py
├── 06-vulnqa/         vulnqa.py
├── 07-webattack/      webattack.py
├── 08-mitre/          mitre.py
├── 09-patroniwatch/   patroniwatch.py
├── 10-vulnintel/      vulnintel.py
├── 11-gitlintwatch/   gitlintwatch.py
└── 12-livefire/       livefire.py
```

每个目录还有一份中文 README。

## 约定

- 每个 Agent 放在 `agents/NN-英文名/`，自成一体：中文 README、主程序、`--demo`。
- 尽量只用 Python 标准库，克隆后即可运行演示。
- 流量监测与 RAG 交替追加。欢迎 star，也欢迎用 Issue 交流。
