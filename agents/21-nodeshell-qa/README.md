# 21-nodeshell-qa · NodeShell-QA

Node2Shell（CVE-2026-111497）离线问答：输一个 Node.js 版本号，告诉你受不受影响、该升到哪个版本；也可以用自然语言问「我中招了吗」「怎么修」「暂时升不了怎么办」。

## 这是什么漏洞

Node.js 内置 Brotli 解码器的越界写，可导致远程代码执行。关键点只有一句：**漏洞在 Node.js 运行时本身，不在应用依赖里**——只升级 npm 包修不掉，必须升级运行时并重启进程。2026-10-21 发布的修复版本：26.12.1、24.22.1、22.23.4；20.x、23.x、25.x 等已停止维护的分支不会得到修复，需要迁移到受支持分支。

## 怎么跑

纯 Python 标准库，无需安装依赖，无需 API Key，离线可跑：

```bash
# 演示：版本研判示例 + 典型问题问答
python nodeshellqa.py --demo

# 研判一个版本
python nodeshellqa.py --check 24.22.0
python nodeshellqa.py --check v20.19.5

# 自然语言提问（也可直接问 CVE 编号）
python nodeshellqa.py --ask "我中招了吗"
python nodeshellqa.py --ask "CVE-2026-111497"
python nodeshellqa.py --ask "暂时不能升级怎么办"
```

## 示例输出

```text
$ python nodeshellqa.py --check 24.22.0
版本 24.22.0：受影响
请升级到 24.22.1 并重启 Node.js 进程；只升级应用依赖修不掉这个漏洞。

$ python nodeshellqa.py --check 20.19.5
版本 20.19.5：EOL 无修复
该分支已停止维护，不会得到修复；请先迁移到受支持的分支（22.x / 24.x / 26.x），再升到对应修复版本。

$ python nodeshellqa.py --ask "我中招了吗"
我中招了吗：只看实际运行的版本
判断是否受影响，只看实际运行的 Node.js 运行时版本（node -v 或代码里的 process.versions），不要看 package.json 里的依赖版本……
```

## 知识库

`kb.json` 内置 9 张卡片，覆盖：漏洞是什么、是否中招、怎么查版本、修复版本表、暴露路径、临时缓解、事后排查、波及面（Bun / Python / Envoy / Istio）、常见误区。检索用 BM25（中文按字、英文按词切分），可直接替换 `kb.json` 扩展。

事实来源（2026-10-24 核实）：Node.js 官方十月安全公告、Contrast《Node2Shell 分析与修复》、Aikido 与 Security Boulevard 的技术分析。漏洞信息以厂商公告为准；本工具只做离线研判，不做网络探测。

## 局限

- 版本研判只认 `主.次.补丁` 三段式；从系统仓库安装、走系统 Brotli 库的 Node.js，要以发行版 brotli 包的更新为准（见卡片 NS-03）。
- 截至 2026-10-23 尚无官方 IoC 与在野利用记录，事后排查只能看异常行为，不能据此断定「没被利用」。
- 问答是抽取式检索，不是大模型生成；问法偏离卡片关键词时可能答非所问，请以卡片标题核对。
