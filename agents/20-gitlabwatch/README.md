# GitLabWatch（20）—— CVE-2026-110264 利用探测

**一句话**：分析 GitLab / 反向代理访问日志，抓打向 `.org` 文件渲染链的异常请求，按 IP 打 0–100 风险分，给出升级处置建议。

## 漏洞背景

- **CVE-2026-110264**，CVSS **10.0**，2026-10-21 由 GitLab 通过 critical patch release 披露并修复。
- 漏洞是 GitLab 内嵌 Ruby 的 **Onigmo 正则引擎在编译特殊构造的正则时整数溢出**，满足条件时未认证攻击者可远程执行任意代码。
- 公开的攻击向量是**渲染精心构造的 `.org` 文件**（经 `org-ruby` / `OtherMarkup` 渲染器）。
- 影响自建 GitLab CE/EE **7.0（2014 年）以来的全部版本**；无缓解措施，只能升级。修复版本：**19.5.1 / 19.4.3 / 19.3.6 / 19.2.9 / 19.1.9 / 19.0.10 / 18.11.13**。
- GitLab 官方给出的两条检测规则被本工具改写成离线启发式（见"检测逻辑"）。
- Ruby 官方随后也发布了修复版 4.0.9 / 3.4.12 / 3.3.13（含本次及三个关联 CVE 的 Onigmo 修复）。

## 检测逻辑

1. **`.org` 渲染请求**：访问日志里命中 `*.org`、`/-/raw/`、blob/raw 路由的请求加 20 分（这是已知攻击面入口）。
2. **Org mode render error burst（官方规则的离线近似）**：同一 IP 短窗口内 4 次以上 `.org` 渲染 500/超时，加 40 分。
3. **病态载荷**：URL 超长（>2000 字符）或搜索/过滤参数里带大量正则元字符/编码异常，加 30 分。
4. **高频重试**：同一 IP 累计 10 次以上 4xx/5xx，加 20 分。
5. **原生崩溃征兆（服务器级）**：日志里出现 `Ruby [BUG]`、`org-ruby`、`Onigmo`、`Timeout::Error … OtherMarkup` 直接告警（对应官方 "Onigmo native worker crash" 规则）。

风险分 = 信号权重之和（上限 100）；≥70 高危，≥40 中危。高危 IP 触发后输出处置建议并返回退出码 1。

## 怎么跑

纯标准库，无需安装，无需 API Key：

```bash
# 离线演示（自动生成含攻击者 203.0.113.77 的合成日志）
python gitlabwatch.py --demo

# 只生成演示日志
python gitlabwatch.py --demo-log demo.log

# 分析真实日志（支持多个，可混搭）
python gitlabwatch.py --log /var/log/nginx/access.log /var/log/gitlab/gitlab-rails/production_json.log

# 结果顺手写成 JSON
python gitlabwatch.py --log access.log --json-out findings.json
```

支持的输入格式：Nginx/Apache combined 访问日志、GitLab `production_json.log`（JSON 行）；`exceptions_json.log` / `puma_stderr.log` 的裸行只做崩溃征兆匹配。

## 示例输出

```text
GitLabWatch 报告  |  CVE-2026-110264 利用探测  |  分析日志行: 80

发现 1 个可疑 IP:
[1] [高危] 203.0.113.77  风险分 100/100
    信号: org_render_request, org_error_burst, pathological_payload, probe_retry
    - .org/渲染请求: /group/proj/-/blob/main/notes0.org?search=%28%3F%3A...
    - .org 渲染错误 7 次（疑似爆破式探测）
    - 19 次 4xx/5xx（高频重试）

处置建议：这是 CVE-2026-110264（CVSS 10.0）的利用探测告警，无缓解措施，
唯一可靠办法是升级到修复版本（19.5.1 / 19.4.3 / 19.3.6 / 19.2.9 / 19.1.9 / 19.0.10 / 18.11.13，按分支选），
GitLab.com 已修复。升级前建议把 Web 入口收进 VPN/白名单，
并把涉事 IP 加入 WAF 封禁，保留日志做取证。
```

## 局限

- 启发式规则面向"渲染 .org"这条已知攻击链；PoC 未公开，真实利用流量形态可能与此不同，误报/漏报都可能。
- GitLab 官方特别提示：一次成功的利用可能**不留下任何崩溃痕迹**——干净日志不能证明服务器未被攻破，未打补丁的外网实例应按"已被触及"处置。
- 时间窗口是简化处理（按日志整体统计而非滑动 30 分钟窗口），生产用请配合 SIEM 做精确窗口聚合。
