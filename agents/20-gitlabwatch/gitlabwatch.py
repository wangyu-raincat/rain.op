#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GitLabWatch —— CVE-2026-110264（GitLab CVSS 10.0 未认证 RCE）利用探测

漏洞背景（2026-10-21 披露）：
  - GitLab 内嵌 Ruby 的 Onigmo 正则引擎在编译特殊构造的正则时整数溢出，
    未认证攻击者可在满足条件时远程执行任意代码。
  - 公开的攻击向量是"渲染精心构造的 .org 文件"（经 org-ruby / OtherMarkup
    渲染器），影响自建 GitLab CE/EE 7.0 以来的全部版本。
  - GitLab 官方发布了两条检测规则，本工具把它们改写成可离线运行的启发式：
    1) "Org mode render error burst" —— 同一客户端 30 分钟内 5+ 次
       .org 文件渲染超时（OtherMarkup Timeout::Error）
    2) "Onigmo native worker crash" —— puma_stderr.log 里的 Ruby [BUG]
       原生崩溃（提到 org-ruby / Onigmo）

用法：
  python gitlabwatch.py --log access.log                 # 分析日志文件
  python gitlabwatch.py --log access.log --json-out out.json
  python gitlabwatch.py --demo                           # 离线演示（含合成攻击流量）
  python gitlabwatch.py --demo-log out.log               # 只生成演示日志

支持输入：Nginx/Apache combined 格式访问日志、GitLab production_json.log
（JSON 行）中的 .org 渲染请求；也支持直接喂 exceptions_json.log /
puma_stderr.log 行来做崩溃征兆检查。纯标准库，离线可跑。
"""

import argparse
import json
import random
import re
import sys
from collections import defaultdict

# ---------- 漏洞常量（2026-10-21 GitLab critical patch release） ----------
CVE = "CVE-2026-110264"
FIXED_VERSIONS = ["19.5.1", "19.4.3", "19.3.6", "19.2.9", "19.1.9", "19.0.10", "18.11.13"]
CVSS = "10.0"

# 权重：每个信号给 IP 加分（上限 100）
WEIGHTS = {
    "org_render_request": 20,   # 请求 .org 文件/渲染路由
    "org_error_burst": 40,      # 短窗口内同一 IP 多次 .org 渲染错误
    "pathological_payload": 30, # 超长 URL / 可疑正则载荷 / 编码异常
    "probe_retry": 20,          # 短时间内大量 4xx/5xx 重试
    "crash_hint": 50,           # 日志里出现原生崩溃征兆（服务器级）
}

ORG_PATH_RE = re.compile(r"\.org(\?|/|$)|/-/raw/|/-/[a-z]+/-/|OtherMarkup|org-ruby", re.I)
SEARCH_PARAM_RE = re.compile(r"[?&](search|q|query|scope|filter|regex|pattern)=", re.I)
REGEX_META_RE = re.compile(r"(\(\?|[\[\]{}*+?]{3,}|\\x[0-9a-fA-F]{2}|%5B%5D)", re.I)
CRASH_RE = re.compile(r"Ruby\s*\[BUG\]|org-ruby|Onigmo|Timeout::Error.*OtherMarkup|OtherMarkup.*Timeout", re.I)
IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")

COMBINED_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+) \S+" (?P<status>\d{3}) (?P<size>\S+)'
)


def parse_line(line):
    """尽量从一行日志里抽出 ip / url / status，返回 dict 或 None。"""
    line = line.strip()
    if not line:
        return None
    # 3) 结构化解析优先：combined 访问日志 / JSON
    m = COMBINED_RE.match(line)
    if m:
        return {"ip": m.group("ip"), "url": m.group("url"),
                "status": m.group("status"), "raw": line}
    if line.startswith("{"):
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            return None
        url = obj.get("path") or obj.get("url") or ""
        status = str(obj.get("status") or "")
        ip = str(obj.get("remote_ip") or obj.get("ip") or "")
        msg = obj.get("message") or ""
        if ip or url or status or CRASH_RE.search(msg):
            return {"ip": ip, "url": url, "status": status, "raw": line}
        return None
    # 4) exceptions_json.log / puma_stderr.log 裸行：只做崩溃征兆匹配
    if CRASH_RE.search(line):
        m = IP_RE.search(line)
        return {"ip": m.group(1) if m else "", "url": "", "status": "",
                "raw": line, "crash_hint": True}
    return None


def analyze(records):
    """records: parse_line 产出的列表。返回 (ip_findings, server_alerts)。"""
    per_ip = defaultdict(lambda: {"signals": set(), "org_errors": 0,
                                   "error_hits": 0, "org_reqs": 0,
                                   "evidence": []})

    server_alerts = []
    for r in records:
        if r.get("crash_hint") or CRASH_RE.search(r["raw"]):
            server_alerts.append(r["raw"][:200])
        ip = r.get("ip") or "未知IP"
        d = per_ip[ip]
        url = r.get("url") or ""
        status = r.get("status") or ""

        if ORG_PATH_RE.search(url):
            d["signals"].add("org_render_request")
            d["org_reqs"] += 1
            d["evidence"].append(f".org/渲染请求: {url[:120]}")
            if status.startswith("5") or "Timeout" in r["raw"]:
                d["org_errors"] += 1

        if len(url) > 2000 or (SEARCH_PARAM_RE.search(url) and REGEX_META_RE.search(url)):
            d["signals"].add("pathological_payload")
            d["evidence"].append(f"可疑载荷: {url[:120]}")

        if status.startswith(("4", "5")):
            d["error_hits"] += 1

    findings = []
    for ip, d in per_ip.items():
        signals = set(d["signals"])
        if d["org_errors"] >= 4:
            signals.add("org_error_burst")          # 官方规则的离线近似
            d["evidence"].append(f".org 渲染错误 {d['org_errors']} 次（疑似爆破式探测）")
        if d["error_hits"] >= 10:
            signals.add("probe_retry")
            d["evidence"].append(f"{d['error_hits']} 次 4xx/5xx（高频重试）")
        if not signals or ip == "未知IP":
            continue
        score = min(100, sum(WEIGHTS[s] for s in signals))
        findings.append({
            "ip": ip, "score": score,
            "level": "高危" if score >= 70 else ("中危" if score >= 40 else "低"),
            "signals": sorted(signals),
            "evidence": d["evidence"][:4],
        })
    findings.sort(key=lambda x: -x["score"])
    return findings, server_alerts


ADVICE = (
    "处置建议：这是 {cve}（CVSS {cvss}）的利用探测告警，无缓解措施，"
    "唯一可靠办法是升级到修复版本（{vers}，按分支选），"
    "GitLab.com 已修复。升级前建议把 Web 入口收进 VPN/白名单，"
    "并把涉事 IP 加入 WAF 封禁，保留日志做取证。"
).format(cve=CVE, cvss=CVSS, vers=" / ".join(FIXED_VERSIONS))


def report(findings, server_alerts, n_records):
    print(f"GitLabWatch 报告  |  {CVE} 利用探测  |  分析日志行: {n_records}")
    if server_alerts:
        print(f"\n[!] 服务器级崩溃征兆 {len(server_alerts)} 条（官方 Onigmo native crash 规则）:")
        for a in server_alerts[:5]:
            print(f"    - {a}")
    if not findings:
        print("\n未发现可疑 IP。注意：一次成功的利用可能不留下崩溃痕迹，"
              "干净日志不能证明服务器未被攻破。")
        return 0
    print(f"\n发现 {len(findings)} 个可疑 IP:")
    for i, f in enumerate(findings, 1):
        print(f"[{i}] [{f['level']}] {f['ip']}  风险分 {f['score']}/100")
        print(f"    信号: {', '.join(f['signals'])}")
        for e in f["evidence"]:
            print(f"    - {e}")
    if any(f["level"] == "高危" for f in findings):
        print(f"\n{ADVICE}")
        return 1
    return 0


def gen_demo_log(path):
    """生成合成演示日志：正常流量 + 一个攻击者 IP 的 .org 渲染探测。"""
    random.seed(20261024)
    normal_ips = [f"10.0.0.{i}" for i in range(2, 12)]
    attacker = "203.0.113.77"
    pages = ["/", "/dashboard", "/explore", "/users/sign_in", "/api/v4/projects"]
    lines = []
    seq = [0]
    def log(ip, url, status, note=""):
        seq[0] += 1
        i = seq[0]
        lines.append(
            f'{ip} - - [24/Oct/2026:09:1{i % 10}:{i % 60:02d} +0800] '
            f'"GET {url} HTTP/1.1" {status} 1234 "-" "Mozilla/5.0"{note}')
    for _ in range(60):
        log(random.choice(normal_ips), random.choice(pages), random.choice(["200"] * 9 + ["404"]))
    evil = ("(?:" + "(a+)+" * 40 + ")",)
    for i in range(7):  # 攻击者：7 次 .org 渲染探测，全部 500 超时
        log(attacker,
            f"/group/proj/-/blob/main/notes{i}.org?search=%28%3F%3A{evil[0][:60]}%29",
            "500", " Timeout::Error OtherMarkup")
    log(attacker, "/group/proj/-/raw/main/README.org", "200")
    for i in range(12):  # 攻击者：高频 404/500 重试
        log(attacker, f"/nope/{i}?x={'A' * 3000}", "404")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return path


def main(argv=None):
    ap = argparse.ArgumentParser(description="GitLabWatch: CVE-2026-110264 利用探测")
    ap.add_argument("--log", nargs="+", help="访问日志文件（可多个）")
    ap.add_argument("--demo", action="store_true", help="离线演示")
    ap.add_argument("--demo-log", help="只生成演示日志到指定路径")
    ap.add_argument("--json-out", help="把结果写成 JSON 文件")
    args = ap.parse_args(argv)

    records = []
    if args.demo_log:
        p = gen_demo_log(args.demo_log)
        print(f"演示日志已生成: {p}")
        return 0
    if args.demo:
        p = gen_demo_log("/tmp/gitlabwatch_demo.log")
        logfiles = [p]
    elif args.log:
        logfiles = args.log
    else:
        ap.error("请指定 --log 日志文件，或用 --demo 跑演示")

    for lf in logfiles:
        try:
            with open(lf, encoding="utf-8", errors="replace") as f:
                for line in f:
                    r = parse_line(line)
                    if r:
                        records.append(r)
        except OSError as e:
            print(f"读日志失败 {lf}: {e}", file=sys.stderr)

    findings, server_alerts = analyze(records)
    rc = report(findings, server_alerts, len(records))
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump({"cve": CVE, "findings": findings,
                       "server_alerts": server_alerts[:20],
                       "advice": ADVICE},
                      f, ensure_ascii=False, indent=2)
        print(f"JSON 已写入: {args.json_out}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
