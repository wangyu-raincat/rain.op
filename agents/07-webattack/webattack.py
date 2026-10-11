#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WebAttack · Web 攻击检测小 Agent

读取 Web 服务器访问日志（Apache / Nginx Combined 格式），按客户端 IP 聚合，
用 6 组启发式规则识别 SQL 注入、XSS、路径遍历、命令注入、敏感文件扫描等
攻击行为，输出 0–100 风险评分、证据链和 alerts.json。

纯 Python 标准库，离线可运行。演示模式内置混合流量。

用法：
    python webattack.py --demo                  # 演示：内置正常流量 + 5 类攻击
    python webattack.py --file /var/log/nginx/access.log
    cat access.log | python webattack.py
    python webattack.py --demo --json /tmp/alerts.json
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from urllib.parse import unquote_plus as _uq

# ---------------------------------------------------------------- 规则定义
# 每组：名称、权重（单次命中加分）、正则列表
RULES = [
    ("SQL注入", 15, [
        r"union\s+select", r"union\s+all\s+select", r"'\s*or\s+'?\d+'?\s*=\s*'?\d",
        r"or\s+1\s*=\s*1", r"information_schema", r"sleep\s*\(", r"benchmark\s*\(",
        r"load_file\s*\(", r"into\s+outfile", r"@@version", r"concat\s*\(",
        r"'--", r"/\*.*\*/", r"order\s+by\s+\d+",
    ]),
    ("XSS", 10, [
        r"<script", r"javascript\s*:", r"onerror\s*=", r"onload\s*=",
        r"onmouseover\s*=", r"alert\s*\(", r"document\.cookie", r"<svg",
        r"<img[^>]*on\w+\s*=", r"eval\s*\(", r"<iframe",
    ]),
    ("路径遍历/LFI", 12, [
        r"\.\./", r"\.\.\\", r"%2e%2e", r"/etc/passwd", r"/etc/shadow",
        r"/etc/hosts", r"php://", r"file://", r"\.\.%2f", r"%252e",
        r"\.\.;/", r"/proc/self/environ",
    ]),
    ("命令注入", 18, [
        r";\s*cat\s", r";\s*id\b", r"\|\s*id\b", r"\$\(", r"`\w+`",
        r"&&\s*whoami", r";\s*whoami", r";\s*wget\s", r";\s*curl\s",
        r"\|\s*nc\s", r";\s*ls\s", r"ping\s+-c",
    ]),
    ("敏感文件扫描", 8, [
        r"/\.git/", r"/\.env\b", r"/\.svn/", r"/\.DS_Store",
        r"/wp-admin", r"/wp-login", r"/phpmyadmin", r"/actuator",
        r"/server-status", r"/console/", r"/manager/html",
        r"backup\.sql", r"dump\.sql", r"/\.well-known/change-password",
    ]),
    ("扫描器指纹", 8, [
        r"sqlmap", r"nikto", r"nmap", r"masscan", r"acunetix",
        r"nessus", r"dirbuster", r"gobuster", r"wpscan",
    ]),
]

COMPILED = [(name, weight, [re.compile(p, re.IGNORECASE) for p in pats])
            for name, weight, pats in RULES]

# Combined 日志格式：IP - user [time] "METHOD /path HTTP/x" status bytes "refer" "UA"
# 注意：攻击载荷里常带空格（SQLi / XSS），request-target 必须允许空格
LOG_RE = re.compile(
    r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (.+?) HTTP/[\d.]+" (\d{3}) \S+ "([^"]*)" "([^"]*)"'
)

HIGH, SUSPICIOUS = 70, 40


def decode(target: str) -> str:
    """URL 解码两遍，兼容 %2e%2e / %252e 这类编码绕过；+ 视为空格。"""
    t = target
    for _ in range(2):
        t = _uq(t)
    return t


def detect(target: str, ua: str):
    """返回命中列表 [(规则名, 权重, 命中的正则原文)]。"""
    text = decode(target)
    hits = []
    for name, weight, patterns in COMPILED:
        for p in patterns:
            if p.search(text) or (name == "扫描器指纹" and p.search(ua)):
                hits.append((name, weight, p.pattern))
                break  # 每组只计一次，避免同一 payload 重复加分
    return hits


def parse_line(line: str):
    m = LOG_RE.match(line.strip())
    if not m:
        return None
    ip, ts, method, target, status, _ref, ua = m.groups()
    return {"ip": ip, "time": ts, "method": method, "target": target,
            "status": int(status), "ua": ua}


def analyze(lines):
    """按 IP 聚合命中，返回 {ip: {...}}。"""
    per_ip = defaultdict(lambda: {"hits": 0, "types": defaultdict(int),
                                  "evidence": [], "status_4xx": 0})
    total = skipped = 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        rec = parse_line(line)
        if rec is None:
            skipped += 1
            continue
        total += 1
        st = per_ip[rec["ip"]]
        if rec["status"] >= 400:
            st["status_4xx"] += 1
        for name, weight, pat in detect(rec["target"], rec["ua"]):
            st["hits"] += 1
            st["types"][name] += weight
            if len(st["evidence"]) < 5:
                st["evidence"].append(f"{name}: {rec['method']} {rec['target'][:90]}")
    results = {}
    for ip, st in per_ip.items():
        base = min(sum(st["types"].values()), 60)
        diversity = min((len(st["types"]) - 1) * 8, 24) if st["types"] else 0
        volume = min(st["hits"] * 2, 24)  # 持续攻击行为本身就很可疑
        scan4xx = 4 if st["status_4xx"] >= 10 else 0  # 大量 4xx + 命中 = 扫描行为
        score = min(base + diversity + volume + scan4xx, 100)
        level = "高危" if score >= HIGH else ("可疑" if score >= SUSPICIOUS else "正常")
        results[ip] = {"ip": ip, "score": score, "level": level,
                       "hits": st["hits"], "types": dict(st["types"]),
                       "evidence": st["evidence"]}
    return results, total, skipped


def report(results, total, skipped):
    print(f"共解析 {total} 条访问日志" + (f"（跳过 {skipped} 条无法解析）" if skipped else ""))
    rows = sorted(results.values(), key=lambda r: -r["score"])
    print(f"{'客户端IP':<16}{'评分':<6}{'等级':<6}{'命中':<6}攻击类型")
    print("-" * 80)
    shown = 0
    for r in rows:
        if r["score"] == 0:
            continue
        types = "、".join(r["types"].keys())
        print(f"{r['ip']:<16}{r['score']:<6}{r['level']:<6}{r['hits']:<6}{types}")
        shown += 1
    if shown == 0:
        print("未发现攻击行为，全部正常。")


def build_alerts(results):
    return {"alerts": [
        {"ip": r["ip"], "score": r["score"], "level": r["level"],
         "hits": r["hits"], "attack_types": sorted(r["types"].keys()),
         "evidence": r["evidence"]}
        for r in sorted(results.values(), key=lambda x: -x["score"])
        if r["score"] >= SUSPICIOUS]}


# ------------------------------------------------------------ 演示流量生成
NORMAL_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
]
NORMAL_PATHS = ["/", "/index.html", "/static/app.js", "/static/style.css",
                "/api/products?page=2", "/product.php?id=12", "/about",
                "/search?q=%E8%BF%9E%E8%A1%A3%E8%A3%99", "/favicon.ico"]


def _log(ip, target, status=200, ua=None, method="GET", ref="-"):
    ua = ua or NORMAL_UAS[0]
    return (f'{ip} - - [11/Oct/2026:09:30:00 +0800] "{method} {target} HTTP/1.1" '
            f'{status} 1234 "{ref}" "{ua}"')


def demo_logs():
    lines = []
    # 正常用户：少量请求，正常 UA
    for ip in ("10.0.0.5", "10.0.0.6"):
        for i, p in enumerate(NORMAL_PATHS[:6]):
            lines.append(_log(ip, p, ua=NORMAL_UAS[i % 2]))
    # 攻击者 A：SQL 注入扫描（product.php?id=）
    for p in [
        "/product.php?id=1' OR '1'='1",
        "/product.php?id=1 UNION SELECT 1,2,3--",
        "/product.php?id=1 UNION SELECT @@version,2,3",
        "/product.php?id=1' AND SLEEP(5)--",
        "/product.php?id=-1 UNION SELECT 1,table_name,3 FROM information_schema.tables",
        "/product.php?id=1;SELECT BENCHMARK(1000000,MD5(1))",
    ]:
        lines.append(_log("192.0.2.10", p))
    # 攻击者 B：XSS
    for p in [
        "/search?q=<script>alert(1)</script>",
        "/comment?name=<img src=x onerror=alert(document.cookie)>",
        "/go?url=javascript:alert(1)",
        "/page?x=<svg onload=eval(atob('eGtz'))>",
    ]:
        lines.append(_log("203.0.113.7", p))
    # 攻击者 C：路径遍历 / LFI（含编码绕过）
    for p in [
        "/download?file=../../../../etc/passwd",
        "/view?page=%2e%2e%2f%2e%2e%2fetc%2fshadow",
        "/inc?f=php://filter/convert.base64-encode/resource=index",
        "/static/....//....//etc/hosts",
    ]:
        lines.append(_log("198.51.100.9", p, status=404))
    # 攻击者 D：敏感文件扫描（sqlmap 指纹）
    for p in ["/.git/HEAD", "/.env", "/.svn/entries", "/wp-admin/",
              "/phpmyadmin/", "/actuator/health", "/server-status",
              "/backup.sql", "/.DS_Store"]:
        lines.append(_log("203.0.113.99", p, status=404,
                          ua="sqlmap/1.8.3#stable (https://sqlmap.org)"))
    # 攻击者 E：命令注入
    for p in [
        "/ping?host=8.8.8.8;cat /etc/passwd",
        "/api/tool?cmd=x|id",
        "/run?a=1$(whoami)",
    ]:
        lines.append(_log("192.0.2.55", p))
    # 正常爬虫（不应误报）：Googlebot 访问普通页面
    lines.append(_log("66.249.66.1", "/sitemap.xml",
                      ua="Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"))
    return lines


def main():
    ap = argparse.ArgumentParser(description="WebAttack · Web 攻击检测小 Agent")
    ap.add_argument("--demo", action="store_true", help="演示模式：内置混合流量")
    ap.add_argument("--file", help="访问日志文件路径（Combined 格式）")
    ap.add_argument("--json", help="告警 JSON 输出路径")
    args = ap.parse_args()

    if args.demo:
        lines = demo_logs()
    elif args.file:
        with open(args.file, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    elif not sys.stdin.isatty():
        lines = sys.stdin.readlines()
    else:
        ap.print_help()
        return

    results, total, skipped = analyze(lines)
    report(results, total, skipped)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(build_alerts(results), f, ensure_ascii=False, indent=2)
        print(f"\n告警 JSON 已写入：{args.json}")


if __name__ == "__main__":
    main()