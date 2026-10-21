#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DrupalWatch — 针对 CVE-2026-108097 的 Drupal Field UI RCE 检测

CVE-2026-108097: Drupal core Field UI 模块 RCE（SA-CORE-2026-014，
2026-10-14 公开，Drupal 评级 Critical 19/25）。FORTBRIDGE 研究员
Adrian Tiron 于 2026-10-20 发布完整分析与 lab PoC：Field UI 有一行
代码"把表格行里命名的 PHP callable 当作代码直接执行"，但核心本身
无法从外部到达该行——需要某个桥接模块/自定义代码把请求数据喂进
这些表格行（已知预认证利用路径）。PoC 演示了文件读取 → 命令执行
的完整链条，全程无需登录。

受影响版本：8.9.0–10.6.18 / 11.0.0–11.3.18 / 11.4.0–11.4.9 /
12.0.0-alpha1–beta1；修复版本：10.6.19 / 11.3.19 / 11.4.10 /
12.0.0-beta2。无法立即升级时建议卸载 field_ui 模块。

本工具读 Web 访问日志（combined 格式），按攻击 IP 输出 0–100
风险分、命中规则与处置建议。纯标准库，离线可跑。
"""

import argparse
import json
import re
import sys
import urllib.parse
from collections import defaultdict
from datetime import datetime, timedelta

# ---------------------------------------------------------------- 常量

FIXED_VERSIONS = "10.6.19 / 11.3.19 / 11.4.10 / 12.0.0-beta2"

# Field UI 相关管理端点（探测重点；正常管理员访问也走这里，
# 所以单看端点只给低分，必须配合载荷指纹）
FIELD_UI_PATHS = [
    re.compile(p, re.IGNORECASE) for p in (
        r"/admin/structure/types/manage/[^/]+/fields",
        r"/admin/structure/[^/]+/display",
        r"/admin/structure/comment/manage/[^/]+/fields",
        r"/admin/reports/fields",
        r"/admin/config/development/configuration",
        r"/field_ui",
    )
]

# PHP callable / 命令执行载荷指纹（URL 解码后匹配）。
# PoC 核心是"表格行命名 callable 即被执行"，所以参数里出现
# callable 形态 + 编码混淆是关键信号。
CALLABLE_RES = [
    re.compile(p, re.IGNORECASE) for p in (
        r"\bsystem\s*\(",
        r"\bshell_exec\s*\(",
        r"\bpassthru\s*\(",
        r"\bpopen\s*\(",
        r"\bproc_open\s*\(",
        r"\beval\s*\(",
        r"\bassert\s*\(",
        r"\bcall_user_func",
        r"\bcreate_function\s*\(",
        r"\bpcntl_exec\b",
        r"%24%7b|%2524%257b",          # 双重编码的 ${
        r"\$\{[^}]{0,40}\}",            # ${...} 变量展开
        r"`[^`]{1,80}`",               # 反引号命令
        r"chr\s*\(\s*\d",              # chr() 混淆
        r"(?:\\\\x[0-9a-f]{2}){3,}",   # \x.. 混淆串
    )
]

# 文件读取 / 信息泄露探测（PoC 链条第一步：file disclosure）
DISCLOSURE_RES = [
    re.compile(p, re.IGNORECASE) for p in (
        r"%2e%2e|%252e|%c0%ae|\.\.%2f|\.\.%5c|\.\./|\.\.\\",
        r"/etc/passwd",
        r"settings\.php",
        r"config/sync",
        r"\.git/HEAD",
        r"CHANGELOG\.txt",
        r"sites/default/files/[^?\s]*\.\.(?:%2f|%5c|/)",
    )
]

# webshell 落地与交互指纹（利用成功后的确认行为；排除含 .. 的穿越误报）
WEBSHELL_RES = [
    re.compile(p, re.IGNORECASE) for p in (
        r"/sites/default/files/(?:(?!\.\.)[^?\s])*\.php",
        r"/sites/default/private/(?:(?!\.\.)[^?\s])*\.php",
        r"/modules/(?:contrib|custom)/[^?\s]*\.php\?",
        r"[?&](?:cmd|c|x|exec|command|q)=[^&\s]{1,200}",
        r"\bwhoami\b|\bid\b;|\buname\s+-[a-z]|\bcat\s+/etc",
        r"/bin/(?:sh|bash)\b",
        r"\bwget\s+https?://|\bcurl\s+[^&\s]*\|\s*(?:sh|bash)",
    )
]

# PoC 核心形态：桥接参数直接命名 callable，如 rows[0][callable]=system
CALLABLE_PARAM_RE = re.compile(
    r"[?&=][\w\[\].%\-]*=\s*"
    r"(?:system|shell_exec|passthru|exec|popen|proc_open|eval|assert|"
    r"call_user_func|create_function|pcntl_exec)\b",
    re.IGNORECASE)

# 查询串里的长 Base64（callable 名常做 Base64 混淆后塞进参数）
B64_RE = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")

# 扫描器 / 批量利用框架 UA
SCANNER_UA_RES = [
    re.compile(p, re.IGNORECASE) for p in (
        r"nuclei", r"sqlmap", r"nikto", r"masscan", r"gobuster",
        r"acunetix", r"nessus", r"zgrab", r"python-requests/\d",
        r"Go-http-client", r"curl/\d.*-A", r"hydra",
    )
]

# 权重：规则组 -> 分数
W_FIELD_UI = 5         # Field UI 端点访问（基线，合法管理员也会触发）
W_FIELD_UI_ERR = 15    # Field UI 端点 + 4xx/5xx（探测形态）
W_CALLABLE = 35        # callable/命令执行载荷（核心指纹）
W_DISCLOSURE = 20      # 文件读取探测
W_WEBSHELL = 40        # webshell 落地/交互（沦陷强信号）
W_B64 = 15             # 长 Base64 载荷
W_SCANNER_UA = 10      # 扫描器 UA
W_BURST = 15           # 10 分钟内 > 60 请求（爆破/扫描速率）

ALERT_THRESHOLD = 50
CRITICAL_THRESHOLD = 80

COMBINED_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) \S+" '
    r'(?P<status>\d{3}) (?P<size>\S+) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)

TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"


# ---------------------------------------------------------------- 日志解析

def parse_line(line):
    m = COMBINED_RE.match(line.strip())
    if not m:
        return None
    d = m.groupdict()
    try:
        d["dt"] = datetime.strptime(d["time"], TIME_FMT)
    except ValueError:
        d["dt"] = None
    d["status"] = int(d["status"])
    # 保留原始路径与解码后路径两份指纹
    raw = d["path"]
    try:
        d["decoded"] = urllib.parse.unquote_plus(raw)
    except Exception:
        d["decoded"] = raw
    return d


# ---------------------------------------------------------------- 规则引擎

def analyze(entries):
    """entries -> {ip: {score, hits, first, last, requests}}"""
    per_ip = defaultdict(lambda: {
        "score": 0, "hits": defaultdict(int), "first": None,
        "last": None, "requests": 0, "times": [],
    })

    for e in entries:
        ip = per_ip[e["ip"]]
        ip["requests"] += 1
        if e["dt"]:
            ip["times"].append(e["dt"])
            if not ip["first"] or e["dt"] < ip["first"]:
                ip["first"] = e["dt"]
            if not ip["last"] or e["dt"] > ip["last"]:
                ip["last"] = e["dt"]

        raw, dec, status = e["path"], e["decoded"], e["status"]
        text = raw + " " + dec

        # 1. Field UI 端点
        if any(rx.search(raw) for rx in FIELD_UI_PATHS):
            if status >= 400:
                ip["score"] += W_FIELD_UI_ERR
                ip["hits"]["field_ui_probe_4xx"] += 1
            else:
                ip["score"] += W_FIELD_UI
                ip["hits"]["field_ui_access"] += 1

        # 2. callable / 命令执行载荷
        matched = False
        for rx in CALLABLE_RES:
            if rx.search(text):
                matched = True
                break
        if not matched and CALLABLE_PARAM_RE.search(dec):
            matched = True
        if matched:
            ip["score"] += W_CALLABLE
            ip["hits"]["callable_payload"] += 1

        # 3. 文件读取探测
        for rx in DISCLOSURE_RES:
            if rx.search(text):
                ip["score"] += W_DISCLOSURE
                ip["hits"]["file_disclosure"] += 1
                break

        # 4. webshell 落地/交互
        for rx in WEBSHELL_RES:
            if rx.search(text):
                ip["score"] += W_WEBSHELL
                ip["hits"]["webshell_activity"] += 1
                break

        # 5. 长 Base64 载荷
        if B64_RE.search(text):
            ip["score"] += W_B64
            ip["hits"]["long_base64"] += 1

        # 6. 扫描器 UA
        ua = e["ua"]
        if any(rx.search(ua) for rx in SCANNER_UA_RES):
            ip["score"] += W_SCANNER_UA
            ip["hits"]["scanner_ua"] += 1

    # 7. 速率：任意 10 分钟窗口 > 60 请求
    for ip, st in per_ip.items():
        times = sorted(t for t in st["times"] if t)
        j = 0
        for i, t in enumerate(times):
            while times[j] < t - timedelta(minutes=10):
                j += 1
            if i - j + 1 > 60:
                st["score"] += W_BURST
                st["hits"]["burst_10min"] += 1
                break

    for st in per_ip.values():
        st["score"] = min(100, st["score"])
        st["hits"] = dict(st["hits"])
    return dict(per_ip)


def verdict(score):
    if score >= CRITICAL_THRESHOLD:
        return "高危"
    if score >= ALERT_THRESHOLD:
        return "可疑"
    if score >= 20:
        return "探测"
    return "低"


RECOMMENDATIONS = {
    "高危": [
        "立即隔离该 IP 的访问并取证：检查 sites/default/files 与模块目录新增 .php 文件",
        f"升级到修复版本（{FIXED_VERSIONS}）；无法立即升级则卸载 field_ui 模块",
        "审查自定义模块/贡献模块中把请求数据喂给 Field UI 表格的代码（桥接点）",
        "检查 files 目录 .htaccess 是否被改动、是否有异常出站连接/意外 PHP 进程",
    ],
    "可疑": [
        "把该 IP 加入 WAF 观察名单，确认 Field UI 相关端点是否需要对外暴露",
        f"核对 Drupal 版本，不在修复版本内则计划升级（{FIXED_VERSIONS}）",
    ],
    "探测": ["属常规扫描噪声；若同一资产反复出现，检查版本并收紧管理端点访问"],
    "低": ["无需处理"],
}


def report(per_ip, out=sys.stdout):
    rows = sorted(per_ip.items(), key=lambda kv: -kv[1]["score"])
    flagged = [(ip, st) for ip, st in rows if st["score"] >= 20]
    print(f"共分析 {len(rows)} 个源 IP，{len(flagged)} 个需要关注（≥20 分）\n",
          file=out)
    for ip, st in rows:
        if st["score"] < 20:
            continue
        v = verdict(st["score"])
        print(f"[{v}] {ip}  风险分 {st['score']}/100  "
              f"请求 {st['requests']} 次", file=out)
        for name, n in sorted(st["hits"].items(), key=lambda kv: -kv[1]):
            print(f"      - {name}: {n} 次", file=out)
        print("      处置建议：", file=out)
        for r in RECOMMENDATIONS[v]:
            print(f"        * {r}", file=out)
        print(file=out)
    if not flagged:
        print("未发现针对 CVE-2026-108097 的可疑活动。", file=out)


# ---------------------------------------------------------------- 演示

DEMO_LOG = """\
# 场景 A: 正常管理员（应低分：只有 Field UI 访问，无载荷）
203.0.113.10 - - [21/Oct/2026:09:02:11 +0800] "GET /admin/structure/types/manage/article/fields HTTP/1.1" 200 5120 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
203.0.113.10 - - [21/Oct/2026:09:02:40 +0800] "POST /admin/structure/types/manage/article/fields/add-field HTTP/1.1" 200 2311 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
# 场景 B: nuclei 扫描器扫 Field UI 端点（探测）
198.51.100.23 - - [21/Oct/2026:09:10:02 +0800] "GET /admin/structure/types/manage/page/fields HTTP/1.1" 403 612 "-" "nuclei/3.3.0"
198.51.100.23 - - [21/Oct/2026:09:10:03 +0800] "GET /admin/reports/fields HTTP/1.1" 403 590 "-" "nuclei/3.3.0"
198.51.100.23 - - [21/Oct/2026:09:10:04 +0800] "GET /field_ui HTTP/1.1" 404 402 "-" "nuclei/3.3.0"
198.51.100.23 - - [21/Oct/2026:09:10:05 +0800] "GET /sites/default/settings.php HTTP/1.1" 403 588 "-" "nuclei/3.3.0"
# 场景 C: PoC 风格利用——桥接端点喂 callable 载荷（应高危）
192.0.2.77 - - [21/Oct/2026:09:15:44 +0800] "GET /entity-list/render?rows[0][callable]=system&rows[0][args]=id HTTP/1.1" 200 1412 "-" "python-requests/2.31"
192.0.2.77 - - [21/Oct/2026:09:15:52 +0800] "GET /entity-list/render?rows%5B0%5D%5Bcallable%5D=shell_exec&rows%5B0%5D%5Bargs%5D=d2hvYW1p%0A HTTP/1.1" 200 1408 "-" "python-requests/2.31"
192.0.2.77 - - [21/Oct/2026:09:16:07 +0800] "GET /entity-list/render?rows[0][callable]=passthru&rows[0][args]=cat${IFS}/etc/passwd HTTP/1.1" 200 1430 "-" "python-requests/2.31"
192.0.2.77 - - [21/Oct/2026:09:16:20 +0800] "POST /sites/default/files/.cache/x9.php?cmd=id HTTP/1.1" 200 96 "-" "python-requests/2.31"
# 场景 D: 文件读取探测（PoC 链条第一步）
192.0.2.99 - - [21/Oct/2026:09:20:11 +0800] "GET /sites/default/files/..%2f..%2fsettings.php HTTP/1.1" 400 220 "-" "Mozilla/5.0"
192.0.2.99 - - [21/Oct/2026:09:20:13 +0800] "GET /entity-list/render?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd HTTP/1.1" 200 1320 "-" "Mozilla/5.0"
"""


def run_demo():
    entries = [e for line in DEMO_LOG.splitlines()
               if line and not line.startswith("#")
               for e in [parse_line(line)] if e]
    per_ip = analyze(entries)
    print("=== DrupalWatch 演示模式（合成日志） ===\n")
    report(per_ip)


# ---------------------------------------------------------------- 主入口

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="DrupalWatch: CVE-2026-108097 Field UI RCE 日志检测")
    ap.add_argument("--log", help="Web 访问日志路径（combined 格式）")
    ap.add_argument("--demo", action="store_true", help="跑内置演示")
    ap.add_argument("--json", action="store_true", help="JSON 输出")
    args = ap.parse_args(argv)

    if args.demo or not args.log:
        if not args.demo and not args.log:
            print("未指定 --log，进入演示模式（加 --demo 明确运行）\n")
        run_demo()
        return 0

    entries = []
    with open(args.log, encoding="utf-8", errors="replace") as f:
        for line in f:
            e = parse_line(line)
            if e:
                entries.append(e)
    per_ip = analyze(entries)

    if args.json:
        serial = {ip: {**st, "verdict": verdict(st["score"]),
                       "first": str(st["first"]), "last": str(st["last"]),
                       "times": [str(t) for t in st["times"]]}
                  for ip, st in per_ip.items()}
        print(json.dumps(serial, ensure_ascii=False, indent=2))
    else:
        report(per_ip)
    return 0


if __name__ == "__main__":
    sys.exit(main())
