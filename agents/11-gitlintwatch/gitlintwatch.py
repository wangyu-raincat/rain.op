#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GitLintWatch — GitLab CI lint 未授权探测检测（CVE-2026-97229）

针对 GitLab 自建版 CI lint 端点（未授权 RCE，CVSS 10.0）扫描行为的
离线启发式检测：解析 HTTP 访问日志 / production.log，按源 IP 打 0-100 风险分。

注意：本工具只做检测与评分，不包含任何可复现利用的正则载荷；
演示日志均为合成数据。
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta

# ---------------------------------------------------------------- 规则定义

LINT_PATH_RE = re.compile(r"ci[/_-]?lint", re.IGNORECASE)   # /ci/lint, /api/v4/.../ci/lint ...
PUBLIC_REF_RE = re.compile(r"(?:/projects/[^/\s?]+(?:/[^/\s?]+)*|ref=[^&\s]+)", re.IGNORECASE)
INLINE_COMMENT_MARK = "(?#"          # 正则内联注释标记 —— 攻击者常用它绕过重复扫描与 ASCII 尺寸检查
QUANTIFIER_RE = re.compile(r"\*\+|\+\*|[*+?]\?|\{\d+(?:,\d*)?\}")
PCT_RE = re.compile(r"%([0-9A-Fa-f]{2})")

RULES = [
    ("R1", "未授权命中 CI lint 端点",
     "匿名（未登录）请求直接打到 CI lint 相关路径，是此 CVE 的前置探测动作。"),
    ("R2", "正则形态异常",
     "请求中携带的正则出现内联注释标记、超长量词结构或嵌套量词，"
     "与 PoC 阶段绕过扫描的构造手法一致。"),
    ("R3", "编码异常",
     "请求含非 ASCII / UTF-8 编码段或异常百分号编码，"
     "对应 UTF-8 仓库路径绕过特征。"),
    ("R4", "行为异常",
     "同一 IP 短时间多次命中 lint 端点（爆破式探测），或 lint 后紧跟 5xx / 超时"
     "（可能触发了后端正则编译器异常）。"),
    ("R5", "组合加权：公开项目分支引用 + 其他信号",
     "公开项目分支引用与任一可疑信号同时出现时加分，"
     "还原攻击链中'公开项目 + 未授权 lint'的组合。"),
]

# 规则权重（同一 IP 命中多种信号时按下式合并，封顶 100）
WEIGHTS = {"R1": 30, "R2": 35, "R3": 15, "R4": 25, "R5": 10}

# ---------------------------------------------------------------- 日志解析

# 支持的日志行格式（空格分隔）：
#   <ISO时间> <源IP> <用户名|-代表匿名> <方法> <路径(含查询参数)> <状态码> <UA...>
# 例：
#   2026-10-14T10:00:01 203.0.113.7 - GET /ci/lint?content=... 200 curl/8.0
LINE_RE = re.compile(
    r"^(?P<ts>\S+)\s+(?P<ip>\S+)\s+(?P<user>\S+)\s+"
    r"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+(?P<status>\d{3})\b\s*(?P<ua>.*)$"
)


def parse_line(line):
    """解析一行日志，失败返回 None。"""
    m = LINE_RE.match(line.strip())
    if not m:
        return None
    d = m.groupdict()
    try:
        d["ts"] = datetime.fromisoformat(d["ts"].replace("Z", "+00:00"))
    except ValueError:
        return None
    d["status"] = int(d["status"])
    return d


def is_lint(path):
    return bool(LINT_PATH_RE.search(path))


def regex_shape_anomaly(path):
    """R2：量词内嵌内联注释标记 / 超长正则 / 嵌套量词。"""
    reasons = []
    if INLINE_COMMENT_MARK in path:
        reasons.append("含正则内联注释标记 (?#...)")
    # 统计查询参数或路径中量词 token 的数量
    quants = QUANTIFIER_RE.findall(path)
    if len(quants) >= 3:
        reasons.append("嵌套/重复量词结构 x%d" % len(quants))
    if len(path) > 800:
        reasons.append("请求串超长(%d字符)" % len(path))
    return reasons


def encoding_anomaly(raw_line):
    """R3：非 ASCII / UTF-8 编码段 / 异常百分号编码。"""
    reasons = []
    # 解码 %XX，看是否出现高字节（非 ASCII）
    decoded = PCT_RE.sub(
        lambda m: chr(int(m.group(1), 16)) if int(m.group(1), 16) < 128 else "\x80",
        raw_line,
    )
    if "\x80" in decoded:
        reasons.append("含 UTF-8/高字节百分号编码段")
    # 行内直接出现非 ASCII 字符
    if any(ord(c) > 127 for c in raw_line):
        reasons.append("行内含非 ASCII 字符")
    # 异常：连续大量百分号编码
    if len(PCT_RE.findall(raw_line)) >= 10:
        reasons.append("异常大量百分号编码")
    return reasons

# ---------------------------------------------------------------- 检测主流程


def detect(entries):
    """entries: [(raw_line, parsed)] -> {ip: {"score": int, "rules": {...}, "samples": [...]}}"""
    by_ip = defaultdict(list)
    for raw, e in entries:
        by_ip[e["ip"]].append((raw, e))
    for ip in by_ip:
        by_ip[ip].sort(key=lambda x: x[1]["ts"])

    results = {}
    for ip, rows in by_ip.items():
        rule_hits = defaultdict(list)   # rule_id -> [原因]
        lint_times = []
        crash_after_lint = False
        public_ref_lint = False

        for raw, e in rows:
            path, user = e["path"], e["user"]
            if not is_lint(path):
                continue
            lint_times.append(e["ts"])

            if user == "-":
                rule_hits["R1"].append("匿名请求 %s %s" % (e["method"], path.split("?")[0]))

            for why in regex_shape_anomaly(path):
                rule_hits["R2"].append(why)

            for why in encoding_anomaly(raw):
                rule_hits["R3"].append(why)

            if PUBLIC_REF_RE.search(path):
                public_ref_lint = True

        # R4-1：短时间多次 lint（120 秒窗口内 >= 4 次）
        burst = False
        if len(lint_times) >= 4:
            for i in range(len(lint_times) - 3):
                if lint_times[i + 3] - lint_times[i] <= timedelta(seconds=120):
                    burst = True
                    break
        if burst:
            rule_hits["R4"].append("120秒内 >=4 次 lint 请求（爆破式探测）")

        # R4-2：lint 后 60 秒内同 IP 出现 5xx
        lint_set = set(lint_times)
        for raw, e in rows:
            if e["status"] >= 500 and any(
                timedelta(0) <= e["ts"] - t <= timedelta(seconds=60) for t in lint_set
            ):
                crash_after_lint = True
                break
        if crash_after_lint:
            rule_hits["R4"].append("lint 后 60 秒内出现 5xx（后端可能异常）")

        # R5：公开项目分支引用 + 任一其他信号
        if public_ref_lint and set(rule_hits) - {"R5"}:
            rule_hits["R5"].append("公开项目/分支引用与可疑信号组合出现")

        # 评分：1 - Π(1 - w_i)，同一规则只计一次
        score = 0.0
        for rid in rule_hits:
            score = 1 - (1 - score) * (1 - WEIGHTS[rid] / 100.0)
        score = round(score * 100)

        if score > 0:
            samples = []
            seen = set()
            for raw, e in rows:
                if is_lint(e["path"]) and raw not in seen:
                    samples.append(raw.strip())
                    seen.add(raw)
                if len(samples) >= 3:
                    break
            results[ip] = {
                "score": score,
                "rules": {rid: sorted(set(v)) for rid, v in rule_hits.items()},
                "hits": len([r for r, e in rows if is_lint(e["path"])]),
                "samples": samples,
            }
    return results


RULE_NAME = {r[0]: r[1] for r in RULES}
RULE_DESC = {r[0]: r[2] for r in RULES}

# ---------------------------------------------------------------- 演示数据（合成）


def demo_log():
    """合成演示日志：3 个 IP —— 攻击者 / 正常用户 / 误伤边缘。"""
    return """\
2026-10-14T10:00:01 203.0.113.7 - GET /ci/lint?ref=main 200 curl/8.5.0
2026-10-14T10:00:12 203.0.113.7 - GET /ci/lint?ref=main&content=a 200 curl/8.5.0
2026-10-14T10:00:25 203.0.113.7 - POST /api/v4/projects/42/ci/lint?ref=dev&content=x(?#bypass)*+{1,300} 200 python-requests/2.31
2026-10-14T10:00:40 203.0.113.7 - POST /api/v4/projects/42/ci/lint?ref=dev&content=y(?#bypass)%E4%B8%AD%E6%96%87*+%7B1%2C300%7D 200 python-requests/2.31
2026-10-14T10:01:02 203.0.113.7 - POST /api/v4/projects/42/ci/lint?ref=dev 502 python-requests/2.31
2026-10-14T10:05:00 198.51.100.23 alice POST /api/v4/projects/7/ci/lint?ref=main 200 GitLab-Runner/16.0
2026-10-14T10:06:11 198.51.100.23 alice GET /api/v4/projects/7 200 GitLab-Runner/16.0
2026-10-14T10:07:33 192.0.2.9 - GET /ci/lint 404 Mozilla/5.0
""".splitlines()


def print_report(results, top=None):
    items = sorted(results.items(), key=lambda kv: -kv[1]["score"])
    if top:
        items = items[:top]
    if not items:
        print("未发现可疑 IP。")
        return
    for ip, r in items:
        print("=" * 64)
        print("IP: %s   风险分: %d/100   lint 命中: %d 次" % (ip, r["score"], r["hits"]))
        for rid in sorted(r["rules"]):
            print("  [%s] %s（权重 %d）" % (rid, RULE_NAME[rid], WEIGHTS[rid]))
            for why in r["rules"][rid][:3]:
                print("        - %s" % why)
        if r["samples"]:
            print("  示例日志:")
            for s in r["samples"]:
                print("        %s" % s[:160])
    print("=" * 64)


def main(argv=None):
    ap = argparse.ArgumentParser(description="GitLintWatch：GitLab CI lint 未授权探测检测（CVE-2026-97229）")
    ap.add_argument("logfile", nargs="?", help="日志文件路径（每行一上述格式）；省略则需 --demo")
    ap.add_argument("--demo", action="store_true", help="用内置合成日志演示，离线可跑")
    ap.add_argument("--list", action="store_true", help="列出检测规则组后退出")
    ap.add_argument("--top", type=int, default=0, help="只显示风险分最高的 N 个 IP")
    ap.add_argument("--json", action="store_true", help="以 JSON 输出结果")
    args = ap.parse_args(argv)

    if args.list:
        for rid, name, desc in RULES:
            print("[%s] %s（权重 %d）\n    %s\n" % (rid, name, WEIGHTS[rid], desc))
        return 0

    if args.demo:
        lines = demo_log()
    elif args.logfile:
        try:
            with open(args.logfile, encoding="utf-8", errors="replace") as f:
                lines = f.read().splitlines()
        except OSError as e:
            print("读日志文件失败：%s" % e, file=sys.stderr)
            return 1
    else:
        ap.print_help()
        return 2

    entries = []
    skipped = 0
    for line in lines:
        if not line.strip():
            continue
        e = parse_line(line)
        if e is None:
            skipped += 1
            continue
        entries.append((line, e))
    if skipped:
        print("（跳过无法解析的行：%d）" % skipped, file=sys.stderr)

    results = detect(entries)
    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
    else:
        print_report(results, top=args.top or None)
    return 0


if __name__ == "__main__":
    sys.exit(main())
