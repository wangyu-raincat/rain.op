#!/usr/bin/env python3
"""APIAbuseWatch：API 滥用 / 批量抓取检测。

分析 Web 访问日志中的 API 请求，按源 IP 聚合，用五组启发式规则打分：

  1. 高频调用爆发：5 分钟窗口内 API 请求数超阈值
  2. 端点枚举：同一 IP 访问大量不同 API 端点（疑似接口探测）
  3. 错误爆发：4xx 占比高，或被限流（429）后仍继续请求
  4. 批量数据拉取：深分页遍历、导出端点高频调用（疑似数据爬取）
  5. 密钥轮换试探：同一 IP 使用多个不同 API Key / Token

只用 Python 标准库，离线可运行，不发起任何网络请求。

日志格式（Apache combined log 的简化版，API 路径需含 /api/）：

    203.0.113.7 - - [03/Nov/2026:20:10:01 +0800] "GET /api/v1/users?page=12 HTTP/1.1" 200 4096 "python-requests/2.31"

用法：

    python apiabuse.py --demo                 # 内置演示日志
    python apiabuse.py -i access.log          # 分析自己的日志
    python apiabuse.py -i access.log -o alerts.json
"""

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime

LOG_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) [^"]*" '
    r'(?P<status>\d{3}) (?P<bytes>\S+) "(?P<ua>[^"]*)"'
)
KEY_RE = re.compile(r'[?&](?:api_key|apikey|key|token|access_token)=([^&\s]+)')
PAGE_RE = re.compile(r'[?&]page=(\d+)')
API_PATH_RE = re.compile(r'/api/', re.I)
EXPORT_PATH_RE = re.compile(r'(export|download|dump|bulk)', re.I)

# 规则权重（分值上限合计 100）
W_RATE_BURST = 30    # 规则 1：高频调用爆发
W_ENUMERATION = 25   # 规则 2：端点枚举
W_ERROR_BURST = 20   # 规则 3：错误爆发
W_BULK_FETCH = 15    # 规则 4：批量数据拉取
W_KEY_ROTATION = 10  # 规则 5：密钥轮换试探

WINDOW_SECONDS = 300       # 5 分钟滑动窗口
RATE_THRESHOLD = 120       # 窗口内 API 请求数达到此值即满分
ENDPOINT_THRESHOLD = 20    # 不同端点数达到此值即满分
ERROR_RATIO_THRESHOLD = 0.5  # 4xx 占比达到此值即满分
ERROR_MIN_COUNT = 20       # 错误爆发判定所需的最少请求数
PAGE_DEPTH_THRESHOLD = 50  # 最大页码达到此值即满分
EXPORT_THRESHOLD = 10      # 导出端点调用数达到此值即满分
KEY_THRESHOLD = 5          # 不同 API Key 数达到此值即满分


def parse_time(ts):
    """解析 Apache 日志时间，失败返回 None。"""
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    return None


def endpoint_of(path):
    """把路径归一化为端点：去掉查询串，把纯数字段替换为 {id}。"""
    base = path.split("?", 1)[0]
    return re.sub(r'/\d+(?=/|$)', '/{id}', base)


def parse_line(line):
    """解析一行日志；非 API 请求或无法解析返回 None。"""
    m = LOG_RE.search(line)
    if not m:
        return None
    path = m.group("path")
    if not API_PATH_RE.search(path):
        return None
    key_m = KEY_RE.search(path)
    page_m = PAGE_RE.search(path)
    try:
        nbytes = int(m.group("bytes"))
    except ValueError:
        nbytes = 0
    return {
        "ip": m.group("ip"),
        "ts": parse_time(m.group("ts")),
        "method": m.group("method"),
        "path": path,
        "endpoint": endpoint_of(path),
        "status": m.group("status"),
        "bytes": nbytes,
        "ua": m.group("ua"),
        "key": key_m.group(1) if key_m else None,
        "page": int(page_m.group(1)) if page_m else None,
        "is_export": bool(EXPORT_PATH_RE.search(path)),
    }


def max_in_window(timestamps, window=WINDOW_SECONDS):
    """滑动窗口内最大请求数；无时间戳时退化为总数。"""
    ts = sorted(t for t in timestamps if t is not None)
    if not ts:
        return len(timestamps)
    best = 1
    left = 0
    for right in range(len(ts)):
        while (ts[right] - ts[left]).total_seconds() > window:
            left += 1
        best = max(best, right - left + 1)
    return best


def score_ip(reqs):
    """对一个 IP 的请求打分，返回 (总分, 证据列表, 统计)。"""
    total = len(reqs)
    statuses = Counter(r["status"] for r in reqs)
    endpoints = Counter(r["endpoint"] for r in reqs)
    keys = {r["key"] for r in reqs if r["key"]}
    pages = [r["page"] for r in reqs if r["page"] is not None]
    export_count = sum(1 for r in reqs if r["is_export"])
    errors = sum(c for s, c in statuses.items() if s.startswith("4"))
    limited = statuses.get("429", 0)
    burst = max_in_window([r["ts"] for r in reqs])

    score = 0
    evidence = []

    # 规则 1：高频调用爆发
    if burst >= RATE_THRESHOLD:
        score += W_RATE_BURST
        evidence.append(f"5 分钟内 API 请求 {burst} 次（爆发阈值 {RATE_THRESHOLD}）")
    elif burst >= RATE_THRESHOLD // 2:
        part = W_RATE_BURST * burst // RATE_THRESHOLD
        score += part
        evidence.append(f"5 分钟内 API 请求 {burst} 次，接近爆发阈值")

    # 规则 2：端点枚举
    n_ep = len(endpoints)
    if n_ep >= ENDPOINT_THRESHOLD:
        score += W_ENUMERATION
        evidence.append(f"访问不同 API 端点 {n_ep} 个（枚举阈值 {ENDPOINT_THRESHOLD}）")
    elif n_ep >= ENDPOINT_THRESHOLD // 2:
        part = W_ENUMERATION * n_ep // ENDPOINT_THRESHOLD
        score += part
        evidence.append(f"访问不同 API 端点 {n_ep} 个，接近枚举阈值")

    # 规则 3：错误爆发
    if total >= ERROR_MIN_COUNT:
        ratio = errors / total
        if ratio >= ERROR_RATIO_THRESHOLD:
            score += W_ERROR_BURST
            evidence.append(f"4xx 错误 {errors}/{total} 次（占比 {ratio:.0%}）")
        elif ratio >= 0.3:
            part = int(W_ERROR_BURST * ratio / ERROR_RATIO_THRESHOLD)
            score += part
            evidence.append(f"4xx 错误 {errors}/{total} 次（占比 {ratio:.0%}）")
    if limited and total >= ERROR_MIN_COUNT:
        evidence.append(f"被限流 429 共 {limited} 次后仍继续请求")

    # 规则 4：批量数据拉取
    max_page = max(pages) if pages else 0
    bulk = False
    if max_page >= PAGE_DEPTH_THRESHOLD:
        score += W_BULK_FETCH
        evidence.append(f"分页遍历到第 {max_page} 页（深分页阈值 {PAGE_DEPTH_THRESHOLD}）")
        bulk = True
    if export_count >= EXPORT_THRESHOLD:
        if not bulk:
            score += W_BULK_FETCH
        evidence.append(f"导出/下载端点调用 {export_count} 次（阈值 {EXPORT_THRESHOLD}）")
        bulk = True
    if bulk:
        pass  # 规则 4 最多计一次满分，避免分页 + 导出双重计分

    # 规则 5：密钥轮换试探
    if len(keys) >= KEY_THRESHOLD:
        score += W_KEY_ROTATION
        evidence.append(f"使用不同 API Key {len(keys)} 个（轮换阈值 {KEY_THRESHOLD}）")

    score = min(score, 100)
    stats = {
        "requests": total,
        "endpoints": n_ep,
        "errors": errors,
        "keys": len(keys),
        "max_page": max_page,
        "bytes": sum(r["bytes"] for r in reqs),
    }
    return score, evidence, stats


def analyze(lines):
    """解析日志行，返回 (请求总数, 告警列表)。"""
    by_ip = defaultdict(list)
    total = 0
    for line in lines:
        rec = parse_line(line)
        if rec is None:
            continue
        total += 1
        by_ip[rec["ip"]].append(rec)

    alerts = []
    for ip, reqs in by_ip.items():
        score, evidence, stats = score_ip(reqs)
        if score >= 40:
            level = "高危" if score >= 70 else "中危"
            alerts.append({
                "ip": ip,
                "level": level,
                "score": score,
                "evidence": evidence,
                "stats": stats,
            })
    alerts.sort(key=lambda a: -a["score"])
    return total, alerts


def demo_lines():
    """内置演示日志：1 个正常用户、1 个高频抓取者、1 个端点枚举 + 密钥轮换者。"""
    lines = []
    base = "03/Nov/2026:20:10:%02d +0800"

    # 正常用户：少量请求，同一 Key，浅分页
    for i in range(6):
        lines.append(
            f'198.51.100.10 - - [{base % (i * 8)}] '
            f'"GET /api/v1/users?page={i + 1}&api_key=key-normal HTTP/1.1" 200 2048 '
            f'"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
        )

    # 抓取者：5 分钟内 150 次请求，深分页到 120 页，导出端点 12 次
    for i in range(150):
        sec = 10 + i  # 全部落在 5 分钟窗口内
        page = i + 1
        path = "/api/v1/users/export" if i % 12 == 0 else f"/api/v1/users?page={page}"
        lines.append(
            f'203.0.113.7 - - [{base % (sec % 60)}] '
            f'"GET {path}&api_key=key-scraper HTTP/1.1" 200 8192 '
            f'"python-requests/2.31"'
        )

    # 枚举者：25 个不同端点、大量 404/403、6 个 Key 轮换、被限流后继续
    endpoints = [f"/api/v1/{name}" for name in (
        "users", "admin", "config", "debug", "internal", "metrics", "health",
        "secrets", "tokens", "keys", "billing", "webhooks", "jobs", "logs",
        "backup", "restore", "settings", "roles", "sessions", "uploads",
        "reports", "audit", "oauth", "graphql", "actuator",
    )]
    for i, ep in enumerate(endpoints):
        status = "404" if i % 3 else "403"
        lines.append(
            f'192.0.2.99 - - [{base % (20 + i)}] '
            f'"GET {ep}?api_key=key-rot-{i % 6} HTTP/1.1" {status} 512 '
            f'"curl/8.5.0"'
        )
    for i in range(110):  # 429 之后仍继续请求，凑满高频爆发阈值
        lines.append(
            f'192.0.2.99 - - [{base % ((45 + i) % 60)}] '
            f'"GET /api/v1/users?api_key=key-rot-0 HTTP/1.1" 429 128 '
            f'"curl/8.5.0"'
        )
    return lines


def main(argv=None):
    ap = argparse.ArgumentParser(description="APIAbuseWatch：API 滥用检测")
    ap.add_argument("--demo", action="store_true", help="使用内置演示日志")
    ap.add_argument("-i", "--input", help="输入日志文件路径")
    ap.add_argument("-o", "--output", help="把告警写入 JSON 文件")
    args = ap.parse_args(argv)

    if args.demo:
        lines = demo_lines()
    elif args.input:
        with open(args.input, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    else:
        ap.error("请指定 --demo 或 -i <日志文件>")

    total, alerts = analyze(lines)
    print(f"APIAbuseWatch API 滥用检测报告  |  分析 API 请求: {total} 条")
    if not alerts:
        print("未发现可疑 IP。")
        return 0

    print(f"发现 {len(alerts)} 个可疑 IP：")
    for i, a in enumerate(alerts, 1):
        s = a["stats"]
        print(f"[{i}] [{a['level']}] {a['ip']}  风险分 {a['score']}/100  "
              f"(请求 {s['requests']} 次，端点 {s['endpoints']} 个，"
              f"错误 {s['errors']} 次，Key {s['keys']} 个)")
        for ev in a["evidence"]:
            print(f"    - {ev}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(alerts, f, ensure_ascii=False, indent=2)
        print(f"JSON 告警已写入: {args.output}")

    return 1 if any(a["level"] == "高危" for a in alerts) else 0


if __name__ == "__main__":
    sys.exit(main())
