#!/usr/bin/env python3
"""LoginBurst：Web 登录爆破 / 撞库检测。

分析 Web 访问日志中的登录请求，按源 IP 聚合，用五组启发式规则打分：

  1. 登录失败爆发：短时间内大量 401/403 登录失败
  2. 撞库特征：同一 IP 尝试大量不同用户名
  3. 爆破后成功：多次失败后出现登录成功（200），疑似已被攻破
  4. 撞库式低频试探：同一 IP 对大量账号各试 1~2 次（密码喷洒）
  5. 自动化特征：脚本类 User-Agent、缺失 UA、极高请求速率

只用 Python 标准库，离线可运行，不发起任何网络请求。

日志格式（Apache combined log 的简化版，登录路径需含 login/signin/auth）：

    203.0.113.7 - - [02/Nov/2026:08:10:01 +0800] "POST /login?user=alice HTTP/1.1" 401 512 "python-requests/2.31"

用法：

    python loginburst.py --demo                 # 内置演示日志
    python loginburst.py -i access.log          # 分析自己的日志
    python loginburst.py -i access.log -o alerts.json
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
    r'(?P<status>\d{3}) \S+ "(?P<ua>[^"]*)"'
)
USER_RE = re.compile(r'[?&](?:user|username|login|account)=([^&\s]+)')
LOGIN_PATH_RE = re.compile(r'(login|signin|sign-in|auth|oauth|session)', re.I)
AUTO_UA_RE = re.compile(
    r'(curl|wget|python-requests|httpclient|go-http|scrapy|nmap|hydra|'
    r'metasploit|sqlmap|brute|bot|crawler|spider)', re.I)

# 规则权重（分值上限合计 100）
W_FAIL_BURST = 30   # 规则 1：失败爆发
W_MANY_USERS = 25   # 规则 2：多用户名撞库
W_SUCCESS_AFTER_FAIL = 25  # 规则 3：爆破后成功
W_SPRAY = 10        # 规则 4：密码喷洒
W_AUTOMATION = 10   # 规则 5：自动化特征

FAIL_STATUSES = {"401", "403"}
SUCCESS_STATUSES = {"200", "302"}
WINDOW_SECONDS = 300          # 5 分钟滑动窗口
FAIL_BURST_THRESHOLD = 20     # 窗口内失败数达到此值即满分
MANY_USERS_THRESHOLD = 10     # 不同用户名达到此值即满分
SPRAY_MIN_USERS = 20          # 喷洒判定：不同用户名数
SPRAY_MAX_FAIL_PER_USER = 2   # 喷洒判定：每用户平均失败数上限
RATE_THRESHOLD = 60           # 窗口内总登录请求数（自动化判定）


def parse_time(ts):
    """解析 Apache 日志时间，失败返回 None。"""
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    return None


def parse_line(line):
    """解析一行日志；非登录请求或无法解析返回 None。"""
    m = LOG_RE.search(line)
    if not m:
        return None
    path = m.group("path")
    if not LOGIN_PATH_RE.search(path):
        return None
    user_m = USER_RE.search(path)
    return {
        "ip": m.group("ip"),
        "ts": parse_time(m.group("ts")),
        "method": m.group("method"),
        "path": path,
        "status": m.group("status"),
        "ua": m.group("ua"),
        "user": user_m.group(1) if user_m else None,
    }


def max_in_window(timestamps, window=WINDOW_SECONDS):
    """滑动窗口内最大请求数（时间戳需已排序，None 视为同一时刻）。"""
    ts = sorted(t for t in timestamps if t is not None)
    if not ts:
        return 0
    best, left = 0, 0
    for right in range(len(ts)):
        while (ts[right] - ts[left]).total_seconds() > window:
            left += 1
        best = max(best, right - left + 1)
    return best


def analyze(records):
    """按 IP 聚合，返回告警列表（风险分从高到低）。"""
    by_ip = defaultdict(list)
    for rec in records:
        by_ip[rec["ip"]].append(rec)

    alerts = []
    for ip, recs in by_ip.items():
        fails = [r for r in recs if r["status"] in FAIL_STATUSES]
        successes = [r for r in recs if r["status"] in SUCCESS_STATUSES]
        users = {r["user"] for r in recs if r["user"]}
        fail_users = Counter(r["user"] for r in fails if r["user"])
        uas = {r["ua"] for r in recs}
        fail_window = max_in_window([r["ts"] for r in fails])
        total_window = max_in_window([r["ts"] for r in recs])

        score, signals = 0, []

        # 规则 1：登录失败爆发
        if fail_window >= FAIL_BURST_THRESHOLD:
            score += W_FAIL_BURST
            signals.append(f"5 分钟内登录失败 {fail_window} 次（爆发阈值 {FAIL_BURST_THRESHOLD}）")
        elif fail_window >= 10:
            part = round(W_FAIL_BURST * fail_window / FAIL_BURST_THRESHOLD)
            score += part
            signals.append(f"5 分钟内登录失败 {fail_window} 次")

        # 规则 2：多用户名撞库
        if len(users) >= MANY_USERS_THRESHOLD:
            score += W_MANY_USERS
            signals.append(f"尝试不同用户名 {len(users)} 个（撞库阈值 {MANY_USERS_THRESHOLD}）")
        elif len(users) >= 5:
            score += round(W_MANY_USERS * len(users) / MANY_USERS_THRESHOLD)
            signals.append(f"尝试不同用户名 {len(users)} 个")

        # 规则 3：爆破后成功——有失败记录且出现成功，且成功发生在失败之后
        if successes and fails:
            fail_ts = [r["ts"] for r in fails if r["ts"]]
            ok_ts = [r["ts"] for r in successes if r["ts"]]
            success_after_fail = (
                (not fail_ts or not ok_ts)  # 无时间戳时按“失败后有成功”计
                or max(ok_ts) >= min(fail_ts)
            )
            if success_after_fail:
                score += W_SUCCESS_AFTER_FAIL
                signals.append(
                    f"失败 {len(fails)} 次后出现登录成功 {len(successes)} 次，疑似已被攻破")

        # 规则 4：密码喷洒——很多账号、每账号失败很少
        if len(fail_users) >= SPRAY_MIN_USERS:
            avg = len(fails) / len(fail_users) if fail_users else 0
            if avg <= SPRAY_MAX_FAIL_PER_USER:
                score += W_SPRAY
                signals.append(
                    f"密码喷洒特征：{len(fail_users)} 个账号各失败约 {avg:.1f} 次")

        # 规则 5：自动化特征
        auto_ua = any(AUTO_UA_RE.search(ua) or ua in ("", "-") for ua in uas)
        if auto_ua:
            score += W_AUTOMATION // 2
            signals.append("脚本类或缺失 User-Agent")
        if total_window >= RATE_THRESHOLD:
            score += W_AUTOMATION // 2
            signals.append(f"5 分钟内登录请求 {total_window} 次，速率异常")

        score = min(score, 100)
        level = "高危" if score >= 70 else "中危" if score >= 40 else "低危"
        if score >= 40 or (fails and len(fails) >= 10):
            alerts.append({
                "ip": ip,
                "score": score,
                "level": level,
                "total_logins": len(recs),
                "failures": len(fails),
                "successes": len(successes),
                "distinct_users": len(users),
                "signals": signals,
            })
    alerts.sort(key=lambda a: -a["score"])
    return alerts


def demo_records():
    """内置演示：1 个正常用户、1 个暴力破解、1 个密码喷洒。"""
    lines = []
    # 正常用户：2 次失败后成功
    for i, status in enumerate(("401", "401", "200")):
        lines.append(
            f'198.51.100.10 - - [02/Nov/2026:08:1{i}:0{i} +0800] '
            f'"POST /login?user=zhangsan HTTP/1.1" {status} 512 '
            f'"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"')
    # 撞库 + 爆破后成功：12 个账号各多次失败后成功，脚本 UA，集中在 3 分钟内
    for i in range(30):
        lines.append(
            f'203.0.113.7 - - [02/Nov/2026:08:2{i % 3}:{(i * 2) % 60:02d} +0800] '
            f'"POST /login?user=user{i % 12:02d} HTTP/1.1" 401 512 "python-requests/2.31"')
    lines.append(
        '203.0.113.7 - - [02/Nov/2026:08:23:00 +0800] '
        '"POST /login?user=user03 HTTP/1.1" 200 1024 "python-requests/2.31"')
    # 密码喷洒：40 个账号各失败 1 次
    for i in range(40):
        lines.append(
            f'192.0.2.99 - - [02/Nov/2026:09:0{i % 10}:{(i * 3) % 60:02d} +0800] '
            f'"POST /login?user=user{i:02d} HTTP/1.1" 401 512 "curl/8.5.0"')
    return [parse_line(ln) for ln in lines if parse_line(ln)]


def report(alerts, total_records):
    """打印中文报告。"""
    print(f"LoginBurst 登录爆破检测报告  |  分析登录请求: {total_records} 条")
    if not alerts:
        print("未发现可疑 IP。")
        return 0
    print(f"发现 {len(alerts)} 个可疑 IP：")
    for i, a in enumerate(alerts, 1):
        print(f"[{i}] [{a['level']}] {a['ip']}  风险分 {a['score']}/100  "
              f"(登录 {a['total_logins']} 次，失败 {a['failures']} 次，"
              f"成功 {a['successes']} 次，涉及账号 {a['distinct_users']} 个)")
        for s in a["signals"]:
            print(f"    - {s}")
    return 1 if any(a["level"] == "高危" for a in alerts) else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="LoginBurst：Web 登录爆破 / 撞库检测")
    ap.add_argument("-i", "--input", help="访问日志文件（默认用内置演示）")
    ap.add_argument("--demo", action="store_true", help="使用内置演示日志")
    ap.add_argument("-o", "--output", help="JSON 告警输出路径")
    args = ap.parse_args(argv)

    if args.demo or not args.input:
        records = demo_records()
    else:
        records = []
        with open(args.input, encoding="utf-8", errors="ignore") as f:
            for line in f:
                rec = parse_line(line)
                if rec:
                    records.append(rec)

    alerts = analyze(records)
    code = report(alerts, len(records))
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(alerts, f, ensure_ascii=False, indent=2)
        print(f"JSON 告警已写入: {args.output}")
    return code


if __name__ == "__main__":
    sys.exit(main())
