#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FireboxWatch —— WatchGuard Firebox 严重漏洞探测嫌疑检测

背景：
  WatchGuard 于 2026-10-27 批量发布 Fireware OS 安全公告，其中 7 项
  严重漏洞（CVSS 9.1–9.5，厂商称无已知在野利用）涉及 Firebox 的多个
  网络-facing 服务。本工具分析 Firebox 日志，从日志征兆中识别与这
  7 项漏洞对应的探测嫌疑，按源 IP 打 0–100 风险分：

    信号              CVE                    组件 / 征兆
    ad_crash          CVE-2026-112709/112710  AD 认证服务登录前崩溃/异常（9.2）
    sip_anomaly       CVE-2026-93857         SIP 代理异常突发（9.2）
    cluster_unauth    CVE-2026-93865         FireCluster 非集群 IP 同步尝试（9.2）
    portal_anomaly    CVE-2026-93866         Access Portal 异常请求（9.2）
    log_gap           CVE-2026-103593        日志服务崩溃 / 日志断档（9.1）
    wg_anomaly        CVE-2026-103594        WireGuard 配置处理异常（9.5）
    ad_burst          （同 AD 两项的辅助信号）同一 IP 登录前认证失败爆发

  WireGuard 项的可达条件与其余几项不同：据公开报道，它需要经过
  Firebox 与 WatchGuard Cloud 之间的 TLS 解密通道才可达，不等于
  任意外网未认证直达；因此它的告警建议里会单独注明这一点，不要
  把它当成普通外网未认证 RCE 来处置。

用法：
  python fireboxwatch.py --log firebox.log
  python fireboxwatch.py --log firebox.log --json-out alerts.json
  python fireboxwatch.py --demo
  python fireboxwatch.py --demo-log demo.log

说明与边界：
  - 本工具只分析日志，不向任何地址发请求、不做主动探测。
  - 命中规则只是“探测嫌疑”，不是入侵定论：服务崩溃也可能由配置
    错误、异常流量或正常运维触发；请结合补丁版本、时间窗口与设备
    侧的崩溃转储复核。
  - 补丁版本（2026.4 / 12.12.4，T15/T35 用 12.5.22）以 WatchGuard
    厂商 advisory 为准；本工具不判定设备是否已打补丁，只提示核查。
  - 纯标准库，离线可跑。
"""

import argparse
import json
import re
import sys
from collections import defaultdict

# ---------- 信号定义：CVE、CVSS、权重、建议 ----------
SIGNALS = {
    "ad_crash": {
        "cve": "CVE-2026-112709 / CVE-2026-112710", "cvss": "9.2",
        "weight": 35, "label": "AD 认证服务崩溃/异常",
        "advice": "命中 AD 认证服务异常：核查该时段 admd 崩溃记录与登录前请求，"
                  "确认 Fireware 是否已升级到厂商修复版本，并排查认证服务重启后"
                  "的异常会话。",
    },
    "sip_anomaly": {
        "cve": "CVE-2026-93857", "cvss": "9.2",
        "weight": 30, "label": "SIP 代理异常",
        "advice": "命中 SIP 代理异常：核查 SIP 代理的畸形报文与崩溃记录，确认是否"
                  "有外部 IP 在向 SIP 端口发送异常流量，必要时先限制 SIP 暴露面。",
    },
    "cluster_unauth": {
        "cve": "CVE-2026-93865", "cvss": "9.2",
        "weight": 35, "label": "FireCluster 非集群同步尝试",
        "advice": "命中 FireCluster 非集群同步：该信号对应未认证即可注入 root 级操作"
                  "的缺陷，立即核查集群互联口是否暴露给非集群地址，并确认集群"
                  "成员配置未被改动。",
    },
    "portal_anomaly": {
        "cve": "CVE-2026-93866", "cvss": "9.2",
        "weight": 30, "label": "Access Portal 异常请求",
        "advice": "命中 Access Portal 异常：核查 Portal 的超大/畸形请求与越界写征兆，"
                  "确认 Portal 是否对公网开放，必要时先收紧访问来源。",
    },
    "log_gap": {
        "cve": "CVE-2026-103593", "cvss": "9.1",
        "weight": 25, "label": "日志服务崩溃/断档",
        "advice": "命中日志服务异常：日志断档本身会掩盖其他攻击痕迹，先恢复日志"
                  "服务并补采该时段的设备侧日志，再回查同一窗口的其他信号。",
    },
    "wg_anomaly": {
        "cve": "CVE-2026-103594", "cvss": "9.5",
        "weight": 40, "label": "WireGuard 配置处理异常",
        "advice": "命中 WireGuard 配置异常：注意该项可达条件不同——需经 Firebox 与 "
                  "WatchGuard Cloud 之间的 TLS 解密通道才可达，不等于任意外网"
                  "未认证直达；核查云侧通道与 WireGuard 配置下发记录后再定级。",
    },
    "ad_burst": {
        "cve": "CVE-2026-112709 / CVE-2026-112710", "cvss": "9.2",
        "weight": 20, "label": "AD 登录前认证失败爆发",
        "advice": "同一 IP 登录前认证失败爆发：结合 ad_crash 一起看，若同时出现"
                  "服务崩溃则优先处置；单独出现时也可能是口令喷洒，先看频率与"
                  "账号分布。",
    },
}

IP_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
CRASH_RE = re.compile(r"crash|segfault|segmentation|buffer overflow|heap|"
                      r"stack overflow|out-of-bounds|out of bounds|restarted|"
                      r"exited unexpectedly|died|core dump", re.I)
ANOMALY_RE = re.compile(r"crash|malformed|oversized|parse error|parse failed|"
                         r"integer overflow|out-of-bounds|out of bounds|"
                         r"buffer overflow|invalid|truncated", re.I)


def _has(text, *words):
    return any(w in text for w in words)


def detect_signals(line):
    """返回一行日志命中的信号列表（不含需要计数的爆发类信号）。"""
    low = line.lower()
    found = []
    if _has(low, "admd", "active directory", "directory service", "ad auth"):
        if CRASH_RE.search(low):
            found.append("ad_crash")
    if _has(low, "sip proxy", "sipd", "sip "):
        if ANOMALY_RE.search(low) or "sip proxy" in low and "error" in low:
            found.append("sip_anomaly")
    if _has(low, "firecluster", "cluster sync", "cluster daemon"):
        if _has(low, "unauthenticated", "not a cluster member",
                "unknown member", "non-cluster", "sync rejected",
                "not in cluster", "unauthorized"):
            found.append("cluster_unauth")
    if _has(low, "access portal", "portal"):
        if ANOMALY_RE.search(low) or "portal" in low and "error" in low:
            found.append("portal_anomaly")
    if _has(low, "logd", "logging service", "syslog service", "log service"):
        if CRASH_RE.search(low) or "stopped" in low or "gap" in low:
            found.append("log_gap")
    if _has(low, "wireguard", "wire guard") or re.search(r"\bwg\b", low):
        if _has(low, "config") and ANOMALY_RE.search(low):
            found.append("wg_anomaly")
    return found


def analyze(lines):
    """返回 (per_ip, device_events, total)。"""
    per_ip = defaultdict(lambda: {"score": 0, "signals": defaultdict(int),
                                  "examples": []})
    device_events = []
    ad_fail_count = defaultdict(int)
    for line in lines:
        line = line.rstrip("\n")
        if not line.strip():
            continue
        low = line.lower()
        ip_match = IP_RE.search(line)
        signals = detect_signals(line)
        # 登录前 AD 认证失败：先计数，满 5 次再记为爆发信号
        if ip_match and "authentication failed" in low \
                and _has(low, "admd", "active directory", "ad auth") \
                and ("pre-auth" in low or "before login" in low):
            ad_fail_count[ip_match.group(1)] += 1
        if not signals:
            continue
        if not ip_match:
            # 无源 IP 的设备级事件（如日志服务本机崩溃）：单列，不归因到 IP
            device_events.append((signals[0], line.strip()))
            continue
        ip = ip_match.group(1)
        info = per_ip[ip]
        for sig in signals:
            info["signals"][sig] += 1
            if len(info["examples"]) < 5:
                info["examples"].append(line.strip())
    # 计分：权重按命中次数递减计入（首条全额，后续每条 5 分），上限 100
    for ip, info in per_ip.items():
        score = 0
        for sig, count in info["signals"].items():
            w = SIGNALS[sig]["weight"]
            score += w + 5 * (count - 1)
        if ad_fail_count.get(ip, 0) >= 5:
            info["signals"]["ad_burst"] = ad_fail_count[ip]
            score += SIGNALS["ad_burst"]["weight"]
        distinct = [s for s in info["signals"] if s in SIGNALS]
        if len(distinct) >= 3:
            score += 15  # 多信号交叉：系统性探测嫌疑
        info["score"] = min(100, score)
    return per_ip, device_events, len(lines)


def level(score):
    if score >= 70:
        return "高危"
    if score >= 40:
        return "中危"
    return "低危"


def report(per_ip, device_events, total, json_out=None):
    alerts = {ip: info for ip, info in per_ip.items()
              if info["score"] >= 20}
    print("FireboxWatch Firebox 漏洞探测嫌疑报告  |  分析日志: %d 条" % total)
    if device_events:
        print("设备级事件（无源 IP，未计入 IP 风险分）: %d 条" % len(device_events))
        for sig, line in device_events[:5]:
            print("  [%s] %s" % (SIGNALS[sig]["label"], line))
    if not alerts:
        print("未发现可疑 IP。")
    else:
        print("发现 %d 个可疑 IP:" % len(alerts))
        worst = 0
        for i, (ip, info) in enumerate(
                sorted(alerts.items(), key=lambda kv: -kv[1]["score"]), 1):
            worst = max(worst, info["score"])
            sig_text = ", ".join("%s×%d" % (s, c)
                                 for s, c in sorted(info["signals"].items()))
            print("[%d] [%s] %s  风险分: %d" % (i, level(info["score"]), ip,
                                                info["score"]))
            print("    信号: %s" % sig_text)
            for sig in sorted(info["signals"]):
                meta = SIGNALS[sig]
                print("    %s（%s，CVSS %s）" % (meta["label"], meta["cve"],
                                                meta["cvss"]))
            seen_advice = set()
            for sig in sorted(info["signals"]):
                advice = SIGNALS[sig]["advice"]
                if advice not in seen_advice:
                    seen_advice.add(advice)
                    print("    建议: %s" % advice)
        if json_out:
            data = {ip: {"score": info["score"], "level": level(info["score"]),
                         "signals": dict(info["signals"]),
                         "examples": info["examples"]}
                    for ip, info in alerts.items()}
            with open(json_out, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            print("JSON 告警已写入: %s" % json_out)
        return 1 if worst >= 70 else 0
    if json_out:
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump({}, f, ensure_ascii=False, indent=2)
        print("JSON 告警已写入: %s" % json_out)
    return 0


DEMO_LINES = [
    # 正常流量：管理员登录、正常 SIP 通话、正常 Portal 登录
    "2026-10-29 09:00:01 firebox admd[101]: user admin authentication succeeded from 10.0.0.5",
    "2026-10-29 09:00:02 firebox sipd[102]: SIP call established from 10.0.0.6 to 10.0.0.7",
    "2026-10-29 09:00:03 firebox portald[103]: Access Portal login succeeded from 10.0.0.8",
    "2026-10-29 09:00:04 firebox wgd[104]: WireGuard peer 10.0.0.9 handshake ok",
    # 攻击者 A：AD 认证服务崩溃 + 登录前失败爆发
    "2026-10-29 09:01:10 firebox admd[101]: Active Directory authentication service crash (heap buffer overflow) pre-auth request from 203.0.113.45",
    "2026-10-29 09:01:11 firebox admd[101]: admd restarted after crash, request from 203.0.113.45",
    "2026-10-29 09:01:12 firebox admd[101]: Active Directory authentication failed pre-auth from 203.0.113.45",
    "2026-10-29 09:01:13 firebox admd[101]: Active Directory authentication failed pre-auth from 203.0.113.45",
    "2026-10-29 09:01:14 firebox admd[101]: Active Directory authentication failed pre-auth from 203.0.113.45",
    "2026-10-29 09:01:15 firebox admd[101]: Active Directory authentication failed pre-auth from 203.0.113.45",
    "2026-10-29 09:01:16 firebox admd[101]: Active Directory authentication failed pre-auth from 203.0.113.45",
    # 攻击者 B：SIP 代理异常 + Access Portal 异常
    "2026-10-29 09:02:20 firebox sipd[102]: SIP proxy parse error malformed packet from 198.51.100.22",
    "2026-10-29 09:02:21 firebox sipd[102]: SIP proxy crash (stack buffer overflow) from 198.51.100.22",
    "2026-10-29 09:02:22 firebox portald[103]: Access Portal integer overflow error oversized request from 198.51.100.22",
    "2026-10-29 09:02:23 firebox portald[103]: Access Portal malformed request error from 198.51.100.22",
    # 攻击者 C：FireCluster 非集群同步 + 日志服务崩溃 + WireGuard 配置异常
    "2026-10-29 09:03:30 firebox clusterd[105]: FireCluster sync rejected: unauthenticated sync attempt, not a cluster member, from 192.0.2.77",
    "2026-10-29 09:03:31 firebox logd[106]: logging service crash, log gap detected, request from 192.0.2.77",
    "2026-10-29 09:03:32 firebox wgd[104]: WireGuard config parse error oversized configuration from 192.0.2.77",
    # 设备级事件：日志服务本机崩溃（无源 IP，单列提示）
    "2026-10-29 09:03:33 firebox logd[106]: logging service crash, restarted",
]


def main(argv=None):
    ap = argparse.ArgumentParser(description="FireboxWatch：Firebox 漏洞探测嫌疑检测")
    ap.add_argument("--log", help="Firebox 日志文件路径")
    ap.add_argument("--json-out", help="JSON 告警输出路径")
    ap.add_argument("--demo", action="store_true", help="离线演示（含合成攻击流量）")
    ap.add_argument("--demo-log", help="只生成演示日志到指定文件")
    args = ap.parse_args(argv)
    if args.demo_log:
        with open(args.demo_log, "w", encoding="utf-8") as f:
            f.write("\n".join(DEMO_LINES) + "\n")
        print("演示日志已写入: %s（%d 条）" % (args.demo_log, len(DEMO_LINES)))
        return 0
    if args.demo:
        per_ip, device_events, total = analyze(DEMO_LINES)
        return report(per_ip, device_events, total, args.json_out)
    if args.log:
        with open(args.log, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        per_ip, device_events, total = analyze(lines)
        return report(per_ip, device_events, total, args.json_out)
    ap.error("请指定 --log 或 --demo")
    return 2


if __name__ == "__main__":
    sys.exit(main())
