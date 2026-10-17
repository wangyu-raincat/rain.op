#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SEGWatch -- Cisco Secure Email Gateway 沦陷检测（针对 CVE-2026-76519）

CVE-2026-76519: Cisco Secure Email Gateway (SEG) AMP 的 File Reputation
附件处理路径存在相对路径穿越 (CWE-23)，未授权远程攻击者只需发一封
带精心构造附件的邮件穿过网关，即可在底层 OS 写任意文件并以 root
执行命令。CVSS 9.8, Cisco 定级 Critical, 已在野利用, CISA KEV 在列。

检测逻辑直接来自 Cisco 官方沦陷排查指南 + 公告中的影响条件：
  R1 沦陷指示器：system_logs 中 "System Security" 行命中
      "Suspected compromise indicator was found" / "Compromise detected."（不区分大小写）
  R2 附件异常：文件名含路径穿越序列 (../、..\\、URL 编码变体、绝对路径)，
      或同一发件人短时间多封带附件邮件（可疑投递）
  R3 网关外联异常：网关向未知外部 IP 上传/下载（Cisco 明确建议查这一项）；
      新出现的外部目标、非工作时间传输额外加权
  R4 暴露面自查：File Reputation 启用 + Content Scanner Tools < 25.3.0.5525
      → 标记"可被利用"，有其它命中时风险分保底上浮

输入格式（均为纯文本, 可离线跑; --demo 自带合成数据）：
  system 日志:  ts=<ISO> gateway=<网关名> msg=<消息>
  邮件日志   :  ts=<ISO> gateway=<网关名> sender=<发件人> file=<附件名> size=<字节>
  流量日志   :  ts=<ISO> gateway=<网关名> dst=<目标IP> direction=upload|download bytes=<字节>
  配置快照   :  JSON {"gateway": "...", "file_reputation": true, "content_scanner": "25.2.1.1000"}

只用 Python 标准库。

用法:
    python segwatch.py --demo
    python segwatch.py --syslog sys.log --maillog mail.log --flows flow.log --config cfg.json
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime

# ---------------------------------------------------------------- 规则常量
COMPROMISE_PATTERNS = [
    "suspected compromise indicator was found",
    "compromise detected.",
]

TRAVERSAL_PATTERNS = [
    r"\.\./", r"\.\.\\",           # ../ ..\
    r"%2e%2e%2f", r"%2e%2e%5c",    # URL 编码变体（大小写不敏感）
    r"\.\.%2f", r"\.\.%5c",          # 混合编码: ..%2f ..%5c
    r"%252e%252e%252f",            # 双重编码
    r"/etc/", r"/root/", r"/tmp/", # 绝对路径（类 Unix）
    r"%00",                       # 空字节截断
    r"^[a-z]:\\",                  # C:\ 绝对路径（Windows）
]

# 可信的 Cisco / 常见更新服务网段(示例)，演示用
KNOWN_GOOD_PREFIXES = ("208.64.2", "173.37.", "72.163.", "10.", "192.168.", "172.16.")

SAFE_SCANNER_VERSION = (25, 3, 0, 5525)  # Content Scanner Tools 修复版

RULE_ACTIONS = {
    "R1-沦陷指示器": "【立即处置】隔离该网关(断开集群/管理网), 按 Cisco 官方指南重建可信配置; "
                      "轮换集群内全部凭证与 SSH 密钥 —— Cisco 警告 SSH 私钥可能已泄露。",
    "R2-附件穿越":   "隔离命中邮件/附件, 检查网关文件系统是否被写入异常文件, "
                      "并在防火墙侧追查同发件人的其它邮件。",
    "R2-附件轰炸":   "同一发件人短时间内连发多封带附件邮件, 考虑在网关策略层临时拦截该发件人。",
    "R3-外联异常":   "核查防火墙日志确认上传/下载目标与内容, 封锁可疑外部 IP, "
                      "注意攻击者可能已抹掉本机日志 —— 以网络侧日志为准。",
    "R4-可被利用":   "尽快升级 Content Scanner Tools ≥ 25.3.0.5525(无需重启) "
                      "或 AsyncOS 到 15.5.5-014 / 16.5.0-780; 应急可先关闭 File Reputation 缓解。",
}


# ---------------------------------------------------------------- 解析
def parse_kv(line):
    """解析 ts=... gateway=... key=value 的行, 返回 dict(键均小写)。
    msg= 字段取行尾全部内容（消息本身可含空格）。"""
    out = {}
    line = line.strip()
    m = re.search(r"\bmsg=", line)
    tail = ""
    if m:
        tail = line[m.end():]
        line = line[:m.start()]
    for token in line.split():
        if "=" in token:
            k, v = token.split("=", 1)
            out[k.lower()] = v
    if tail:
        out["msg"] = tail
    return out


def parse_version(s):
    """'25.2.1.1000' -> (25,2,1,1000)，解析失败返回 (0,)。"""
    try:
        return tuple(int(x) for x in re.split(r"[.\-]", s) if x.isdigit())
    except Exception:
        return (0,)


def ts_hour(ts):
    """从 ISO 时间取小时，失败返回 -1。"""
    try:
        return datetime.fromisoformat(ts).hour
    except Exception:
        return -1


def looks_traversal(filename):
    fname = filename.lower()
    for pat in TRAVERSAL_PATTERNS:
        if re.search(pat, fname, re.IGNORECASE):
            return pat
    return None


def is_unknown_dst(dst):
    return not dst.startswith(KNOWN_GOOD_PREFIXES)


# ---------------------------------------------------------------- 检测
class HostResult:
    def __init__(self, gateway):
        self.gateway = gateway
        self.score = 0
        self.exploitable = False
        self.hits = []  # (rule, evidence)
        self._detail = []  # (rule, evidence, points) 用于同规则 cap

    def add(self, rule, evidence, points, cap=None):
        self.hits.append((rule, evidence))
        if cap is not None:
            # 同规则累计贡献不超过 cap
            so_far = sum(p for r, _, p in self._detail if r == rule)
            points = max(0, min(points, cap - so_far))
        self._detail.append((rule, evidence, points))
        self.score = min(100, self.score + points)

    def finalize(self):
        # 暴露面可被利用 + 有其它命中 → 风险分保底 85（CVE-2026-76519 两个条件缺一不可，
        # 都满足意味着攻击者只要发一封邮件就能打穿）
        if self.exploitable and any(r.startswith(("R1", "R2", "R3")) for r, _ in self.hits):
            self.score = max(self.score, 85)


def analyze(sys_lines, mail_lines, flow_lines, configs):
    results = {}

    def host(gw):
        if gw not in results:
            results[gw] = HostResult(gw)
        return results[gw]

    # ---- R1: 沦陷指示器（system_logs）
    for line in sys_lines:
        f = parse_kv(line)
        if not f.get("msg") or not f.get("gateway"):
            continue
        msg = f["msg"].lower()
        if "system security" not in msg:
            continue
        for pat in COMPROMISE_PATTERNS:
            if pat in msg:
                host(f["gateway"]).add(
                    "R1-沦陷指示器",
                    "system_logs: %s" % line.strip()[:160],
                    60, cap=80,
                )
                break

    # ---- R2: 附件异常
    sender_times = defaultdict(list)  # (gateway, sender) -> [datetime]
    for line in mail_lines:
        f = parse_kv(line)
        if not f.get("gateway") or not f.get("file"):
            continue
        gw = f["gateway"]
        hit = looks_traversal(f["file"])
        if hit:
            host(gw).add(
                "R2-附件穿越",
                "附件名命中穿越模式 %r: %s" % (hit, line.strip()[:160]),
                15, cap=40,
            )
        # 附件轰炸：同一发件人 10 分钟内 >=3 封带附件邮件
        sender = f.get("sender", "?")
        try:
            t = datetime.fromisoformat(f["ts"])
        except Exception:
            continue
        key = (gw, sender)
        sender_times[key] = [x for x in sender_times[key]
                             if (t - x).total_seconds() < 600]
        sender_times[key].append(t)
        if len(sender_times[key]) == 3:  # 只在刚好达到阈值时告警一次
            host(gw).add(
                "R2-附件轰炸",
                "发件人 %s 10 分钟内连发 %d 封带附件邮件" % (sender, len(sender_times[key])),
                10, cap=20,
            )

    # ---- R3: 网关外联异常
    seen_baseline = defaultdict(set)  # gateway -> 已见外部目标
    for line in flow_lines:
        f = parse_kv(line)
        if not f.get("gateway") or not f.get("dst"):
            continue
        gw, dst = f["gateway"], f["dst"]
        if not is_unknown_dst(dst):
            continue
        try:
            size = int(f.get("bytes", "0"))
        except ValueError:
            size = 0
        pts = 8
        notes = ["网关 %s 向未知外部 IP %s %s %d bytes" % (
            gw, dst, f.get("direction", "?"), size)]
        if dst not in seen_baseline[gw]:
            pts += 4
            notes.append("新出现的外联目标")
        hour = ts_hour(f.get("ts", ""))
        if 0 <= hour < 6:
            pts += 4
            notes.append("非工作时间传输")
        if f.get("direction") == "upload" and size > 10 * 1024 * 1024:
            pts += 6
            notes.append("向未知外部大额上传")
        seen_baseline[gw].add(dst)
        host(gw).add("R3-外联异常", "; ".join(notes), pts, cap=35)

    # ---- R4: 暴露面自查（配置快照）
    for cfg in configs:
        gw = cfg.get("gateway")
        if not gw:
            continue
        fr = bool(cfg.get("file_reputation"))
        ver = parse_version(str(cfg.get("content_scanner", "")))
        if fr and ver < SAFE_SCANNER_VERSION:
            h = host(gw)
            h.exploitable = True
            h.hits.append((
                "R4-可被利用",
                "File Reputation=启用, Content Scanner Tools=%s (< 25.3.0.5525)"
                % cfg.get("content_scanner"),
            ))
        elif fr:
            host(gw).hits.append((
                "R4-信息",
                "File Reputation=启用, Content Scanner Tools=%s (已修复)" % cfg.get("content_scanner"),
            ))

    for h in results.values():
        h.finalize()
    return results


# ---------------------------------------------------------------- 演示数据
def demo_data():
    sys_lines = [
        "ts=2026-10-16T09:12:03 gateway=seg-01 msg=System Security: periodic health check passed",
        "ts=2026-10-16T09:15:44 gateway=seg-01 msg=mail flow normal, 1420 messages processed",
        "ts=2026-10-16T14:02:11 gateway=seg-02 msg=System Security: Suspected compromise indicator was found in AMP file reputation cache",
        "ts=2026-10-16T14:03:52 gateway=seg-02 msg=System Security: Compromise detected. content scanner child process spawned unexpected shell",
        "ts=2026-10-16T15:20:00 gateway=seg-01 msg=System Security: signature update completed",
    ]
    mail_lines = [
        "ts=2026-10-16T09:30:00 gateway=seg-01 sender=alice@example.com file=Q3_report.pdf size=482112",
        "ts=2026-10-16T10:05:12 gateway=seg-01 sender=bob@example.com file=invoice_1016.xlsx size=88320",
        "ts=2026-10-16T13:55:01 gateway=seg-02 sender=evil@attacker.tld file=doc.pdf size=1024",
        "ts=2026-10-16T13:58:20 gateway=seg-02 sender=evil@attacker.tld file=..%2f..%2f..%2ftmp%2fx.pdf size=2048",
        "ts=2026-10-16T14:01:33 gateway=seg-02 sender=evil@attacker.tld file=..\\..\\..\\Windows\\Temp\\a.dat size=4096",
        "ts=2026-10-16T14:04:10 gateway=seg-02 sender=evil@attacker.tld file=%2e%2e%2f%2e%2e%2fbin%2fsh size=8192",
        "ts=2026-10-16T16:40:00 gateway=seg-02 sender=newsletter@vendor.com file=oct_update.zip size=556032",
    ]
    flow_lines = [
        "ts=2026-10-16T09:20:00 gateway=seg-01 dst=208.64.200.10 direction=download bytes=5242880",
        "ts=2026-10-16T10:00:00 gateway=seg-01 dst=173.37.100.5 direction=download bytes=1048576",
        "ts=2026-10-16T02:15:44 gateway=seg-02 dst=185.220.70.9 direction=upload bytes=157286400",
        "ts=2026-10-16T02:40:02 gateway=seg-02 dst=91.121.44.17 direction=download bytes=20971520",
        "ts=2026-10-16T14:10:30 gateway=seg-02 dst=185.220.70.9 direction=upload bytes=8388608",
    ]
    configs = [
        {"gateway": "seg-01", "file_reputation": True, "content_scanner": "25.3.0.5525"},
        {"gateway": "seg-02", "file_reputation": True, "content_scanner": "25.2.1.1000"},
    ]
    return sys_lines, mail_lines, flow_lines, configs


# ---------------------------------------------------------------- 输出
def verdict(score):
    if score >= 85:
        return "🔴 极高危（疑似已被打穿）"
    if score >= 60:
        return "🟠 高危"
    if score >= 30:
        return "🟡 中危"
    if score > 0:
        return "🟢 低危"
    return "✅ 未见异常"


def report(results):
    print("=" * 64)
    print("SEGWatch 检测报告（CVE-2026-76519 Cisco 邮件网关沦陷检测）")
    print("=" * 64)
    for gw in sorted(results):
        h = results[gw]
        tag = "【可被利用】" if h.exploitable else ""
        print("\n网关 %s%s  风险分: %d/100  %s" % (gw, tag, h.score, verdict(h.score)))
        print("-" * 64)
        if not h.hits:
            print("  无命中。")
            continue
        for rule, ev in h.hits:
            action = RULE_ACTIONS.get(rule)
            print("  [%s] %s" % (rule, ev))
            if action:
                print("      → %s" % action)


def main(argv=None):
    ap = argparse.ArgumentParser(description="SEGWatch: CVE-2026-76519 网关沦陷检测")
    ap.add_argument("--demo", action="store_true", help="用内置合成数据演示")
    ap.add_argument("--syslog", help="system 日志文件")
    ap.add_argument("--maillog", help="邮件/附件日志文件")
    ap.add_argument("--flows", help="网关外联流量日志文件")
    ap.add_argument("--config", help="配置快照 JSON 文件")
    args = ap.parse_args(argv)

    if args.demo or not any([args.syslog, args.maillog, args.flows, args.config]):
        sys_lines, mail_lines, flow_lines, configs = demo_data()
        print("[*] 演示模式：使用内置合成数据（离线可运行）\n")
    else:
        def load(p):
            if not p:
                return []
            with open(p, encoding="utf-8", errors="replace") as fh:
                return fh.readlines()
        sys_lines = load(args.syslog)
        mail_lines = load(args.maillog)
        flow_lines = load(args.flows)
        configs = []
        if args.config:
            with open(args.config, encoding="utf-8") as fh:
                data = json.load(fh)
            configs = data if isinstance(data, list) else [data]

    results = analyze(sys_lines, mail_lines, flow_lines, configs)
    report(results)
    return 0


if __name__ == "__main__":
    sys.exit(main())
