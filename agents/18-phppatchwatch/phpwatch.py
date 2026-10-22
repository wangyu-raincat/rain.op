#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PHPatchWatch -- PHP 核心 RCE（CVE-2026-109618 / CVE-2026-109619，代号 PHP2Shell）
暴露面盘点与补丁就绪度评估 agent。

给定一组主机及其 PHP 版本标识（X-Powered-By / Server 头 / phpinfo 版本串），
判定每台主机是否在受影响分支、是否已打上官方紧急补丁，并给出 0-100 风险分
与升级处置建议。纯标准库，离线可跑。
"""
import argparse
import csv
import json
import re
import sys

CVE_A = "CVE-2026-109618"
CVE_B = "CVE-2026-109619"

# 各分支修复版本（官方紧急补丁，2026-10-21 22:00 北京时间发布）
FIXED = {
    (8, 5): (8, 5, 12),
    (8, 4): (8, 4, 27),
    (8, 3): (8, 3, 36),
    (8, 2): (8, 2, 35),
}
# EOL 分支：无补丁，必须升级
EOL_BRANCHES = [(8, 1), (8, 0), (7, 4), (7, 3), (7, 2), (7, 1), (7, 0), (5, 6), (5, 5)]

VER_RE = re.compile(r"PHP[\s/]*([1-9]\d*)\.(\d+)(?:\.(\d+))?", re.IGNORECASE)


def parse_version(text):
    """从版本标识串里提取 (major, minor, patch)；解析失败返回 None。"""
    if not text:
        return None
    m = VER_RE.search(text.strip())
    if not m:
        return None
    major, minor = int(m.group(1)), int(m.group(2))
    patch = int(m.group(3)) if m.group(3) else 0
    return (major, minor, patch)


def assess(version):
    """
    返回 (状态, 风险分 0-100, 修复目标, 说明)。
    状态: patched / vulnerable / eol / unknown
    """
    if version is None:
        return ("unknown", 30,
                "手工确认版本号",
                "版本标识缺失或无法解析，无法判定补丁状态")
    major, minor, patch = version
    branch = (major, minor)
    if branch in FIXED:
        fixed = FIXED[branch]
        if (major, minor, patch) >= fixed:
            return ("patched", 5,
                    "无（已修复）",
                    "版本已含官方紧急补丁")
        return ("vulnerable", 95,
                ".".join(map(str, fixed)) + " 或更高",
                "在受影响分支内且低于修复版本——有官方补丁可用，立即升级")
    if branch in EOL_BRANCHES or major < 8 or (major == 8 and minor < 2):
        return ("eol", 100,
                "升级到 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12",
                "分支已 EOL、无官方补丁；8.2 以下分支永远不会有 PHP2Shell 修复")
    if major == 8 and minor > 5:
        return ("unknown", 30,
                "手工确认",
                "未知未来分支，暂未收录修复信息")
    return ("unknown", 30, "手工确认版本号", "分支未收录")


def banner_exposed(source_text):
    """版本头是否明文暴露（X-Powered-By / Server / phpinfo）。"""
    if not source_text:
        return False
    t = source_text.lower()
    return ("x-powered-by" in t or "server:" in t or "phpinfo" in t)


def score_host(host):
    name = host.get("name", "")
    banner = host.get("banner", "")
    version = parse_version(banner)
    status, score, target, note = assess(version)
    evidence = []
    if banner:
        evidence.append("banner=%r" % banner.strip()[:60])
    if banner_exposed(banner):
        score = min(100, score + 5)
        evidence.append("版本头明文暴露（便于攻击者定向）")
    if version:
        evidence.append("解析版本=%s" % ".".join(map(str, version)))
    return {
        "name": name,
        "banner": banner.strip()[:80],
        "version": ".".join(map(str, version)) if version else "未知",
        "status": status,
        "risk": score,
        "fix_target": target,
        "evidence": evidence,
        "note": note,
    }


STATUS_ZH = {"patched": "已修复", "vulnerable": "受影响·有补丁", "eol": "受影响·EOL无补丁", "unknown": "未知"}
STATUS_TAG = {"patched": "✅", "vulnerable": "⚠️", "eol": "🔴", "unknown": "❓"}


def recommend(r):
    if r["status"] == "eol":
        return ("立即停机/迁移：该分支永无 PHP2Shell 补丁。"
                "升级到 8.2.35+ / 8.3.36+ / 8.4.27+ / 8.5.12+；"
                "过渡期用 WAF 拦截 PHP 相关 RCE 载荷并关闭 X-Powered-By。")
    if r["status"] == "vulnerable":
        return ("24 小时内升级到 %s。升级前关掉版本头暴露、"
                "WAF 拉高告警。" % r["fix_target"])
    if r["status"] == "patched":
        return "保持现状；关注后续补丁分支更新。"
    return "手工确认 PHP 版本（php -v / phpinfo），再跑一次评估。"


def render(results):
    total = len(results)
    urgent = sum(1 for r in results if r["risk"] >= 80)
    print("PHP2Shell 暴露面盘点：共 %d 台主机，%d 台需立即处置（≥80 分）\n"
          "（%s / %s，CVSS 9.2，补丁发布 2026-10-21 22:00 北京时间）\n"
          % (total, urgent, CVE_A, CVE_B))
    for r in sorted(results, key=lambda x: -x["risk"]):
        print("[%s %s] %s  风险分 %d/100  版本 %s"
              % (STATUS_TAG[r["status"]], STATUS_ZH[r["status"]],
                 r["name"], r["risk"], r["version"]))
        for e in r["evidence"]:
            print("      - %s" % e)
        print("      - %s" % r["note"])
        print("      处置建议：%s\n" % recommend(r))


DEMO_HOSTS = [
    {"name": "web-01（官网）", "banner": "X-Powered-By: PHP/8.4.27"},
    {"name": "web-02（商城）", "banner": "X-Powered-By: PHP/8.3.20"},
    {"name": "web-03（旧后台）", "banner": "Server: Apache/2.4.57 (Unix) PHP/7.4.33"},
    {"name": "api-01", "banner": "X-Powered-By: PHP/8.2.35"},
    {"name": "api-02", "banner": "X-Powered-By: PHP/8.5.10"},
    {"name": "cdn-edge-01", "banner": "Server: nginx"},
]


def load_csv(path):
    hosts = []
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            hosts.append({"name": row.get("name", "").strip(),
                          "banner": row.get("banner", "").strip()})
    return hosts


def main():
    ap = argparse.ArgumentParser(description="PHPatchWatch：PHP2Shell 暴露面与补丁就绪度评估")
    ap.add_argument("--demo", action="store_true", help="内置演示：6 台样本主机")
    ap.add_argument("--csv", help="CSV 输入（列：name,banner），banner 为版本标识串")
    ap.add_argument("--json", action="store_true", help="JSON 输出，接 SIEM")
    args = ap.parse_args()

    if args.csv:
        hosts = load_csv(args.csv)
    elif args.demo:
        hosts = DEMO_HOSTS
    else:
        ap.print_help()
        sys.exit(1)

    results = [score_host(h) for h in hosts]
    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
    else:
        render(results)


if __name__ == "__main__":
    main()
