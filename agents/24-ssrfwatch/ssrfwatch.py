#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSRFWatch —— 服务端请求伪造（SSRF）探测检测

背景：
  很多 Web 应用提供“帮用户抓一个 URL”的功能：图片代理、链接预览、
  Webhook 回调、PDF 生成、文件导入（?url=、?uri=、?target=、?next=、
  ?callback= 等参数）。如果服务端不对目标地址做校验，攻击者就能让
  服务器替自己请求本不该从外网访问的地址：
    - 云元数据服务：169.254.169.254（AWS / 阿里云 100.100.100.168、
      GCP metadata.google.internal），偷临时凭证；
    - 内网地址：127.0.0.1、localhost、10/8、172.16/12、192.168/16，
      探内网管理后台、Redis、数据库端口；
    - 危险协议：file://、gopher://、dict://、ftp://，读本地文件或
      打内网协议；
    - 绕过形态：十进制/八进制/十六进制 IP（2130706433、0177.0.0.1、
      0x7f.0.0.1）、URL 双重编码、@ 混淆（http://公网@内网地址）、
      0.0.0.0、DNS 重定向到内网的短链。

  本工具分析 Nginx/Apache combined 格式访问日志，扫描请求 URL 里的
  SSRF 征兆，给每个客户端 IP 打 0–100 风险分，输出告警与处置建议。
  纯标准库，离线可跑。

用法：
  python ssrfwatch.py --log access.log                 # 分析日志文件
  python ssrfwatch.py --log access.log --json-out out.json
  python ssrfwatch.py --demo                           # 离线演示（含合成攻击流量）
  python ssrfwatch.py --demo-log out.log               # 只生成演示日志

说明与边界：
  - 本工具只分析日志，不向任何地址发请求、不做主动探测。
  - 命中规则不等于确认 SSRF 成功：日志里没有响应体，无法确认服务
    端是否真的发起了内网请求；200 + 较大响应体只作为“疑似成功”的
    加分信号，不是定罪证据。
  - 合法的图片代理、链接预览也可能带 url= 参数指向公网地址：只打
    公网目标时仅记低分，不会误报成高危；请结合参数目标与时间窗口复核。
"""

import argparse
import json
import random
import re
import sys
from collections import defaultdict
from urllib.parse import unquote

# ---------- 征兆清单 ----------
# 可能携带目标 URL 的参数名
FETCH_PARAMS = [
    "url", "uri", "target", "next", "redirect", "callback", "webhook",
    "fetch", "proxy", "image", "file", "path", "src", "link", "feed",
    "import", "load", "download", "preview", "page", "dest", "host",
]

# 云元数据端点：AWS / 阿里云 / GCP / Azure
METADATA_RE = re.compile(
    r"169\.254\.169\.254|100\.100\.100\.168|metadata\.google\.internal|"
    r"metadata\.google|instance-data|/latest/meta-data|/latest/dynamic|"
    r"/computeMetadata|/metadata/identity|/meta-data/iam|"
    r"169\.254\.170\.2", re.I)
# 内网 / 回环地址（点分十进制）
PRIVATE_IP_RE = re.compile(
    r"(?<![\d.])("
    r"127\.\d{1,3}\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|0\.0\.0\.0|localhost|"
    r"\[::1\]|\[fe80::[^\]]*\]"
    r")(?![\d.])", re.I)
# 危险协议
DANGEROUS_SCHEME_RE = re.compile(
    r"(file|gopher|dict|ftp|tftp|expect|php|ldap|smb|netdoc|jar):", re.I)
# 绕过形态：十进制/八进制/十六进制 IP、@ 混淆、双重编码残留、0x 开头主机
BYPASS_RE = re.compile(
    r"(?<![\d.])2130706433(?![\d.])|(?<![\d.])0x7f[0-9a-f.]+|"
    r"(?<![\d.])0177\.\d+\.\d+\.\d+|(?<![\d.])3232235521(?![\d.])|"
    r"https?://[^/\s?#]+@|%25[23]f|%252f|%255c|%252e|"
    r"(?<![\d.])0\.0\.0\.0(?![\d.])", re.I)
# 内网敏感端口（出现在目标地址端口位）
SENSITIVE_PORT_RE = re.compile(
    r":(22|23|6379|3306|5432|27017|11211|2375|2376|8080|8443|"
    r"9000|9200|5601|8161|15672|5985|5986|445|1433|1521|"
    r"2049|873|53)\b")
# 内网敏感路径（目标 URL 的路径部分）
SENSITIVE_PATH_RE = re.compile(
    r"/(admin|internal|actuator|debug|console|manager|jmx-console|"
    r"env|config|phpinfo|server-status|wp-admin|api/v1/admin|"
    r"\.env|credentials|secrets)", re.I)

# 值像 URL/主机才算抓取目标：带协议、点分 IP、域名、localhost、元数据主机或绝对路径
URLISH_RE = re.compile(
    r"^[a-z][a-z0-9+.-]*://|^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"^localhost\b|^metadata\.google|^[a-z0-9-]+(\.[a-z0-9-]+)+(/|$)|"
    r"^/[^ \s]*", re.I)

COMBINED_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+) \S+" (?P<status>\d{3}) (?P<size>\S+)'
)

# 权重：每个信号给 IP 加分（上限 100）
WEIGHTS = {
    "metadata_probe": 40,   # 云元数据端点探测（偷凭证意图最强）
    "private_target": 30,   # 目标是内网/回环地址
    "dangerous_scheme": 30, # file/gopher/dict 等危险协议
    "bypass_shape": 20,     # 十进制/十六进制 IP、@ 混淆、双重编码
    "sensitive_port": 20,   # 目标端口是内网敏感服务
    "sensitive_path": 15,   # 目标路径是内网管理面
    "fetch_param": 5,       # 带抓取参数但目标是公网（低分，仅记录）
    "enum_burst": 30,       # 同一 IP 命中多种不同 SSRF 信号
    "suspected_hit": 25,    # 200 + 较大响应体（疑似服务端真的取回了内网内容）
}


def decode_twice(text):
    """解码两次，逮住双重编码的绕过；解码失败时返回原串。"""
    out = text
    for _ in range(2):
        try:
            nxt = unquote(out)
        except Exception:
            break
        if nxt == out:
            break
        out = nxt
    return out


def fetch_targets(url):
    """从请求 URL 里抽出可能的目标地址：

    返回 (targets, has_fetch_param)：targets 是参数值里看起来像 URL/
    主机的片段；没有抓取参数时返回空列表。
    """
    if "?" not in url:
        return [], False
    path, query = url.split("?", 1)
    targets, has_param = [], False
    for pair in query.split("&"):
        if "=" not in pair:
            continue
        key, val = pair.split("=", 1)
        if key.lower() not in FETCH_PARAMS:
            continue
        decoded = decode_twice(val)
        # 值必须像 URL/主机才算目标：普通分页参数（如 ?page=2）直接忽略，
        # 否则正常流量会被误记为抓取行为。
        if not URLISH_RE.search(decoded):
            continue
        has_param = True
        targets.append(decoded)
    # 整个 URL 路径本身就是代理式路径，如 /proxy/http://169.254...
    if not targets:
        decoded_path = decode_twice(path)
        if re.search(r"https?://|file:|gopher:|dict:", decoded_path, re.I):
            targets.append(decoded_path)
    return targets, has_param


def parse_line(line):
    """解析一行 combined 访问日志，返回 dict 或 None。"""
    line = line.strip()
    if not line:
        return None
    m = COMBINED_RE.match(line)
    if not m:
        return None
    try:
        size = int(m.group("size"))
    except ValueError:
        size = 0
    return {"ip": m.group("ip"), "method": m.group("method").upper(),
            "url": m.group("url"), "status": m.group("status"),
            "size": size, "raw": line}


def analyze(records):
    """核心分析：返回 {ip: {score, signals, targets, ...}}。"""
    per_ip = defaultdict(lambda: {"score": 0, "signals": defaultdict(int),
                                  "targets": set(), "examples": []})
    for rec in records:
        ip, url = rec["ip"], rec["url"]
        targets, has_param = fetch_targets(url)
        if not targets and not has_param:
            continue
        info = per_ip[ip]
        if len(info["examples"]) < 3:
            info["examples"].append(rec["raw"])

        def add(signal):
            info["signals"][signal] += 1
            info["score"] = min(100, info["score"] + WEIGHTS[signal])

        if has_param and not targets:
            add("fetch_param")
        for tgt in targets:
            info["targets"].add(tgt[:120])
            hit = False
            if METADATA_RE.search(tgt):
                add("metadata_probe")
                hit = True
            if PRIVATE_IP_RE.search(tgt):
                add("private_target")
                hit = True
            if DANGEROUS_SCHEME_RE.search(tgt):
                add("dangerous_scheme")
                hit = True
            if BYPASS_RE.search(tgt):
                add("bypass_shape")
                hit = True
            if SENSITIVE_PORT_RE.search(tgt):
                add("sensitive_port")
                hit = True
            if SENSITIVE_PATH_RE.search(tgt):
                add("sensitive_path")
                hit = True
            if not hit:
                # 抓取参数指向公网：合法代理/预览行为，仅低分记录
                add("fetch_param")
            # 疑似成功：元数据/内网目标返回 200 且响应体不小
            if hit and rec["status"] == "200" and rec["size"] >= 1000 \
                    and (METADATA_RE.search(tgt) or PRIVATE_IP_RE.search(tgt)):
                add("suspected_hit")

    # 枚举爆发：同一 IP 命中 3 种以上不同 SSRF 信号
    for ip, info in per_ip.items():
        ssrf_sigs = {s for s in info["signals"]
                     if s not in ("fetch_param",)}
        if len(ssrf_sigs) >= 3:
            info["signals"]["enum_burst"] += 1
            info["score"] = min(100, info["score"] + WEIGHTS["enum_burst"])
    return per_ip


def level(score):
    if score >= 70:
        return "高危"
    if score >= 40:
        return "中危"
    return "低危"


def advice(info):
    """按命中信号给处置建议。"""
    sigs = info["signals"]
    out = []
    if sigs.get("metadata_probe"):
        out.append("命中云元数据探测：立即核查云凭证是否泄露，轮换实例角色临时凭证，检查元数据服务访问日志。")
    if sigs.get("private_target") or sigs.get("sensitive_port"):
        out.append("命中内网目标/敏感端口：检查服务端是否真的发起了内网请求，排查内网管理后台与数据库的访问记录。")
    if sigs.get("dangerous_scheme"):
        out.append("命中危险协议：服务端抓取入口应只允许 http/https，并校验目标主机与协议。")
    if sigs.get("bypass_shape"):
        out.append("命中绕过形态：校验逻辑要先解码、解析 IP 再判断，禁止十进制/十六进制 IP 与 @ 混淆主机。")
    if sigs.get("suspected_hit"):
        out.append("疑似成功取回内网内容：按内网信息泄露处置，复核该时间段的服务端出站请求日志。")
    if not out:
        out.append("仅公网抓取参数：确认来源是否为合法代理/预览服务，误报可忽略。")
    return out


def render(per_ip, total):
    """打印中文报告，返回退出码（有高危告警返回 1）。"""
    alerts = {ip: info for ip, info in per_ip.items() if info["score"] >= 20}
    print("SSRFWatch SSRF 探测检测报告  |  分析日志: %d 条" % total)
    if not alerts:
        print("未发现可疑的 SSRF 探测。")
        return 0
    print("发现 %d 个可疑 IP:" % len(alerts))
    worst = 0
    for i, (ip, info) in enumerate(sorted(alerts.items(), key=lambda kv: -kv[1]["score"]), 1):
        lv = level(info["score"])
        worst = max(worst, info["score"])
        print("[%d] [%s] %s  风险分: %d" % (i, lv, ip, info["score"]))
        print("    信号: %s" % ", ".join("%s×%d" % (k, v) for k, v in info["signals"].items()))
        for tgt in sorted(info["targets"])[:3]:
            print("    目标: %s" % tgt)
        for a in advice(info):
            print("    建议: %s" % a)
    return 1 if worst >= 70 else 0


def gen_demo_log():
    """生成混合演示日志：正常流量 + 合法预览 + 两类攻击者。"""
    rnd = random.Random(20261028)
    lines = []
    tpl = ('{ip} - - [28/Oct/2026:09:00:{sec:02d} +0800] "{m} {u} HTTP/1.1" {s} {size}')

    def emit(ip, method, url, status, size, sec):
        lines.append(tpl.format(ip=ip, m=method, u=url, s=status, size=size, sec=sec))

    sec = 0
    # 正常用户：首页、API、静态资源
    for _ in range(30):
        sec += 1
        emit("10.0.0.21", "GET", rnd.choice(["/", "/api/orders", "/static/app.js",
                                            "/api/products?page=2"]), 200, rnd.randint(300, 9000), sec % 60)
    # 合法预览服务：只抓公网链接
    for _ in range(4):
        sec += 1
        emit("10.0.0.9", "GET",
             "/api/preview?url=https%3A%2F%2Fexample.com%2Farticle%2F123", 200, 2400, sec % 60)
    # 攻击者 A：云元数据探测（直连 + 编码 + @ 混淆），一次疑似成功
    attacker_a = "203.0.113.91"
    for url, status, size in [
            ("/api/fetch?url=http://169.254.169.254/latest/meta-data/", 200, 3120),
            ("/api/fetch?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2Fiam%2Fsecurity-credentials%2F", 200, 1890),
            ("/proxy?target=http://example.com@169.254.169.254/latest/meta-data/", 403, 0),
            ("/api/image?url=http://metadata.google.internal/computeMetadata/v1/", 200, 940),
            ("/api/fetch?url=http://2130706433/admin/", 200, 1500)]:
        sec += 1
        emit(attacker_a, "GET", url, status, size, sec % 60)
    # 攻击者 B：内网端口扫描 + 危险协议
    attacker_b = "198.51.100.17"
    for url, status, size in [
            ("/import?uri=http://127.0.0.1:6379/", 500, 0),
            ("/import?uri=http://127.0.0.1:3306/", 500, 0),
            ("/import?uri=http://192.168.1.10:8080/admin/", 200, 2100),
            ("/import?uri=file:///etc/passwd", 200, 1320),
            ("/import?uri=gopher://127.0.0.1:6379/_INFO", 500, 0),
            ("/import?uri=http://0x7f.0.0.1:2375/version", 200, 860)]:
        sec += 1
        emit(attacker_b, "GET", url, status, size, sec % 60)
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description="SSRFWatch：SSRF 探测检测")
    ap.add_argument("--log", help="访问日志文件（combined 格式）")
    ap.add_argument("--json-out", help="把告警写入 JSON 文件")
    ap.add_argument("--demo", action="store_true", help="离线演示（含合成攻击流量）")
    ap.add_argument("--demo-log", help="只生成演示日志到指定文件")
    args = ap.parse_args(argv)

    if args.demo_log:
        with open(args.demo_log, "w", encoding="utf-8") as f:
            f.write(gen_demo_log())
        print("演示日志已写入: %s" % args.demo_log)
        return 0

    if args.demo:
        text = gen_demo_log()
    elif args.log:
        with open(args.log, encoding="utf-8", errors="replace") as f:
            text = f.read()
    else:
        ap.error("请指定 --log 或 --demo")

    records = [r for r in (parse_line(ln) for ln in text.splitlines()) if r]
    per_ip = analyze(records)
    code = render(per_ip, len(records))

    if args.json_out:
        out = {ip: {"score": info["score"], "level": level(info["score"]),
                     "signals": dict(info["signals"]),
                     "targets": sorted(info["targets"]),
                     "advice": advice(info)}
               for ip, info in per_ip.items() if info["score"] >= 20}
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=2)
        print("JSON 告警已写入: %s" % args.json_out)
    return code


if __name__ == "__main__":
    sys.exit(main())
