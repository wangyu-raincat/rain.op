#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ActuatorWatch —— Spring Boot Actuator 暴露面探测检测

背景：
  Spring Boot Actuator 把应用的健康检查、环境变量、配置属性、线程转储、
  堆转储等管理端点暴露为 HTTP 接口。本意是给运维用，但一旦在生产环境
  未加鉴权就对外开放，攻击者可以：
    - GET /actuator/env、/actuator/configprops 窃取数据库密码、云密钥；
    - GET /actuator/heapdump 拿到堆内存转储，离线翻出明文凭证；
    - POST /actuator/env + /actuator/refresh 篡改配置（经典的
      spring.cloud.bootstrap.location / eureka.client.serviceUrl 注入链，
      可导致 RCE）；
    - POST /actuator/gateway/routes 注入 SpEL 表达式
      （Spring Cloud Gateway CVE-2022-22947）；
    - POST /actuator/shutdown / /actuator/restart 搞停服务。

  本工具分析 Nginx/Apache combined 格式访问日志，用启发式规则给每个
  客户端 IP 打 0–100 风险分，输出告警与处置建议。纯标准库，离线可跑。

用法：
  python actuatorwatch.py --log access.log                 # 分析日志文件
  python actuatorwatch.py --log access.log --json-out out.json
  python actuatorwatch.py --demo                           # 离线演示（含合成攻击流量）
  python actuatorwatch.py --demo-log out.log               # 只生成演示日志

说明与边界：
  - 本工具只分析日志，不向任何地址发请求、不做主动探测。
  - 命中规则不等于确认入侵：内网监控、合法运维、健康检查探针也可能
    命中；请结合 IP 归属与时间窗口复核后再处置。
  - 日志里没有响应体，无法确认 env/heapdump 是否真的吐出了敏感信息；
    200 + 大响应体只作为“疑似成功窃取”的加分信号，不是定罪证据。
"""

import argparse
import json
import random
import re
import sys
from collections import defaultdict

# ---------- 端点清单 ----------
# 读敏感：GET 一下就可能泄露信息
READ_SENSITIVE = [
    "env", "configprops", "heapdump", "threaddump", "mappings",
    "beans", "sessions", "trace", "httptrace", "loggers",
    "flyway", "liquibase", "caches", "conditions", "scheduledtasks",
]
# 写危险：POST 就可能改配置、重启、停服务
WRITE_DANGEROUS = [
    "env", "refresh", "restart", "shutdown", "gateway/routes",
    "gateway/refresh", "loggers", "caches",
]
# 相对无害但常被枚举：健康检查类
BENIGN_PROBE = ["health", "info", "metrics", "prometheus"]

ACTUATOR_PREFIX_RE = re.compile(
    r"/(?:actuator|manage|admin|management|api/actuator|actuator-management)(/|$)", re.I)
# 绕过形态：/actuator/../、双斜杠、URL 编码点、大小写混写、后缀绕过
BYPASS_RE = re.compile(
    r"/actuator/\.\.|//actuator|/%2e/actuator|/actuator%2f|/actuator\.|"
    r"/\.+/actuator|/actuator;|/manage/|/admin/actuator", re.I)
# 载荷征兆：SpEL / 配置注入关键字（出现在 URL 或查询串里）
PAYLOAD_RE = re.compile(
    r"spel|expression|spring\.cloud\.bootstrap\.location|eureka\.client\.serviceUrl|"
    r"management\.endpoint|spring\.datasource|password|secret|%24%7B|"
    r"\$\{.*\}|Runtime|ProcessBuilder", re.I)

COMBINED_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+) \S+" (?P<status>\d{3}) (?P<size>\S+)'
)

# 权重：每个信号给 IP 加分（上限 100）
WEIGHTS = {
    "read_sensitive": 20,    # GET 敏感端点
    "write_dangerous": 40,  # POST 危险端点（改配置/重启/停服）
    "spel_payload": 30,      # URL 里带 SpEL / 配置注入关键字
    "enum_burst": 30,        # 短窗口内枚举多个不同端点
    "bypass_shape": 20,      # 路径绕过形态
    "big_dump": 25,          # 200 + 超大响应体（疑似 heapdump 成功）
    "benign_probe": 5,       # 健康检查类枚举（低分，仅作记录）
}


def endpoint_of(url):
    """从 URL 里抽出 actuator 端点名，如 /actuator/env -> env；非 actuator 返回 None。"""
    path = url.split("?", 1)[0]
    m = re.search(r"/actuator/(.+)$", path, re.I)
    if m:
        return m.group(1).strip("/").lower()
    if BYPASS_RE.search(path):
        return "__bypass__"
    return None


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
    """核心分析：返回 {ip: {score, signals, endpoints, ...}}。"""
    per_ip = defaultdict(lambda: {"score": 0, "signals": defaultdict(int),
                                  "endpoints": set(), "examples": []})
    for rec in records:
        ip, method, url = rec["ip"], rec["method"], rec["url"]
        ep = endpoint_of(url)
        info = per_ip[ip]
        if ep is None and not BYPASS_RE.search(url):
            continue
        info["endpoints"].add(ep or "?")
        if len(info["examples"]) < 3:
            info["examples"].append(rec["raw"])

        def add(signal):
            info["signals"][signal] += 1
            info["score"] = min(100, info["score"] + WEIGHTS[signal])

        if ep == "__bypass__" or BYPASS_RE.search(url):
            add("bypass_shape")
        if ep in READ_SENSITIVE and method == "GET":
            add("read_sensitive")
        if ep in WRITE_DANGEROUS and method == "POST":
            add("write_dangerous")
        if ep in BENIGN_PROBE and method == "GET":
            add("benign_probe")
        if PAYLOAD_RE.search(url):
            add("spel_payload")
        # 200 + 大响应体：heapdump / env 成功窃取的疑似信号
        if rec["status"] == "200" and rec["size"] >= 1_000_000 and ep in ("heapdump", "env", "configprops"):
            add("big_dump")

    # 枚举爆发：同一 IP 命中 4 个以上不同端点
    for ip, info in per_ip.items():
        real_eps = {e for e in info["endpoints"] if e != "__bypass__"}
        if len(real_eps) >= 4:
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
    if sigs.get("write_dangerous"):
        out.append("立即核查配置是否被篡改，检查 env/refresh/gateway 路由变更记录，必要时回滚并重启。")
    if sigs.get("spel_payload"):
        out.append("检查应用日志有无 SpEL 执行痕迹，排查新增路由与异常进程。")
    if sigs.get("big_dump"):
        out.append("heapdump/env 疑似成功下载：按凭证泄露处置，轮换数据库密码与云密钥。")
    if sigs.get("read_sensitive") or sigs.get("enum_burst"):
        out.append("确认 actuator 是否误对外开放：收紧到内网/鉴权，关闭不必要的端点。")
    if not out:
        out.append("仅健康检查类探测：确认来源是否为合法监控，误报可忽略。")
    return out


def render(per_ip, total):
    """打印中文报告，返回退出码（有高危告警返回 1）。"""
    alerts = {ip: info for ip, info in per_ip.items() if info["score"] >= 20}
    print("ActuatorWatch 暴露面探测检测报告  |  分析日志: %d 条" % total)
    if not alerts:
        print("未发现可疑的 Actuator 探测。")
        return 0
    print("发现 %d 个可疑 IP:" % len(alerts))
    worst = 0
    for i, (ip, info) in enumerate(sorted(alerts.items(), key=lambda kv: -kv[1]["score"]), 1):
        lv = level(info["score"])
        worst = max(worst, info["score"])
        print("[%d] [%s] %s  风险分: %d  端点: %s"
              % (i, lv, ip, info["score"], ", ".join(sorted(info["endpoints"]))))
        print("    信号: %s" % ", ".join("%s×%d" % (k, v) for k, v in info["signals"].items()))
        for a in advice(info):
            print("    建议: %s" % a)
    return 1 if worst >= 70 else 0


def gen_demo_log():
    """生成混合演示日志：正常流量 + 两类攻击者 + 一个合法监控。"""
    rnd = random.Random(20261026)
    lines = []
    tpl = ('{ip} - - [26/Oct/2026:09:00:{sec:02d} +0800] "{m} {u} HTTP/1.1" {s} {size}')

    def emit(ip, method, url, status, size, sec):
        lines.append(tpl.format(ip=ip, m=method, u=url, s=status, size=size, sec=sec))

    sec = 0
    # 正常用户：首页、API、静态资源
    for _ in range(30):
        sec += 1
        emit("10.0.0.21", "GET", rnd.choice(["/", "/api/orders", "/static/app.js",
                                            "/api/products?page=2"]), 200, rnd.randint(300, 9000), sec % 60)
    # 合法监控：只打 health
    for _ in range(6):
        sec += 1
        emit("10.0.0.5", "GET", "/actuator/health", 200, 120, sec % 60)
    # 攻击者 A：枚举 + 窃取 env/heapdump（200 大响应体）
    attacker_a = "203.0.113.77"
    for url, status, size in [
            ("/actuator/env", 200, 48210), ("/actuator/configprops", 200, 91300),
            ("/actuator/mappings", 200, 22100), ("/actuator/beans", 200, 15800),
            ("/actuator/heapdump", 200, 18340000), ("/actuator/threaddump", 200, 31200),
            ("/actuator/sessions", 401, 0)]:
        sec += 1
        emit(attacker_a, "GET", url, status, size, sec % 60)
    # 攻击者 B：写危险 + SpEL 注入链 + 绕过形态
    attacker_b = "198.51.100.44"
    for method, url, status, size in [
            ("POST", "/actuator/env", 200, 210),
            ("POST", "/actuator/refresh", 200, 180),
            ("POST", "/actuator/gateway/routes", 201, 320),
            ("GET", "/actuator/gateway/routes?spel=${T(java.lang.Runtime)}", 200, 1500),
            ("GET", "//actuator/env", 404, 0),
            ("POST", "/actuator/shutdown", 403, 0)]:
        sec += 1
        emit(attacker_b, method, url, status, size, sec % 60)
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description="ActuatorWatch：Spring Boot Actuator 暴露面探测检测")
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
                     "endpoints": sorted(info["endpoints"]),
                     "advice": advice(info)}
               for ip, info in per_ip.items() if info["score"] >= 20}
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=2)
        print("JSON 告警已写入: %s" % args.json_out)
    return code


if __name__ == "__main__":
    sys.exit(main())
