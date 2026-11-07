#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PromptInjectionWatch —— LLM 应用提示注入检测（离线小工具）

读 LLM 应用的对话 / 调用日志（JSONL，每行一条记录），用规则 + 打分
检出可疑条目并分级（高 / 中 / 低），输出检测报告。

覆盖的检测维度：
  1. 指令覆盖（ignore previous instructions 类）
  2. 角色劫持（冒充 system / developer）
  3. 分隔符伪造（伪造 ```、---、### 等分隔符，伪造 system 消息）
  4. 敏感信息套取（套取系统提示词、密钥、内部指令）
  5. 工具调用劫持（诱导调用 shell、删除文件、外发数据等危险工具）

用法：
    python promptwatch.py --demo                 # 用自带演示日志跑一遍
    python promptwatch.py -i mylog.jsonl         # 检测自己的日志
    python promptwatch.py -i mylog.jsonl -o report.json   # 报告写 JSON

日志格式（JSONL，每行一条）：
    {"id": "001", "ts": "2026-11-05T10:00:00", "role": "user",
     "content": "...", "source": "chat", "tool_calls": []}
    role: user / assistant / tool / system
    source: chat（直接对话）/ doc（文档内容）/ web（网页内容）/
            tool_output（工具返回）—— 间接注入就藏在这些地方
    tool_calls: 本条触发的工具调用，如 [{"name": "shell_exec", "args": {...}}]

退出码：检出高危条目返回 1，否则返回 0（方便接 CI / 定时巡检）。
只用 Python 标准库，离线可跑。
"""

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

# ---------------------------------------------------------------- 规则库
# 每条规则：(规则名, 维度, 权重, 正则列表)
# 命中一条正则即命中该规则一次；同一规则在一行内最多计一次。

RULES = [
    ("instruction-override", "指令覆盖", 30, [
        r"忽略(以上|之前|前面|所有)?(的)?(指令|提示|规则|系统提示)",
        r"ignore (all )?(previous|above|prior) instructions?",
        r"disregard (all )?(previous|above|prior) instructions?",
        r"forget (all )?(previous|above|prior) instructions?",
        r"不要(再)?遵守(以上|之前|前面)?(的)?(指令|规则)",
        r"override (the )?(system|previous) instructions?",
        r"新的指令(是|：|:)",
        r"从现在开始，?(你)?(必须|要)?(执行|遵守|听从)",
    ]),
    ("role-hijack", "角色劫持", 30, [
        r"你现在是(一个)?(新的|另外的)?(AI|助手|系统|管理员|开发者)",
        r"you are now (a )?(different|new)? ?(ai|assistant|system|admin|developer)",
        r"假装你是(system|管理员|开发者|root)",
        r"pretend (you are|to be) (the )?(system|admin|developer|root)",
        r"切换到(开发者|developer|管理员|admin)模式",
        r"developer mode (enabled|on)",
        r"我是(你的)?(开发者|developer|系统管理员|system admin)",
        r"作为(系统|system|开发者|developer)，",
    ]),
    ("delimiter-forgery", "分隔符伪造", 25, [
        r"```\s*(system|SYSTEM|developer|DEVELOPER)",
        r"^---+\s*$",
        r"^###\s*(system|SYSTEM|指令|instruction)",
        r"\[SYSTEM\]|\[INST\]|<<SYS>>|<\|im_start\|>system",
        r"<\|im_start\|>",
        r"\[/?system\]",
        r"---+\s*(system|系统) (提示|指令|消息)",
        r"以下是(系统|system)给你的(新)?(指令|提示)",
    ]),
    ("secret-extraction", "敏感信息套取", 25, [
        r"(告诉|说出|输出|打印|重复|复述|泄露)(我)?(你的)?(系统提示词|system prompt|初始指令|内部指令|隐藏指令)",
        r"repeat (your )?(system prompt|initial instructions?|hidden instructions?)",
        r"(输出|打印|show|print)(你的)?(完整)?(系统提示|system prompt)",
        r"(api[_-]?key|密钥|secret|token|密码|password)(是)?(什么|多少)",
        r"reveal (your )?(api key|secret|password|system prompt)",
        r"把(你的)?(系统提示词|system prompt)(完整)?(发|告诉|输出)",
        r"(内部|internal)(指令|instructions?|文档|documents?)(是)?(什么|内容)",
    ]),
    ("jailbreak-template", "越狱模板", 20, [
        r"DAN\b",
        r"do anything now",
        r"开发者模式|developer mode",
        r"越狱|jailbreak",
        r"无限制模式|无审查|没有(任何)?限制|without (any )?(restrictions?|filters?|censorship)",
        r"hypothetical(ly)?",
        r"假设(你)?没有(任何)?(限制|审查|规则)",
    ]),
    ("tool-call-hijack", "工具调用劫持", 35, [
        r"(调用|执行|运行|call|run|execute)\s*(shell|bash|终端|命令行|cmd|powershell)",
        r"rm\s+-rf|sudo rm|del /[fs]|format [a-z]:",
        r"(删除|删掉|delete|remove).{0,12}(文件|file|目录|数据库|database)",
        r"(发送|外发|上传|泄露|send|upload|exfiltrate).{0,12}(数据|data|文件|file|密钥|secret)",
        r"(curl|wget)\s+https?://",
        r"(调用|call).{0,20}(send_email|http_post|file_write|shell_exec|delete_file)",
        r"把(文件|数据|密钥).{0,12}(发|传|寄)(到|给|往)",
    ]),
    ("indirect-injection", "间接注入（藏在外部内容里）", 20, [
        r"(网页|文档|文件|webpage|document|article)(中|里|内容)(说|写|要求|指示|命令)",
        r"(根据|按照)(上面|以下|这篇|该)(文档|网页|内容|文章)(的)?(指令|要求|说明)",
        r"the (webpage|document|article) (says|instructs|asks|tells)",
        r"忽略(用户|user)(的)?(问题|请求|指令)",
    ]),
]

# 危险工具调用：工具名本身就高危（即使文本没写明）
DANGEROUS_TOOLS = {
    "shell_exec": 30, "bash": 30, "run_command": 30, "exec": 30,
    "delete_file": 30, "file_write": 20, "http_post": 20,
    "send_email": 20, "upload_file": 20, "read_env": 15,
}

# 严重度阈值（总分）
HIGH_THRESHOLD = 50
MEDIUM_THRESHOLD = 25

SEVERITY_CN = {"high": "高危", "medium": "中危", "low": "低危"}


def load_log(path):
    """读 JSONL 日志；容忍空行与坏行，坏行记一条解析错误。"""
    entries, errors = [], []
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                errors.append({"line": lineno, "error": str(exc), "raw": line[:120]})
                continue
            if not isinstance(obj, dict) or "content" not in obj:
                errors.append({"line": lineno, "error": "缺少 content 字段",
                               "raw": line[:120]})
                continue
            obj.setdefault("id", str(lineno))
            obj.setdefault("role", "user")
            obj.setdefault("source", "chat")
            obj.setdefault("tool_calls", [])
            entries.append(obj)
    return entries, errors


def detect(entry):
    """对一条日志打分，返回 (总分, 命中的规则列表, 严重度)。"""
    text = entry.get("content", "") or ""
    hits = []
    score = 0
    for name, dimension, weight, patterns in RULES:
        for pat in patterns:
            if re.search(pat, text, re.IGNORECASE | re.MULTILINE):
                hits.append({"rule": name, "dimension": dimension,
                             "weight": weight, "pattern": pat})
                score += weight
                break  # 同一规则每条只计一次

    # 工具调用本身的审计：危险工具名直接加分
    for call in entry.get("tool_calls") or []:
        tool = str(call.get("name", "")).lower()
        if tool in DANGEROUS_TOOLS:
            w = DANGEROUS_TOOLS[tool]
            hits.append({"rule": "dangerous-tool-call", "dimension": "工具调用劫持",
                         "weight": w, "pattern": f"tool:{tool}"})
            score += w

    # 间接注入加权：可疑内容来自外部来源（文档/网页/工具输出）时更值得警惕
    if entry.get("source") in ("doc", "web", "tool_output") and hits:
        score += 10
        hits.append({"rule": "untrusted-source", "dimension": "间接注入（藏在外部内容里）",
                     "weight": 10, "pattern": f"source:{entry['source']}"})

    if score >= HIGH_THRESHOLD:
        severity = "high"
    elif score >= MEDIUM_THRESHOLD:
        severity = "medium"
    else:
        severity = "low"
    return score, hits, severity


def analyze(entries):
    """逐条检测，返回 (告警列表, 汇总统计)。"""
    alerts = []
    for entry in entries:
        score, hits, severity = detect(entry)
        if hits:
            alerts.append({
                "id": entry["id"],
                "ts": entry.get("ts", ""),
                "role": entry.get("role", ""),
                "source": entry.get("source", ""),
                "score": score,
                "severity": severity,
                "rules": [h["rule"] for h in hits],
                "dimensions": sorted({h["dimension"] for h in hits}),
                "hit_details": hits,
                "snippet": (entry.get("content", "") or "")[:160].replace("\n", " "),
            })
    stats = {
        "total": len(entries),
        "flagged": len(alerts),
        "by_severity": dict(Counter(a["severity"] for a in alerts)),
        "by_dimension": dict(Counter(d for a in alerts for d in a["dimensions"])),
        "by_rule": dict(Counter(r for a in alerts for r in a["rules"])),
        "top_score": max((a["score"] for a in alerts), default=0),
    }
    return alerts, stats


def print_report(alerts, stats, parse_errors):
    print("PromptInjectionWatch 提示注入检测报告")
    print("=" * 56)
    print(f"分析日志: {stats['total']} 条 | 命中: {stats['flagged']} 条 | "
          f"最高分: {stats['top_score']}")
    sev = stats["by_severity"]
    print(f"分级: 高危 {sev.get('high', 0)} 条 | "
          f"中危 {sev.get('medium', 0)} 条 | 低危 {sev.get('low', 0)} 条")
    if parse_errors:
        print(f"解析失败: {len(parse_errors)} 行（已跳过）")
    print()
    for i, a in enumerate(sorted(alerts, key=lambda x: -x["score"]), 1):
        print(f"[{i}] [{SEVERITY_CN[a['severity']]}] 分数 {a['score']}  "
              f"id={a['id']} role={a['role']} source={a['source']}")
        print(f"    维度: {'、'.join(a['dimensions'])}")
        print(f"    规则: {', '.join(a['rules'])}")
        print(f"    内容: {a['snippet']}")
    print()
    print("汇总（按维度）:")
    for dim, n in sorted(stats["by_dimension"].items(), key=lambda kv: -kv[1]):
        print(f"  {dim}: {n} 条")
    print("汇总（按规则）:")
    for rule, n in sorted(stats["by_rule"].items(), key=lambda kv: -kv[1]):
        print(f"  {rule}: {n} 条")
    if stats["by_severity"].get("high", 0):
        print("\n建议：先处理高危条目——检查对应会话是否已执行危险工具调用，"
              "并把命中的文本加入拦截规则 / 人工审批点。")


def main(argv=None):
    ap = argparse.ArgumentParser(description="PromptInjectionWatch：提示注入检测")
    ap.add_argument("-i", "--input", help="输入 JSONL 日志文件")
    ap.add_argument("--demo", action="store_true", help="用自带演示日志跑一遍")
    ap.add_argument("-o", "--output", help="把报告写成 JSON 文件")
    args = ap.parse_args(argv)

    if args.demo:
        path = Path(__file__).resolve().parent / "sample_log.jsonl"
    elif args.input:
        path = Path(args.input)
    else:
        ap.error("请指定 --demo 或 -i <日志文件>")
    if not path.exists():
        print(f"找不到日志文件: {path}", file=sys.stderr)
        return 2

    entries, parse_errors = load_log(path)
    alerts, stats = analyze(entries)
    print_report(alerts, stats, parse_errors)

    if args.output:
        report = {"stats": stats, "alerts": alerts, "parse_errors": parse_errors}
        Path(args.output).write_text(
            json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\nJSON 报告已写入: {args.output}")

    return 1 if stats["by_severity"].get("high", 0) else 0


if __name__ == "__main__":
    sys.exit(main())
