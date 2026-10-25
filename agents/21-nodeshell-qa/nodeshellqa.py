#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NodeShell-QA: Node2Shell (CVE-2026-111497) offline QA + version check.
Pure stdlib, offline. KB lives in kb.json next to this file.
  --ask "question"  natural-language / CVE-ID question, BM25 retrieval
  --check <ver>     judge a Node.js version: fixed / vulnerable / EOL
  --demo            demo mode
  --kb <path>       KB path (default kb.json beside this script)
"""

import argparse
import json
import math
import os
import re
import sys

KB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "kb.json")

# (branch -> fixed release): below fixed = vulnerable; other branches = EOL, no fix.
FIXED = {
    26: (26, 12, 1),
    24: (24, 22, 1),
    22: (22, 23, 4),
}
CVE_ID = "CVE-2026-111497"


def load_kb(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def tokenize(text):
    """Chinese: per-character; English/digits: per-word. Good enough for BM25."""
    text = text.lower()
    tokens = []
    for part in re.findall(r"[a-z0-9.]+|[\u4e00-\u9fff]+", text):
        if part[0].isascii():
            tokens.append(part)
        else:
            tokens.extend(list(part))
    return tokens


def bm25_scores(query_tokens, docs):
    n = len(docs)
    if n == 0:
        return []
    avg_len = sum(len(d) for d in docs) / n
    df = {}
    for d in docs:
        for t in set(d):
            df[t] = df.get(t, 0) + 1
    k1, b = 1.5, 0.75
    scores = []
    for d in docs:
        tf = {}
        for t in d:
            tf[t] = tf.get(t, 0) + 1
        s = 0.0
        for t in query_tokens:
            if t not in tf:
                continue
            idf = math.log((n - df.get(t, 0) + 0.5) / (df.get(t, 0) + 0.5) + 1)
            s += idf * tf[t] * (k1 + 1) / (tf[t] + k1 * (1 - b + b * len(d) / avg_len))
        scores.append(s)
    return scores


def ask(kb, question):
    """Return (best card, score). Intent routing first, then CVE shortcut, then BM25."""
    norm = question.lower().replace(" ", "")
    # 意图路由：问法明确时直接命中对应卡片，避免 BM25 被高频词带偏。
    intent = [
        (("缓解", "暂时", "升不了", "不能升级", "权宜"), "NS-06"),
        (("bun", "python", "envoy", "istio", "波及"), "NS-08"),
        (("暴露", "路径", "express", "fetch", "body-parser"), "NS-05"),
        (("中招", "受影响", "判断"), "NS-02"),
        (("查版本", "怎么查"), "NS-03"),
        (("排查", "被利用", "日志", "入侵"), "NS-07"),
        (("误区", "误解"), "NS-09"),
        (("修复", "升级", "升到"), "NS-04"),
    ]
    for words, cid in intent:
        if any(w in norm for w in words):
            card = next((c for c in kb if c["id"] == cid), None)
            if card:
                return card, 0.0
    stripped = norm.replace(CVE_ID.lower(), "").replace("node2shell", "")
    if len(stripped) <= 3:
        card = next((c for c in kb if c["id"] == "NS-01"), kb[0])
        return card, 0.0
    docs = [tokenize(c["title"] + " " + c["keywords"] + " " + c["text"]) for c in kb]
    scores = bm25_scores(tokenize(question), docs)
    best = max(range(len(kb)), key=lambda i: scores[i])
    return kb[best], scores[best]


def parse_version(raw):
    """Parse v24.22.0 / 24.22.0 / 'node v24.22.0' -> (major, minor, patch) or None."""
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", raw or "")
    if not m:
        return None
    return tuple(int(x) for x in m.groups())


def check_version(raw):
    """Return (verdict, advice). Verdicts: fixed / vulnerable / EOL no fix / unparsable."""
    v = parse_version(raw)
    if v is None:
        return "无法解析", "请传入形如 24.22.0 或 v24.22.0 的版本号（以 node -v 的输出为准）。"
    major = v[0]
    if major in FIXED:
        fixed = FIXED[major]
        if v >= fixed:
            return "已修复", "该版本已包含 CVE-2026-111497 的修复；确认进程已重启并重新跑 node -v 核对。"
        return "受影响", "请升级到 %s 并重启 Node.js 进程；只升级应用依赖修不掉这个漏洞。" % ".".join(map(str, fixed))
    return "EOL 无修复", "该分支已停止维护，不会得到修复；请先迁移到受支持的分支（22.x / 24.x / 26.x），再升到对应修复版本。"


def print_answer(card, score):
    print("【%s】%s" % (card["id"], card["title"]))
    print(card["text"])
    if score:
        print("(BM25 得分 %.2f；知识库来源：%s)" % (score, card["id"]))
    print("来源复核：Node.js 官方十月安全公告与 Contrast 分析（见 README）。")


def cmd_demo(kb):
    print("=== NodeShell-QA 演示：版本研判 ===")
    for v in ["26.12.1", "24.22.0", "22.23.4", "20.19.5", "25.1.0", "v24.22.1"]:
        verdict, advice = check_version(v)
        print("  %-10s -> %s" % (v, verdict))
        print("     %s" % advice)
    print()
    print("=== NodeShell-QA 演示：典型问题 ===")
    for q in ["我中招了吗", "怎么修复 Node2Shell", "暂时不能升级怎么办", "Express 应用会不会中招"]:
        card, score = ask(kb, q)
        print("问：%s" % q)
        print_answer(card, score)
        print()


def main(argv=None):
    ap = argparse.ArgumentParser(description="Node2Shell（CVE-2026-111497）离线问答")
    ap.add_argument("--ask", metavar="问题", help="自然语言提问，或直接问 CVE-2026-111497")
    ap.add_argument("--check", metavar="版本", help="研判 Node.js 版本，如 24.22.0")
    ap.add_argument("--demo", action="store_true", help="演示模式")
    ap.add_argument("--kb", default=KB_PATH, help="知识库 JSON 路径")
    args = ap.parse_args(argv)

    try:
        kb = load_kb(args.kb)
    except (OSError, ValueError) as e:
        print("知识库加载失败：%s" % e, file=sys.stderr)
        return 2

    if args.demo:
        cmd_demo(kb)
        return 0
    if args.check is not None:
        verdict, advice = check_version(args.check)
        print("版本 %s：%s" % (args.check, verdict))
        print(advice)
        return 0
    if args.ask:
        card, score = ask(kb, args.ask)
        print_answer(card, score)
        return 0
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
