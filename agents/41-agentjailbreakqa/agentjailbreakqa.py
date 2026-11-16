#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AgentJailbreakQA —— 智能体越狱与提示注入防御离线问答（rain.op Day 41 · RAG 向）

回答「agent 怎么被越狱、怎么防住」的问题：角色扮演越狱、编码与混淆
绕过、多轮渐进诱导、间接提示注入、工具调用劫持、越狱后数据外泄，
以及系统提示加固、输入检测、工具调用权限过滤、输出审查、人工审批
与熔断、越狱评测。12 张知识卡片全部离线，词项检索 + 抽取式回答，
每句答案强制带来源编号与防御自查动作。

与 Day 32 PromptInjectionWatch（注入检测）不同：这里讲越狱全貌 ——
手法怎么来、防御怎么配、治理怎么落地，是一份问答手册而不是检测器。
与 Day 35 AgentEvalBench（评测台）不同：这里的评测是一张卡片，
讲评测集怎么做、基线怎么定；要跑批打分请用评测台。
与 Day 37 AgentGovQA（治理怎么做）不同：这里只盯越狱这一条攻击线。

只用 Python 标准库，离线可运行，不调用任何外部 API。

用法：
    python agentjailbreakqa.py --demo                     # 内置演示：4 个典型越狱问题
    python agentjailbreakqa.py --ask "DAN 越狱怎么防？"
    python agentjailbreakqa.py --ask "网页里藏指令怎么办" --category "间接注入"
    python agentjailbreakqa.py --list                     # 列出全部知识卡片
    python agentjailbreakqa.py --checklist                # 越狱防御自查清单
    python agentjailbreakqa.py --checklist --json checklist.json
"""
import argparse
import json
import os
import re
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_KB = os.path.join(HERE, "kb.json")


def tokenize(text):
    """中文按单字 + 二元字串切分，英文/数字按词切分；简单但对越狱问答够用。"""
    text = text.lower()
    tokens = re.findall(r"[a-z0-9_]+", text)
    chars = re.findall(r"[\u4e00-\u9fff]", text)
    tokens.extend(chars)
    tokens.extend("".join(pair) for pair in zip(chars, chars[1:]))
    return tokens


def load_kb(path):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    docs = data["docs"]
    for d in docs:
        d["_tokens"] = Counter(tokenize(d["title"] + " " + d["text"]))
        d["_title_tokens"] = Counter(tokenize(d["title"]))
    return docs


def search(docs, query, top_k=3, category=None):
    """词项重叠打分：标题命中权重 x3；可按类别过滤。"""
    pool = [d for d in docs if category is None or d["category"] == category]
    qtokens = Counter(tokenize(query))
    scored = []
    for d in pool:
        score = 0
        for tok, n in qtokens.items():
            score += min(n, d["_tokens"].get(tok, 0)) * (3 if tok in d["_title_tokens"] else 1)
        if score > 0:
            scored.append((score, d))
    scored.sort(key=lambda x: (-x[0], x[1]["id"]))
    return scored[:top_k]


def best_sentence(doc, query):
    """取文档中最相关的一句：与查询词项重叠最多的句子。"""
    sentences = [s.strip() for s in re.split(r"[。；\n]", doc["text"]) if s.strip()]
    qset = set(tokenize(query))
    return max(sentences, key=lambda s: len(set(tokenize(s)) & qset), default="")


def print_answer(query, results, category=None):
    print(f"问题：{query}" + (f"（类别：{category}）" if category else ""))
    if not results:
        print("未找到相关内容。请换个关键词，或用 --list 看看 12 张知识卡片的主题。")
        return
    print()
    for i, (score, d) in enumerate(results, 1):
        print(f"[{i}] 【{d['id']} · {d['category']}】{d['title']}（匹配分 {score}）")
        print(f"    {best_sentence(d, query)}")
        print(f"    来源：{d['id']}《{d['title']}》· 类别 {d['category']}")
        print(f"    自查动作：{d['checklist']}")


def cmd_ask(args):
    docs = load_kb(args.kb)
    if args.category and args.category not in {d["category"] for d in docs}:
        print(f"未知的类别：{args.category}")
        print("可用类别：" + "、".join(sorted({d["category"] for d in docs})))
        return 2
    results = search(docs, args.ask, top_k=args.top, category=args.category)
    print_answer(args.ask, results, category=args.category)
    return 0


DEMO_QUESTIONS = [
    ("DAN 越狱怎么防？", None),
    ("网页里藏了隐藏指令怎么办？", None),
    ("agent 被越狱后把密码发出去了怎么拦？", None),
    ("怎么证明我的 agent 防越狱是有效的？", None),
]


def cmd_demo(args):
    docs = load_kb(args.kb)
    print("=" * 64)
    print("AgentJailbreakQA 演示：4 个典型的 agent 越狱问题")
    print("=" * 64)
    for query, category in DEMO_QUESTIONS:
        print()
        print_answer(query, search(docs, query, top_k=2, category=category))
    print()
    print("=" * 64)
    print(f"知识库共 {len(docs)} 张卡片，覆盖 "
          f"{len({d['category'] for d in docs})} 种类别；"
          "每条答案都带来源编号与自查动作。")
    print("跑 --checklist 可打印越狱防御自查清单。")
    return 0


def cmd_list(args):
    docs = load_kb(args.kb)
    print(f"AgentJailbreakQA 知识库：{len(docs)} 张卡片")
    by_cat = {}
    for d in docs:
        by_cat.setdefault(d["category"], []).append(d)
    for cat in sorted(by_cat):
        print(f"\n【{cat}】")
        for d in by_cat[cat]:
            print(f"  {d['id']} · {d['title']}")
    return 0


def cmd_checklist(args):
    docs = load_kb(args.kb)
    items = [{"id": d["id"], "category": d["category"], "title": d["title"],
              "item": d["checklist"], "done": False} for d in docs]
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"total": len(items), "done": 0, "items": items},
                      f, ensure_ascii=False, indent=2)
        print(f"检查清单已写入 {args.json}（{len(items)} 项，初始全部待办）")
    print("AgentJailbreakQA 越狱防御自查清单")
    print(f"共 {len(items)} 项 · 覆盖 {len({d['category'] for d in docs})} 种类别")
    print("用法：逐项确认后在 JSON 里把 done 改为 true；全部 done 方可上线。")
    print()
    for i, d in enumerate(items, 1):
        print(f"[ ] {i:>2}. [{d['category']}] {d['item']}")
    print()
    print("提示：这份清单是自查工具，不是安全背书；具体安全要求"
          "以组织内部规定为准。")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description="AgentJailbreakQA：越狱与提示注入防御离线问答")
    p.add_argument("--kb", default=DEFAULT_KB, help="知识库 JSON 路径（默认 kb.json）")
    p.add_argument("--ask", help="提问")
    p.add_argument("--top", type=int, default=3, help="返回卡片数（默认 3）")
    p.add_argument("--category", help="只在指定类别内检索，如 “间接注入”")
    p.add_argument("--demo", action="store_true", help="演示：4 个典型越狱问题")
    p.add_argument("--list", action="store_true", help="列出全部知识卡片")
    p.add_argument("--checklist", action="store_true", help="打印越狱防御自查清单")
    p.add_argument("--json", help="配合 --checklist：把清单写成 JSON 文件")
    args = p.parse_args(argv)
    if args.demo:
        return cmd_demo(args)
    if args.list:
        return cmd_list(args)
    if args.checklist:
        return cmd_checklist(args)
    if args.ask:
        return cmd_ask(args)
    p.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
