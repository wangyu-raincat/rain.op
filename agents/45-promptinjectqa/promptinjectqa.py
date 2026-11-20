#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PromptInjectQA -- 提示注入攻防离线问答（rain.op Day 45 · RAG 向）

回答「agent 怎么防提示注入」的问题：直接注入与越狱的区别、间接注入、
RAG 知识库投毒、工具输出注入、多步调用链放大，以及输入净化、注入检测、
最小权限、沙箱隔离、评测集与事件复盘。12 张知识卡片全部离线，词项检索
+ 抽取式回答，每条答案强制带来源编号与防御自查动作。

与 Day 41 AgentJailbreakQA（越狱问答）不同：这里讲控制权争夺 --
攻击者怎么夺走 agent 的指令权、怎么沿调用链放大；越狱只讲模型
安全边界怎么被绕过。要了解越狱话术与对齐绕过请用 JailbreakQA。
与 Day 33 SecureRAGVault（权限过滤问答）不同：这里讲注入攻防 --
知识库投毒只是间接注入的一种；要按角色过滤检索结果请用
SecureRAGVault。
与 Day 34 MCPGuard（调用时拦截）不同：这里是问答手册 -- 讲注入
从哪来、怎么防、怎么评测；要实时拦截危险工具调用请用 MCPGuard。
与 Day 35 AgentEvalBench（安全评测台）不同：这里只覆盖注入评测集
的设计方法；要自动跑批打分、输出通过率报告请用 AgentEvalBench。

只用 Python 标准库，离线可运行，不调用任何外部 API。

用法：
    python promptinjectqa.py --demo                    # 内置演示：4 个典型注入问题
    python promptinjectqa.py --ask "怎么防间接注入？"
    python promptinjectqa.py --ask "工具返回里有注入怎么办" --category "工具输出注入"
    python promptinjectqa.py --list                    # 列出全部知识卡片
    python promptinjectqa.py --checklist               # 注入防御自查清单
    python promptinjectqa.py --checklist --json checklist.json
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
    """中文按单字 + 二元字串切分，英文/数字按词切分；简单但对注入问答够用。"""
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
        print(f"    防御动作：{d['checklist']}")


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
    ("怎么防间接注入？", None),
    ("工具返回结果里夹带指令怎么办？", None),
    ("注入评测集应该怎么设计？", None),
    ("一次注入事件怎么复盘？", None),
]


def cmd_demo(args):
    docs = load_kb(args.kb)
    print("=" * 64)
    print("PromptInjectQA 演示：4 个典型的提示注入问题")
    print("=" * 64)
    for query, category in DEMO_QUESTIONS:
        print()
        results = search(docs, query, top_k=2, category=category)
        print_answer(query, results, category=category)
    print()
    print("提示：用 --ask 自由提问，用 --checklist 导出注入防御自查清单。")
    return 0


def cmd_list(args):
    docs = load_kb(args.kb)
    print(f"PromptInjectQA 知识库：共 {len(docs)} 张卡片")
    print()
    for d in docs:
        print(f"  {d['id']}  【{d['category']}】{d['title']}")
    return 0


def cmd_checklist(args):
    docs = load_kb(args.kb)
    lines = ["PromptInjectQA 注入防御自查清单", "=" * 40, ""]
    for d in docs:
        lines.append(f"[{d['id']}] {d['title']}（{d['category']}）")
        lines.append(f"    {d['checklist']}")
    text = "\n".join(lines)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(
                [{"id": d["id"], "category": d["category"], "title": d["title"],
                  "action": d["checklist"]} for d in docs],
                f, ensure_ascii=False, indent=2,
            )
        print(f"自查清单已写入：{args.json}")
    print(text)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="PromptInjectQA -- 提示注入攻防离线问答")
    parser.add_argument("--kb", default=DEFAULT_KB, help="知识库 JSON 路径（默认 kb.json）")
    parser.add_argument("--ask", metavar="问题", help="直接提问")
    parser.add_argument("--category", metavar="类别", help="只在指定类别里检索")
    parser.add_argument("--top", type=int, default=3, help="返回的卡片数量（默认 3）")
    parser.add_argument("--demo", action="store_true", help="内置演示：4 个典型注入问题")
    parser.add_argument("--list", action="store_true", help="列出全部知识卡片")
    parser.add_argument("--checklist", action="store_true", help="注入防御自查清单")
    parser.add_argument("--json", metavar="路径", help="与 --checklist 联用，把清单写成 JSON")
    args = parser.parse_args(argv)

    if not os.path.exists(args.kb):
        print(f"知识库不存在：{args.kb}")
        return 2
    if args.demo:
        return cmd_demo(args)
    if args.list:
        return cmd_list(args)
    if args.checklist:
        return cmd_checklist(args)
    if args.ask:
        return cmd_ask(args)
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
