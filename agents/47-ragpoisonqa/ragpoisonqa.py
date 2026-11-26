#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RAGPoisonQA -- RAG 知识库投毒防御离线问答（rain.op Day 47 · RAG 向）

回答「RAG 知识库怎么防投毒」的问题：知识库投毒的定义、对抗性文档
与检索操纵、指令型投毒与事实篡改、来源可信度分级、入库清洗与人工
审批、引用溯源与多源一致性校验，以及投毒评测集与事件复盘。12 张
知识卡片全部离线，词项检索 + 抽取式回答，每条答案强制带来源编号
与防御自查动作。

与 Day 45 RAGPoisonQA（提示注入攻防）不同：注入问答里知识库投毒
只是间接注入的一种；这里专讲 RAG 投毒全链路 -- 文档怎么被塞进来、
怎么被检索命中、怎么污染答案、每一层怎么防。要了解直接/间接/工具
输出三类注入的通用打法请用 RAGPoisonQA。
与 Day 33 SecureRAGVault（权限过滤问答）不同：这里讲投毒防御 --
内容本身是否可信；权限过滤讲谁能看到哪级文档。要按角色过滤检索
结果请用 SecureRAGVault。
与 Day 39 SkillPoisonQA（技能/工具供应链投毒）不同：这里投毒的
目标是知识库里的文档与答案；技能投毒的目标是 agent 技能与 MCP 工
具描述。要查技能描述劫持与工具投毒请用 SkillPoisonQA。
与 Day 35 AgentEvalBench（安全评测台）不同：这里只覆盖投毒评测集
的设计方法；要自动跑批打分、输出通过率报告请用 AgentEvalBench。

只用 Python 标准库，离线可运行，不调用任何外部 API。

用法：
    python ragpoisonqa.py --demo                    # 内置演示：4 个典型投毒问题
    python ragpoisonqa.py --ask "怎么防知识库投毒？"
    python ragpoisonqa.py --ask "入库前要做什么检查" --category "入库治理"
    python ragpoisonqa.py --list                    # 列出全部知识卡片
    python ragpoisonqa.py --checklist               # 投毒防御自查清单
    python ragpoisonqa.py --checklist --json checklist.json
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
    """中文按单字 + 二元字串切分，英文/数字按词切分；简单但对投毒问答够用。"""
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
    ("知识库投毒是怎么回事？", None),
    ("对抗性文档怎么操纵检索排名？", None),
    ("答案怎么做到引用溯源？", None),
    ("一次投毒事件怎么复盘？", None),
]


def cmd_demo(args):
    docs = load_kb(args.kb)
    print("=" * 64)
    print("RAGPoisonQA 演示：4 个典型的知识库投毒问题")
    print("=" * 64)
    for query, category in DEMO_QUESTIONS:
        print()
        results = search(docs, query, top_k=2, category=category)
        print_answer(query, results, category=category)
    print()
    print("提示：用 --ask 自由提问，用 --checklist 导出投毒防御自查清单。")
    return 0


def cmd_list(args):
    docs = load_kb(args.kb)
    print(f"RAGPoisonQA 知识库：共 {len(docs)} 张卡片")
    print()
    for d in docs:
        print(f"  {d['id']}  【{d['category']}】{d['title']}")
    return 0


def cmd_checklist(args):
    docs = load_kb(args.kb)
    lines = ["RAGPoisonQA 投毒防御自查清单", "=" * 40, ""]
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
    parser = argparse.ArgumentParser(description="RAGPoisonQA -- RAG 知识库投毒防御离线问答")
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
