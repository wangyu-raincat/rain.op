#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AgentSecQA - AI 智能体安全离线问答。

纯标准库，离线可运行，不联网、不调用外部 API：

  --ask <问题>   在本地知识库（kb.json）中检索智能体安全知识卡片
  --list         列出知识库全部卡片标题
  --demo         跑一遍演示：3 个典型问答

检索方式是词项重叠打分（标题命中权重更高），回答为抽取式：
输出最相关卡片的原文段落并标注卡片编号，便于核对来源。
它讲的是通用防御思路，不是针对某个具体产品或版本的审计结论；
落地到自家智能体时，请结合实际的工具清单、权限配置与日志复核。
"""

import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
KB_PATH = os.path.join(HERE, "kb.json")


def tokenize(text):
    """分词：英文/数字词 + 每个中文字符，便于中文问答匹配。"""
    text = (text or "").lower()
    tokens = re.findall(r"[a-z0-9]+", text)
    tokens += [ch for ch in text if "\u4e00" <= ch <= "\u9fff"]
    return tokens


def load_kb(kb_path):
    with open(kb_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data["cards"]


def score(question_tokens, card):
    """标题命中权重 3，标签命中权重 2，正文命中权重 1。"""
    qset = set(question_tokens)
    title_tokens = set(tokenize(card["title"]))
    tag_tokens = set()
    for tag in card.get("tags", []):
        tag_tokens |= set(tokenize(tag))
    text_tokens = set(tokenize(card["text"]))
    return (
        3 * len(qset & title_tokens)
        + 2 * len(qset & tag_tokens)
        + 1 * len(qset & text_tokens)
    )


def ask(question, cards, topn=3):
    qtokens = tokenize(question)
    scored = [(score(qtokens, card), card) for card in cards]
    scored.sort(key=lambda item: item[0], reverse=True)
    return [(s, c) for s, c in scored if s > 0][:topn]


def print_card(card, rank=None, score_value=None):
    head = "【%s】%s" % (card["id"], card["title"])
    if rank is not None:
        head = "[%d] %s" % (rank, head)
    if score_value is not None:
        head += "（匹配分 %d）" % score_value
    print(head)
    print(card["text"])
    if card.get("tags"):
        print("标签：" + "、".join(card["tags"]))
    print()


def cmd_ask(question, cards):
    results = ask(question, cards)
    if not results:
        print("知识库中没有匹配条目。换个关键词试试，例如：提示注入、工具权限、MCP。")
        return 0
    print("问题：%s\n" % question)
    for i, (s, card) in enumerate(results, 1):
        print_card(card, rank=i, score_value=s)
    return 0


def cmd_list(cards):
    print("知识库共 %d 张卡片：\n" % len(cards))
    for card in cards:
        print("  %s  %s" % (card["id"], card["title"]))
    return 0


def cmd_demo(cards):
    demos = [
        "什么是间接提示注入？怎么防？",
        "智能体调用工具时应该怎么控制权限？",
        "MCP 工具投毒是什么？接入第三方工具前要查什么？",
    ]
    for question in demos:
        print("=" * 60)
        cmd_ask(question, cards)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="AgentSecQA — AI 智能体安全离线问答")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--ask", metavar="问题", help="提问，检索本地知识库")
    group.add_argument("--list", action="store_true", help="列出全部知识卡片")
    group.add_argument("--demo", action="store_true", help="跑演示问答")
    parser.add_argument("--kb", default=KB_PATH, help="知识库 JSON 路径（默认 kb.json）")
    args = parser.parse_args(argv)

    try:
        cards = load_kb(args.kb)
    except (OSError, ValueError) as exc:
        print("知识库加载失败：%s" % exc, file=sys.stderr)
        return 2

    if args.ask:
        return cmd_ask(args.ask, cards)
    if args.list:
        return cmd_list(cards)
    return cmd_demo(cards)


if __name__ == "__main__":
    sys.exit(main())
