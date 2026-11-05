#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CloudSecQA - 云安全配置离线问答。

纯标准库，离线可运行，不联网、不调用外部 API：

  --ask <问题>   在本地知识库（kb.json）中检索云安全知识卡片
  --list         列出知识库全部卡片标题
  --demo         跑一遍演示：3 个典型问答

检索方式是词项重叠打分（标题命中权重更高），回答为抽取式：
输出最相关卡片的原文段落并标注卡片编号，便于核对来源。
它讲的是通用云配置防御思路，不针对某个云厂商或账号做审计结论；
落地到自家云账号时，请结合实际的 IAM、存储桶策略与审计日志复核。
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
    cards = data["cards"]
    if not isinstance(cards, list) or not cards:
        raise ValueError("知识库为空或格式不对")
    return cards


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
        print("知识库中没有匹配条目。换个关键词试试，例如：存储桶、密钥泄露、IAM。")
        return 0
    print("问题：%s\n" % question)
    for rank, (s, card) in enumerate(results, 1):
        print_card(card, rank=rank, score_value=s)
    return 0


def cmd_list(cards):
    for card in cards:
        print("【%s】%s" % (card["id"], card["title"]))
    return 0


def cmd_demo(cards):
    for question in [
        "存储桶公开了怎么处理？",
        "云上密钥 AK 泄露了怎么办？",
        "云账号权限给太大了怎么收紧？",
    ]:
        cmd_ask(question, cards)
        print("-" * 40)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="CloudSecQA - 云安全配置离线问答")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--ask", metavar="问题", help="提问，检索知识库卡片")
    group.add_argument("--list", action="store_true", help="列出全部卡片标题")
    group.add_argument("--demo", action="store_true", help="跑一遍演示")
    parser.add_argument("--kb", default=KB_PATH, help="知识库 JSON 路径（默认 kb.json）")
    args = parser.parse_args(argv)

    try:
        cards = load_kb(args.kb)
    except (OSError, ValueError) as exc:
        print("读取知识库失败：%s" % exc, file=sys.stderr)
        return 2

    if args.ask:
        return cmd_ask(args.ask, cards)
    if args.list:
        return cmd_list(cards)
    return cmd_demo(cards)


if __name__ == "__main__":
    sys.exit(main())
