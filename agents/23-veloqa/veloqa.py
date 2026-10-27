#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""VeloQA — Arista VeloCloud Orchestrator（VCO）问答与版本研判。

围绕 CVE-2026-114625（VCO SQL 注入，CWE-89）的离线小工具，纯标准库：
  --check <版本>   判某 on-prem VCO 版本是否仍受本漏洞影响
  --ask <问题>     在本地知识库（kb.json）中检索相关情报卡片
  --demo           跑一遍演示：版本研判 + 典型问答

知识来源：Arista 安全公告 0199（经多家转述）、CISA KEV 收录信息、
The Hacker News 相关报道。情报时效以知识库为准，处置前请以厂商
公告与 CISA KEV 复核；不要把本工具的研判当作厂商官方结论。
"""

import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
KB_PATH = os.path.join(HERE, "kb.json")

# 分支 -> 修复版本（必须按分支一一对应，见知识卡 velo-04）
FIXED = {
    (5, 2): (5, 2, 3, 18),
    (6, 1): (6, 1, 3, 10),
    (6, 4): (6, 4, 2, 12),
}

# 只修了上一个漏洞 CVE-2026-93952、不能修本漏洞的版本（见知识卡 velo-05）
ONLY_93952 = {(5, 2, 3, 16), (6, 4, 2, 8)}


def parse_version(text):
    """解析 '5.2.3.18' 式版本号，失败返回 None。"""
    text = (text or "").strip().lstrip("vV")
    parts = text.split(".")
    if not (3 <= len(parts) <= 4) or not all(p.isdigit() for p in parts):
        return None
    nums = tuple(int(p) for p in parts)
    while len(nums) < 4:
        nums = nums + (0,)
    return nums


def fmt_version(nums):
    return ".".join(str(n) for n in nums)


def check_version(text):
    """研判版本，返回 (结论, 说明)。结论：受影响 / 已修复 / 未确认 / 格式错误。"""
    ver = parse_version(text)
    if ver is None:
        return ("格式错误", "版本号格式无法解析，请输入形如 5.2.3.18 的版本号。")
    fixed = FIXED.get(ver[:2])
    if fixed is None:
        return ("未确认",
                "Arista 未将该分支列为受影响/修复版本（例如 VCO 7.0 未列出），"
                "不要直接判定为安全，需向 Arista TAC 确认。")
    if ver >= fixed:
        return ("已修复",
                "该版本已达到本分支修复版本 %s，不受 CVE-2026-114625 影响。"
                % fmt_version(fixed))
    note = ""
    if ver in ONLY_93952:
        note = "注意：该版本只修复了 9 月的 CVE-2026-93952，不能修复本漏洞！"
    return ("仍受影响",
            "该版本低于本分支修复版本 %s，仍受 CVE-2026-114625 影响，"
            "请升级到 %s 或更高。%s" % (fmt_version(fixed), fmt_version(fixed), note))


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


def ask(question, cards, topn=3):
    """简单词项重叠检索：命中词越多、整句命中越多，得分越高。"""
    qtokens = tokenize(question)
    qset = set(qtokens)
    scored = []
    for card in cards:
        hay = card["title"] + " " + card["text"] + " " + " ".join(card.get("tags", []))
        ctokens = set(tokenize(hay))
        overlap = len(qset & ctokens)
        if overlap == 0:
            continue
        score = overlap
        # 整句/关键词原样出现在卡片里，加分
        q = question.strip().lower()
        if q and q in hay.lower():
            score += 5
        scored.append((score, card))
    scored.sort(key=lambda x: -x[0])
    return scored[:topn]


def cmd_check(args):
    verdict, detail = check_version(args.check)
    print("版本研判：%s" % args.check)
    print("结论：%s" % verdict)
    print("说明：%s" % detail)
    if verdict == "仍受影响":
        return 1
    return 0


def cmd_ask(args):
    cards = load_kb(args.kb)
    results = ask(args.ask, cards)
    if not results:
        print("没有找到相关情报卡片。换个说法试试，例如：只读账号能不能打？")
        return 1
    print("问题：%s" % args.ask)
    for i, (score, card) in enumerate(results, 1):
        print("\n[%d] %s（匹配分 %d，卡片 %s）" % (i, card["title"], score, card["id"]))
        print("    %s" % card["text"])
    return 0


def cmd_demo(args):
    cards = load_kb(args.kb)
    print("=== VeloQA 演示：CVE-2026-114625 版本研判 ===")
    for ver in ["5.2.3.16", "6.4.2.12", "6.1.3.10", "5.2.3.18", "6.1.3.9", "7.0.0.0"]:
        verdict, detail = check_version(ver)
        print("\n--check %s -> %s" % (ver, verdict))
        print("   %s" % detail)
    print("\n=== VeloQA 演示：典型问答 ===")
    for q in ["只读账号能不能打？", "托管版还要不要管？",
              "Edge 要不要升级？", "VCO 7.0 安全吗？"]:
        results = ask(q, cards, topn=1)
        print("\n问：%s" % q)
        if results:
            print("答：%s" % results[0][1]["text"])
        else:
            print("答：（无匹配卡片）")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="VeloQA：VCO 问答与版本研判")
    parser.add_argument("--kb", default=KB_PATH, help="知识库 JSON 路径")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", metavar="版本", help="研判某版本是否受影响")
    group.add_argument("--ask", metavar="问题", help="向知识库提问")
    group.add_argument("--demo", action="store_true", help="运行演示")
    args = parser.parse_args(argv)
    if args.demo:
        return cmd_demo(args)
    if args.check is not None:
        return cmd_check(args)
    return cmd_ask(args)


if __name__ == "__main__":
    sys.exit(main())
