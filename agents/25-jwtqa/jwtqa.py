#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""JwtQA — JWT 安全离线问答与令牌自查。

纯标准库，离线可运行，不校验签名、不联网、不调用外部 API：

  --ask <问题>      在本地知识库（kb.json）中检索 JWT 安全知识卡片
  --inspect <令牌>  只解析 JWT 的 header / payload 结构，指出常见风险点
  --demo            跑一遍演示：3 个示例令牌自查 + 3 个典型问答

--inspect 的定位是“结构自查”，不是安全审计：它看不到服务端的密钥
与校验逻辑，所以只能指出令牌本身可疑的地方（例如 alg=none、kid 带
路径穿越字符、缺少 exp、payload 里放敏感字段），不能判定一次请求
是否真的能绕过校验。结论请结合服务端实现复核。
"""

import argparse
import base64
import binascii
import json
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
KB_PATH = os.path.join(HERE, "kb.json")

SENSITIVE_CLAIMS = {
    "password", "passwd", "pwd", "secret", "ssn", "id_card",
    "bank_card", "credit_card", "private_key", "api_key", "token",
}

# 风险分：分项累加，上限 100；等级按分数划分
FINDINGS = []


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
    """词项重叠检索：命中词越多、整句命中越多，得分越高。"""
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
        q = question.strip().lower()
        if q and q in hay.lower():
            score += 5
        scored.append((score, card))
    scored.sort(key=lambda x: -x[0])
    return scored[:topn]


def b64url_decode(part):
    """解码 JWT 的 base64url 段，失败返回 None。"""
    part = (part or "").strip()
    part += "=" * (-len(part) % 4)
    try:
        raw = base64.urlsafe_b64decode(part.encode("ascii"))
    except (binascii.Error, ValueError):
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None


def inspect_token(token):
    """解析令牌结构，返回 (header, payload, findings, score)。

    findings 每项为 (级别, 说明)；级别：高危/中危/低危/提示。
    """
    token = (token or "").strip()
    parts = token.split(".")
    if len(parts) != 3:
        return None, None, [("高危", "令牌不是 header.payload.signature 三段式，无法解析。")], 100
    header = b64url_decode(parts[0])
    payload = b64url_decode(parts[1])
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None, None, [("高危", "header 或 payload 不是合法 JSON，令牌结构异常。")], 100

    findings = []
    score = 0

    def add(level, points, text):
        nonlocal score
        findings.append((level, text))
        score += points

    alg = str(header.get("alg", "")).lower()
    if alg == "none":
        add("高危", 100, "alg=none：令牌声明不使用签名，若服务端接受无签名令牌，"
            "攻击者可任意伪造身份。请确认服务端拒绝 alg=none。")
    elif alg == "":
        add("高危", 60, "header 缺少 alg 字段，服务端解析行为不可预期，应拒绝此类令牌。")
    elif alg == "hs256":
        add("提示", 10, "alg=HS256：安全性取决于密钥强度与保密；弱口令密钥可被离线爆破，"
            "且密钥一旦泄露，所有令牌都可伪造。")
    elif alg in ("rs256", "es256", "ps256"):
        add("提示", 0, "alg=%s：非对称签名，公钥可公开；但要警惕密钥混淆攻击——"
            "服务端绝不能把 RSA 公钥当作 HMAC 密钥去验 HS256。" % alg.upper())
    else:
        add("低危", 10, "alg=%s：非常见算法，请确认服务端白名单只放行预期算法。" % alg)

    kid = header.get("kid")
    if kid is not None:
        kid = str(kid)
        if ".." in kid or "/" in kid or "\\" in kid:
            add("高危", 90, "kid 含路径字符（%s）：可能存在 kid 目录遍历，"
                "攻击者借此指定任意文件作为 HMAC 密钥。" % kid)
        elif re.search(r"['\";]|--|\bor\b", kid, re.I):
            add("高危", 90, "kid 含 SQL 特征字符（%s）：可能存在 kid 注入，"
                "请用白名单/固定映射代替拼接查询。" % kid)
        else:
            add("低危", 10, "kid 存在（%s）：请确认服务端用固定映射取密钥，"
                "不要直接用 kid 拼文件路径或 SQL。" % kid)

    for field in ("jku", "x5u"):
        if field in header:
            add("高危", 70, "%s 存在（%s）：攻击者可指向自己控制的密钥地址，"
                "请勿信任令牌自带的密钥 URL。" % (field, header[field]))

    if "exp" not in payload:
        add("中危", 40, "payload 缺少 exp：令牌永不过期，一旦泄露可长期使用，"
            "建议设置较短有效期并配合刷新机制。")
    else:
        try:
            exp = int(payload["exp"])
            if exp < time.time():
                add("中危", 50, "exp 已过期：服务端应拒绝该令牌；若仍能通过，"
                    "说明过期校验缺失。")
            elif exp - time.time() > 7 * 24 * 3600:
                add("低危", 15, "exp 有效期超过 7 天：有效期越长，泄露后的窗口越大，"
                    "建议按业务需要缩短。")
        except (TypeError, ValueError):
            add("低危", 20, "exp 不是合法时间戳，服务端应拒绝该令牌。")

    leaked = sorted(set(str(k).lower() for k in payload) & SENSITIVE_CLAIMS)
    if leaked:
        add("高危", 60, "payload 含敏感字段（%s）：JWT payload 只是 base64 编码，"
            "任何拿到令牌的人都能读出，敏感信息不要放进令牌。" % "、".join(leaked))

    if payload.get("admin") is True or str(payload.get("role", "")).lower() == "admin":
        add("提示", 0, "payload 声明了管理员身份：请确认服务端以签名校验后的"
            "声明为准，且关键操作另有服务端授权检查，不要只信令牌里的角色。")

    if not findings:
        findings.append(("提示", "结构上未发现上述风险点；这不等于安全，"
                         "仍需确认服务端正确验签、校验 exp/aud/iss。"))
    return header, payload, findings, min(score, 100)


def level_of(score):
    if score >= 70:
        return "高危"
    if score >= 30:
        return "中危"
    if score > 0:
        return "低危"
    return "未见风险"


def print_inspect(token, label=None):
    header, payload, findings, score = inspect_token(token)
    print("令牌自查%s：风险分 %d（%s）" % ("：" + label if label else "", score, level_of(score)))
    if header is not None:
        print("  header : %s" % json.dumps(header, ensure_ascii=False))
        print("  payload: %s" % json.dumps(payload, ensure_ascii=False))
    for level, text in findings:
        print("  [%s] %s" % (level, text))
    return 0 if score < 70 else 1


def cmd_ask(args):
    cards = load_kb(args.kb)
    results = ask(args.ask, cards)
    if not results:
        print("没有找到相关知识卡片。换个说法试试，例如：alg=none 有什么危害？")
        return 1
    print("问题：%s" % args.ask)
    for i, (score, card) in enumerate(results, 1):
        print("\n[%d] %s（匹配分 %d，卡片 %s）" % (i, card["title"], score, card["id"]))
        print("    %s" % card["text"])
    return 0


def b64url(obj):
    raw = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def demo_token(header, payload, sig="DEMO"):
    return "%s.%s.%s" % (b64url(header), b64url(payload), b64url(sig))


DEMO_TOKENS = [
    ("alg=none 的伪造令牌",
     demo_token({"alg": "none", "typ": "JWT"},
                {"sub": "attacker", "role": "admin", "iat": 1700000000})),
    ("kid 带路径穿越的令牌",
     demo_token({"alg": "HS256", "kid": "../../etc/passwd"},
                {"sub": "user1", "exp": 9999999999})),
    ("相对规范的令牌",
     demo_token({"alg": "RS256", "typ": "JWT"},
                {"sub": "user2", "role": "user", "exp": 1999999999,
                 "iat": 1700000000, "iss": "demo-app"})),
]

DEMO_QUESTIONS = ["alg=none 有什么危害？", "RS256 变成 HS256 是怎么攻击的？",
                  "JWT 里能放密码吗？"]


def cmd_demo(args):
    cards = load_kb(args.kb)
    print("=== JwtQA 演示：令牌结构自查 ===")
    for label, token in DEMO_TOKENS:
        print()
        print_inspect(token, label)
    print("\n=== JwtQA 演示：典型问答 ===")
    for q in DEMO_QUESTIONS:
        results = ask(q, cards, topn=1)
        print("\n问：%s" % q)
        if results:
            print("答：%s" % results[0][1]["text"])
        else:
            print("答：（无匹配卡片）")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="JwtQA：JWT 安全问答与令牌自查")
    parser.add_argument("--kb", default=KB_PATH, help="知识库 JSON 路径")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--ask", metavar="问题", help="向知识库提问")
    group.add_argument("--inspect", metavar="令牌", help="自查一个 JWT 的结构风险")
    group.add_argument("--demo", action="store_true", help="运行演示")
    args = parser.parse_args(argv)
    if args.demo:
        return cmd_demo(args)
    if args.inspect is not None:
        return print_inspect(args.inspect)
    return cmd_ask(args)


if __name__ == "__main__":
    sys.exit(main())
