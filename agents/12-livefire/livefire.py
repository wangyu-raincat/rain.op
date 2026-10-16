#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LiveFire-QA（12-livefire）：「正在着火的漏洞」离线问答小助手

只收录正在被利用、或暂无补丁的高危漏洞，回答：
  - 哪个最该先修（威胁状态分流）
  - 没补丁的怎么缓（修复/缓解速查）

纯 Python 标准库，无需网络、无需 API Key。
"""
import argparse
import math
import re

# ---------------------------------------------------------------------------
# 知识库：每条 = {编号, 产品, CVSS, 披露时间, 威胁状态, 利用条件, 影响, 修复或缓解, 来源}
# 数据截止：2026-10-14
# ---------------------------------------------------------------------------
KB = [
    {
        "id": "CVE-2026-104935",
        "product": "Ivanti Connect Secure",
        "cvss": "未公布（高危）",
        "disclosed": "2026-10-14",
        "threat": "在野利用中",
        "no_patch": False,
        "condition": "无需凭证即可触发；攻击链复杂度低，属认证绕过接 root 级 RCE 的完整链条。",
        "impact": "未授权攻击者可拿到目标设备 root 权限；已有组织报告被利用入侵。",
        "fix": "立即按 CISA 通告打补丁（受影响：22.8R2.4、25.1.2.2、25.1.1.1 及更早版本）。"
               "注意：补丁只堵住入口，若已被入侵，AD 凭证可能已被盗，需另行全域排查轮换。",
        "source": "https://www.waterisac.org/tlpclear-vulnerability-notification-cisa-urges-patching-newly-exploited-vulnerability-in-ivanti-connect-secure-cve-2026-104935-used-in-unauthenticated-root-level-rce-chain",
    },
    {
        "id": "CVE-2026-104937",
        "product": "Shopware 6.7",
        "cvss": "未公布（高危）",
        "disclosed": "2026-10-14",
        "threat": "暂无补丁",
        "no_patch": True,
        "condition": "媒体上传功能接受 HTML 文件且缺少安全响应头；管理员点击恶意链接即触发存储型 XSS。",
        "impact": "管理员 token 被盗；若管理员有扩展管理权限，可进一步升级为整机 RCE。",
        "fix": "暂无官方补丁。缓解：限制/禁用媒体上传中的 HTML 文件类型；给后台管理页面加可信来源访问控制；"
               "提醒管理员不点未知链接；关注厂商后续公告及时升级（CERT/CC 因联系不上厂商已直接披露，编号 VU#157374）。",
        "source": "https://securityonline.info/shopware-vulnerability-cve-2026-104937/",
    },
    {
        "id": "ZDI-26-756",
        "product": "Genesis World",
        "cvss": "无（ZDI 公开咨询，未分配 CVE）",
        "disclosed": "2026-10-14",
        "threat": "无补丁（zero-day）",
        "no_patch": True,
        "condition": "`load_checkpoint` 接口存在反序列化漏洞；ZDI 联系维护者 3 个月无回应后公开。",
        "impact": "远程代码执行；AI/ML 供应链场景下的典型零日案例。",
        "fix": "暂无补丁。唯一缓解：限制与该产品的交互面（网络隔离、最小权限、不加载不可信 checkpoint）；"
               "在 AI 训练/推理链路中把它当作不可信组件对待。",
        "source": "https://deafnews.it/en/news/zero/zero-day-rce-in-genesis-world-zdi-publishes-advisory-with-no-patch-available",
    },
    {
        "id": "CVE-2026-103572",
        "product": "Visual Studio Copilot（影响 VS 2022 17.14 / SSMS）",
        "cvss": "8.8",
        "disclosed": "2026-10-13（10 月补丁星期二）",
        "threat": "PoC 已公开，暂无在野利用",
        "no_patch": False,
        "condition": "间接 prompt injection 触发：AI 处理不可信文件或外部数据时中招；"
                   "VS 与 SSMS 共享 `Microsoft.VisualStudio.Copilot.Core.dll`，一处中招多处受影响。",
        "impact": "远程代码执行；AI 工具链安全的新鲜案例——攻击面从代码本身扩展到 AI 处理的数据。",
        "fix": "按 10 月补丁星期二更新到修复版本；缓解：让 Copilot 处理不可信内容前先做输入审查，"
               "生产/敏感环境谨慎开启 AI 自动处理外部数据的能力。",
        "source": "https://securityonline.info/cve-2026-103572-visual-studio-copilot-rce-disclosed/",
    },
    {
        "id": "CVE-2026-89107",
        "product": "SAP S/4HANA（Manage Substitution / Validation Rules）",
        "cvss": "9.9",
        "disclosed": "2026-10-13",
        "threat": "已披露，需认证",
        "no_patch": False,
        "condition": "需认证；规则定义功能的领域脚本语言输入校验不足。",
        "impact": "核心 ERP 系统远程代码执行；一旦得手可直接触及企业财务与业务核心数据。",
        "fix": "按 SAP 安全通告升级到修复版本；缓解：收紧规则定义功能的访问权限（最小授权），"
               "对规则脚本变更做审计与变更审批。",
        "source": "https://www.thehackerwire.com/vulnerability/CVE-2026-89107/",
    },
]

CVE_RE = re.compile(r"(CVE-\d{4}-\d+|ZDI-\d{2}-\d+)", re.IGNORECASE)


# ---------------------------------------------------------------------------
# 分词：英文按词切分，中文按单字切分（双语 BM25）
# ---------------------------------------------------------------------------
def tokenize(text):
    text = text.lower()
    tokens = re.findall(r"[a-z0-9]+(?:[-.][a-z0-9]+)*", text)
    for ch in text:
        if "一" <= ch <= "鿿":
            tokens.append(ch)
    return tokens


class BM25:
    def __init__(self, docs, k1=1.5, b=0.75):
        self.k1, self.b = k1, b
        self.docs = [tokenize(d) for d in docs]
        self.N = len(self.docs)
        self.avgdl = sum(len(d) for d in self.docs) / max(1, self.N)
        df = {}
        for d in self.docs:
            for t in set(d):
                df[t] = df.get(t, 0) + 1
        self.idf = {t: math.log(1 + (self.N - c + 0.5) / (c + 0.5))
                    for t, c in df.items()}

    def score(self, query):
        qt = tokenize(query)
        out = []
        for d in self.docs:
            s, dl = 0.0, len(d)
            for t in qt:
                f = d.count(t)
                if f and t in self.idf:
                    s += self.idf[t] * f * (self.k1 + 1) / (
                        f + self.k1 * (1 - self.b + self.b * dl / self.avgdl))
            out.append(s)
        return out


def doc_text(e):
    return " ".join([e["id"], e["product"], e["cvss"], e["threat"],
                     e["condition"], e["impact"], e["fix"]])


RETRIEVER = BM25([doc_text(e) for e in KB])


def rank(query, entries, top_k=3):
    idx = [KB.index(e) for e in entries]
    scores = RETRIEVER.score(query)
    ranked = sorted(idx, key=lambda i: scores[i], reverse=True)
    return [(KB[i], scores[i]) for i in ranked if scores[i] > 0][:top_k]


# ---------------------------------------------------------------------------
# 输出
# ---------------------------------------------------------------------------
def show_card(e, score=None):
    line = "-" * 60
    print(line)
    print("HOT %s  |  %s" % (e["id"], e["product"]))
    print("   CVSS：%s ｜ 披露：%s ｜ 状态：【%s】" % (e["cvss"], e["disclosed"], e["threat"]))
    print("   利用条件：%s" % e["condition"])
    print("   影响：%s" % e["impact"])
    print("   修复/缓解：%s" % e["fix"])
    print("   来源：%s" % e["source"])
    if score is not None:
        print("   （检索得分 %.2f）" % score)
    print(line)


def by_cve(query):
    m = CVE_RE.search(query)
    if not m:
        return None
    want = m.group(1).upper()
    for e in KB:
        if e["id"].upper() == want:
            return e
    return None


def cmd_exploited():
    hits = [e for e in KB if "在野利用" in e["threat"] and "暂无" not in e["threat"]]
    print("!!  在野利用中的漏洞（%d 条，最优先处理）：\n" % len(hits))
    for e in hits:
        show_card(e)


def cmd_unpatched():
    hits = [e for e in KB if e["no_patch"]]
    print("++ 暂无补丁的漏洞（%d 条，靠缓解措施顶着）：\n" % len(hits))
    for e in hits:
        show_card(e)


def cmd_fix(query):
    e = by_cve(query)
    if e:
        print(">> 编号精确命中，直接给修复/缓解方案：\n")
        show_card(e)
        return
    hits = rank(query, KB, top_k=3)
    if not hits:
        print("没找到相关漏洞，换个关键词试试（或直接问编号，如 CVE-2026-104935）。")
        return
    print(">> 按相关度给出修复/缓解方案：\n")
    for e, s in hits:
        show_card(e, s)


def cmd_ask(query):
    e = by_cve(query)
    if e:
        print(">> 编号精确命中：\n")
        show_card(e)
        return
    hits = rank(query, KB, top_k=3)
    if not hits:
        print("没找到相关漏洞。试试：--exploited（在野利用）、--unpatched（无补丁）、或直接问编号。")
        return
    print(">> 检索结果（按相关度）：\n")
    for e, s in hits:
        show_card(e, s)


def cmd_demo():
    print("=" * 60)
    print("** LiveFire-QA 离线演示 **")
    print("=" * 60)
    print("\n[演示 1] 无补丁的有哪些？（--unpatched）\n")
    cmd_unpatched()
    print("\n[演示 2] Ivanti 那个（在野利用）怎么修？（--fix）\n")
    cmd_fix("Ivanti 那个在野利用的怎么修 CVE-2026-104935")
    print("\n[演示 3] 自然语言提问：shopware xss\n")
    for e, s in rank("shopware xss 存储型 跨站", KB, top_k=1):
        show_card(e, s)
    print("\n[演示 4] 在野利用中的有哪些？（--exploited）\n")
    cmd_exploited()
    print("\nOK 演示结束。试试：python livefire.py --exploited / --unpatched / --fix \"关键词\"")


def main(argv=None):
    ap = argparse.ArgumentParser(description="LiveFire-QA：正在着火的漏洞离线问答（纯标准库）")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--exploited", action="store_true", help="只看在野利用中的漏洞（最优先修）")
    g.add_argument("--unpatched", action="store_true", help="只看暂无补丁的漏洞（看缓解措施）")
    g.add_argument("--fix", action="store_true", help="修复/缓解速查模式（配合查询词）")
    g.add_argument("--demo", action="store_true", help="离线演示")
    ap.add_argument("query", nargs="?", default="", help="查询词：自然语言、产品名或 CVE/ZDI 编号")
    args = ap.parse_args(argv)

    if args.demo:
        return cmd_demo()
    if args.exploited:
        return cmd_exploited()
    if args.unpatched:
        return cmd_unpatched()
    if args.fix:
        return cmd_fix(args.query)
    if not args.query:
        ap.print_help()
        return
    return cmd_ask(args.query)


if __name__ == "__main__":
    main()
