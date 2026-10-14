#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VulnIntel-QA 🛡️ 2026年10月高危漏洞情报离线问答

用 BM25 检索内置的 4 条 2026 年 10 月真实高危 CVE 知识库，回答
"这个漏洞影响谁、利用条件是什么、修复版本是多少、是否已被在野利用"。
纯 Python 标准库，离线可运行，不依赖任何外部 API。

知识库来源：Patchstack / Cisco / Citrix / GitHub 安全公告及多家安全媒体报道
（2026-10-13 核验整理，条目附来源链接；CVSS 口径以条目内标注为准）。

用法:
    python vulnintel.py --demo                 演示模式：自动回答 5 个示例问题
    python vulnintel.py "CVE-2026-85097 是什么漏洞"
    python vulnintel.py --id CVE-2026-76465    按 CVE 编号精确查询
    python vulnintel.py --list                  列出知识库全部 CVE
    python vulnintel.py --exploited             哪些已被在野利用
    python vulnintel.py --needs-config          哪些需要特殊配置才受影响
    python vulnintel.py --fix                   全部修复版本速查
"""

import math
import re
import sys
from collections import Counter

# ---------------------------------------------------------------- 知识库
# 4 条 2026 年 10 月报道的高危 CVE（核验于 2026-10-13）
KB = [
    dict(
        cve="CVE-2026-85097",
        cvss="10.0（Patchstack；官方 CVE 记录 9.8）",
        product="WordPress Bricksforge 插件（Pro Forms 模块）",
        affected="Bricksforge ≤ 3.1.8.9；表单含上传字段的站点均受影响；"
                "供应商称即使表单没有上传字段，只要 Pro Forms 激活就受影响。",
        prereq="无特殊配置前置：Pro Forms 激活即可。",
        auth="无需登录（unauthenticated）",
        root_cause="上传时校验了 MIME，但表单提交时信任客户端传的 "
                   "temporaryFileUploads 参数里的 url 字段，不做二次校验。",
        chain="① 未授权 AJAX bricksforge_regenerate_nonce 取有效 nonce → "
              "② 上传 GIF/PHP polyglot（合法图片 + 内嵌 PHP），通过 MIME 校验落进临时目录 → "
              "③ 提交表单：服务端文件路径指向已校验的图片，但 url 以 .php 结尾 → "
              "④ PHP 落盘被执行 → RCE。",
        fix="升级到 3.1.8.10 起（供应商同时建议直接升级到最新 4.0.1）。",
        exploited="✅ 已在野利用：Patchstack 于 2026-10-07 21:47 UTC 首次观测到，"
                  "数小时内 63 个独立 IP，自动化批量探测 PHP 扩展变体。",
        detect="审计对 /wp-json/bricksforge/v1/form_submit 和 admin-ajax.php"
               "（action=bricksforge_form_submit）且带 temporaryFileUploads 参数的请求；"
               "检查 wp-content/uploads/bricksforge/tmp/ 下意外 PHP 文件（如 login_admin_*.php）；"
               "排查未知管理员账号。",
        sources="thehackernews.com / scworld.com / deafnews.it / wpdeeply.com",
        keys="wordpress 插件 文件上传 webshell polyglot mime 绕过 bricksforge 表单 nonce 未授权",
    ),
    dict(
        cve="CVE-2026-76465",
        cvss="9.8",
        product="Cisco Nexus 3000 / Nexus 9000（独立 NX-OS 模式）",
        affected="Nexus 3000 系列、独立 NX-OS 模式的 Nexus 9000；"
                "Nexus 9000（Silicon One ASIC）无法开启该功能、不受影响；ACI 模式不受影响。",
        prereq="⚠️ 必须开启 MPLS OAM（默认关闭）才受影响。",
        auth="无需登录（unauthenticated），远程攻击",
        root_cause="处理 MPLS echo-request 包时校验不当（CWE-590，free of memory not on the heap）。",
        chain="远程未授权攻击者向交换机上某个 IP 地址发送构造的 MPLS echo-request → "
              "以 root 权限执行任意代码，或进程崩溃导致设备重启 → DoS。",
        fix="Cisco 2026-10-07 安全公告已发布修复软件更新（另有 Live Protect 屏蔽规则）；无 workaround。",
        exploited="❌ Cisco 官方表示发布时未发现已知的恶意利用。",
        detect="先确认哪些交换机实际开启了 MPLS OAM（NGOAM 检查不能替代此检查）；"
               "管理面访问审计会漏掉非管理接口的攻击路径。",
        sources="nulltap.sh / cvefeed.io（Cisco 2026-10-07 安全公告）",
        keys="cisco nexus 交换机 mpls oam echo root 网络设备 思科",
    ),
    dict(
        cve="CVE-2026-107406",
        cvss="9.5（CVSS v4.0）",
        product="Citrix NetScaler ADC / NetScaler Gateway",
        affected="作 SAML IdP 时：14.1-73.37～14.1-73.41、13.1-64.23～13.1-64.28、"
                "13.1-FIPS/NDcPP 13.1-37.279～13.1-37.282；"
                "作 SAML SP 或 IdP 时：更老版本（14.1-73.37 之前 / 13.1-64.23 之前 / "
                "13.1-37.279 之前）全部受影响；Secure Private Access 混合部署中使用的 NetScaler 同样受影响。",
        prereq="⚠️ 设备必须被配置为 SAML SP（配置含 add authentication samlAction）"
               "或 SAML IdP（配置含 add authentication samlIdPProfile）才受影响。",
        auth="无需登录（unauthenticated），远程攻击",
        root_cause="内存缓冲区边界限制不当（CWE-119），内存溢出。",
        chain="未授权远程攻击者针对 SAML 配置的设备触发内存溢出 → RCE 或 DoS。",
        fix="升级到 14.1-73.46 及以上；13.1-64.29 及以上；"
            "14.1-FIPS 14.1-73.46 FIPS 及以上；13.1-FIPS/NDcPP 13.1.37.283 及以上。",
        exploited="❌ Citrix 通报发布时\"未发现未缓解的利用\"；公告 CTX697191 发布于 2026-10-08。"
                  "背景：这是 Citrix 不到两周内第三次 NetScaler 紧急补丁。",
        detect="检查配置中是否有 add authentication samlAction / "
               "add authentication samlIdPProfile 条目，确认是否在受影响配置范围内。",
        sources="support.citrix.com（CTX697191）/ csa.gov.sg",
        keys="citrix netscaler saml 内存溢出 缓冲区 网关 adc idp sp",
    ),
    dict(
        cve="CVE-2026-90970",
        cvss="9.9",
        product="GitLab AI Gateway（自托管，GitLab Duo / Duo Agent Platform 背后的服务）",
        affected="自托管 GitLab AI Gateway：18.1.6～19.2.3、19.3.0～19.3.1、19.4.0；"
                "18.1.6 之前版本经确认也覆盖在此区间内按 18.1.6 起算。"
                "核心 GitLab 升级不修复此问题，必须单独升级 Gateway 镜像。",
        prereq="需要已认证用户 + 有 Duo Agent Platform 访问权限。",
        auth="需要登录（authenticated）",
        root_cause="用户自定义 agent flow 定义经服务端模板引擎渲染（本质是 SSTI，"
                   "服务器端模板注入），提示模板沙箱未做中和（CWE-1336）。",
        chain="提交构造的 flow 配置 → 逃出提示模板沙箱 → "
              "在 AI Gateway 主机/容器上执行任意命令（注意：是服务器端代码执行，不是 AI prompt injection）。",
        fix="升级到 19.2.4 / 19.3.2 / 19.4.1（披露于 2026-10-02）。"
            "GitLab 自托管云网关已提前修复。",
        exploited="❌ 无已知利用、无公开 PoC；HackerOne 研究员 invisiblemeerkat 负责披露。"
                  "备注：同组件 2026 年 2 月修过 CVE-2026-1868（同样 CVSS 9.9、同样 CWE-1336、"
                  "同样攻击面），沙箱二次被绕过。",
        detect="审计 AI Gateway 的自定义 flow / agent 定义提交记录；"
               "检查 Gateway 容器异常进程与外联行为。",
        sources="thehackernews.com / aiweekly.co",
        keys="gitlab ai gateway duo agent ssti 沙箱逃逸 模板注入 提示词",
    ),
]

# ---------------------------------------------------------------- 分词与 BM25
STOP = {"的", "了", "是", "在", "和", "与", "或", "如何", "怎么", "什么", "为什么",
        "哪些", "哪个", "这种", "那个", "以及", "被", "把", "对", "就", "而", "及",
        "并", "等", "有关", "漏洞", "高危", "修复", "攻击", "版本", "多少", "是否",
        "已经", "这个", "有没有", "请问", "一下"}

def tokenize(text):
    text = text.lower()
    toks = []
    toks += re.findall(r"[a-z0-9]+(?:[.\-][a-z0-9]+)*", text)   # 英文词/编号/版本号
    chs = re.findall(r"[\u4e00-\u9fff]", text)
    toks += [a + b for a, b in zip(chs, chs[1:])]                # 中文二元组
    return [t for t in toks if (t not in STOP and len(t) > 1) or t.isdigit()]

def build_index(docs):
    df = Counter()
    doc_tf = []
    for d in docs:
        field = " ".join([d["cve"], d["cvss"], d["product"], d["affected"], d["prereq"],
                          d["auth"], d["root_cause"], d["chain"], d["fix"],
                          d["exploited"], d["detect"], d["keys"]])
        tf = Counter(tokenize(field))
        # CVE 编号 / 产品 / 关键词 加权
        boost = Counter(tokenize(d["cve"] + " " + d["product"] + " " + d["keys"]))
        for t, c in boost.items():
            tf[t] += c * 2
        doc_tf.append(tf)
        for t in tf:
            df[t] += 1
    N = len(docs)
    idf = {t: math.log((N - df_t + 0.5) / (df_t + 0.5) + 1) for t, df_t in df.items()}
    avgdl = sum(sum(tf.values()) for tf in doc_tf) / N
    return doc_tf, idf, avgdl

DOC_TF, IDF, AVGDL = build_index(KB)
K1, B = 1.5, 0.75

def search(query, topn=3):
    qtf = Counter(tokenize(query))
    scores = []
    for i, tf in enumerate(DOC_TF):
        dl = sum(tf.values())
        s = 0.0
        for t, q in qtf.items():
            if t not in tf:
                continue
            num = tf[t] * (K1 + 1)
            den = tf[t] + K1 * (1 - B + B * dl / AVGDL)
            s += IDF.get(t, 0) * num / den * (1 + math.log1p(q))
        scores.append((s, i))
    scores.sort(reverse=True)
    return [(KB[i], s) for s, i in scores[:topn] if s > 0]

def find_by_id(cid):
    cid = cid.strip().upper()
    if not cid.startswith("CVE-"):
        cid = "CVE-" + cid.lstrip("-")
    for e in KB:
        if e["cve"].upper() == cid:
            return e
    return None

def card(e):
    line = "─" * 46
    return (
        f"\n{line}\n"
        f"🛡️ {e['cve']} · CVSS {e['cvss']}\n"
        f"产品: {e['product']}\n"
        f"{line}\n"
        f"📌 影响范围: {e['affected']}\n"
        f"🔑 前置条件: {e['prereq']}\n"
        f"👤 认证要求: {e['auth']}\n"
        f"🐛 根因: {e['root_cause']}\n"
        f"⛓️ 攻击链: {e['chain']}\n"
        f"🩹 修复版本: {e['fix']}\n"
        f"🌐 在野利用: {e['exploited']}\n"
        f"🔍 排查要点: {e['detect']}\n"
        f"📚 来源: {e['sources']}\n"
    )

def answer(query):
    # ① CVE 编号精确命中
    m = re.search(r"\bCVE[-\s]?\d{4}[-\s]?\d{4,6}\b", query.upper())
    if m:
        e = find_by_id(m.group(0))
        if e:
            print(f"✅ 编号精确命中 {e['cve']}")
            print(card(e))
            return
    # ② 聚合类问题：先按意图分流
    q = query
    if any(w in q for w in ("在野利用", "被利用", "正在利用", "野外利用", "已被利用")):
        hits = [e for e in KB if e["exploited"].startswith("✅")]
        print(f"🔎 知识库中 {len(hits)} 条已被在野利用：")
        for e in hits:
            print(card(e))
        return
    if any(w in q for w in ("特殊配置", "前置条件", "默认关闭", "需要配置", "才受影响")):
        hits = [e for e in KB if "⚠️" in e["prereq"]]
        print(f"🔎 知识库中 {len(hits)} 条需要特殊配置才受影响：")
        for e in hits:
            print(card(e))
        return
    if any(w in q for w in ("修复版本", "怎么修复", "如何修复", "升级到")) and \
            not re.search(r"\bCVE[-\s]?\d", q.upper()):
        print("🔎 全部修复版本速查：")
        for e in KB:
            print(f"  {e['cve']:16} {e['fix']}")
        return
    # ③ BM25 自然语言检索
    hits = search(query)
    if not hits:
        print("😅 知识库里没找到相关漏洞，换个关键词试试"
              "（如：wordpress / cisco / netscaler / gitlab / 在野利用 / 修复版本）。")
        return
    print(f"🔎 检索到 {len(hits)} 条相关漏洞，最相关：")
    for e, s in hits:
        print(card(e))

def demo():
    print("=" * 50)
    print("🛡️ VulnIntel-QA 演示：2026年10月高危漏洞情报离线问答")
    print(f"   知识库: {len(KB)} 条真实 CVE ｜ 检索: BM25 ｜ 依赖: 仅标准库")
    print("=" * 50)
    for q in [
        "CVE-2026-85097 是什么漏洞",
        "哪些漏洞已经被在野利用了",
        "哪些漏洞需要特殊配置才受影响",
        "WordPress 插件漏洞怎么修复",
        "Citrix NetScaler 的修复版本是多少",
    ]:
        print(f"\n❓ 问: {q}")
        answer(q)
    print("\n✨ 演示结束。直接 `python vulnintel.py \"你的问题\"` 开始提问。")

def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
    elif argv[0] == "--demo":
        demo()
    elif argv[0] == "--list":
        for e in KB:
            print(f"{e['cve']:16} CVSS {e['cvss']:28} {e['product']}")
    elif argv[0] == "--id" and len(argv) > 1:
        e = find_by_id(argv[1])
        print(card(e) if e else f"😅 没找到编号 {argv[1]}")
    elif argv[0] == "--exploited":
        answer("哪些漏洞已经被在野利用了")
    elif argv[0] == "--needs-config":
        answer("哪些漏洞需要特殊配置才受影响")
    elif argv[0] == "--fix":
        answer("全部漏洞的修复版本是多少")
    else:
        answer(" ".join(argv))

if __name__ == "__main__":
    main(sys.argv[1:])
