#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RansomQA -- 勒索软件应急响应离线问答 agent。

内置 18 张知识卡片：以 2026-10-20 发布的联合通告 AA26-293A
（#StopRansomware: SafePay Ransomware，FBI / CISA / USSS /
德国莱法州刑警 / 英国 NCA 联合发布，约 600 家受害组织）为
核心情报，叠加勒索软件应急响应 Playbook（隔离、遏制、根除、
恢复、谈判、合规报告）。

- 纯标准库，离线可跑
- BM25 检索 + 抽取式回答（按句子打分拼回答）
- 支持：交互问答 / 单次查询 / --demo 演示

用法:
    python3 ransomqa.py --demo
    python3 ransomqa.py --query "SafePay 是怎么进来的"
    python3 ransomqa.py                 # 交互模式
"""
import argparse
import math
import re
import sys

# ---------------------------------------------------------------- 知识卡片 ----
# 每张卡: id / title / keywords(检索加权) / body(回答来源)
CARDS = [
    {
        "id": "safepay-profile",
        "title": "SafePay 组织情报（AA26-293A）",
        "keywords": "safepay aa26-293a stopransomware 通告 联合",
        "body": (
            "2026-10-20，FBI、CISA、美国特勤局（USSS）、德国莱法州刑警"
            "（Landeskriminalamt Rheinland-Pfalz）、英国国家打击犯罪局（NCA）"
            "及英国西北有组织犯罪调查组联合发布 #StopRansomware 通告 "
            "AA26-293A，主题为 SafePay 勒索软件。"
            "SafePay 自 2024-08 活跃至今，已波及约 600 家组织，覆盖北美、"
            "南美、欧洲、澳洲的多个关键基础设施行业。典型手法是双重勒索："
            "先窃取数据再加密系统，拒付则威胁公开数据。公开通告未将其归因"
            "到任何特定国家或已知团伙。"
        ),
    },
    {
        "id": "safepay-access",
        "title": "SafePay 初始入侵方式",
        "keywords": "初始 入侵 入口 钓鱼 vpn 凭证 密码 边界",
        "body": (
            "按 AA26-293A 通告，SafePay 的初始立足点主要来自四类："
            "（1）被盗/被猜解的凭证；（2）钓鱼邮件；（3）互联网暴露面安全"
            "设备的已知漏洞利用，尤其是 VPN 服务；（4）面向公网的防火墙/"
            "边界设备漏洞。CISA 官员特别强调：带已知漏洞的公网设备仍是"
            "SafePay 这类团伙最常盯的目标。自查优先级：先看 VPN/防火墙"
            "补丁状态和面向公网的备份服务器。"
        ),
    },
    {
        "id": "safepay-ttps",
        "title": "SafePay 攻击链与破坏手法",
        "keywords": "ttp 攻击链 横向 移动 加密 备份 删除 双重 勒索 电话",
        "body": (
            "SafePay 进入内网后大量使用合法 IT/运维工具进行横向移动、数据"
            "窃取和加密，以此规避传统恶意软件检测。其标志性破坏动作："
            "删除本地备份副本、重置存放备份的 NAS 设备，彻底断掉受害者"
            "不付赎金的恢复路。施压手段除泄露网站外，还包括直接打电话"
            "向受害者索要赎金、威胁公开被盗数据。取证时重点看：异常新增"
            "账户、远程管理工具活动、安全服务被改动、异常外发流量。"
        ),
    },
    {
        "id": "safepay-iocs",
        "title": "SafePay 失陷指示器（IOC）",
        "keywords": "ioc ip 失陷 指示 域名 stix 情报",
        "body": (
            "AA26-293A 附带的 IOC（含已做脱敏处理的 IP，研判时请在受控"
            "的威胁情报平台如 MISP / VirusTotal / SIEM 内还原使用）："
            "104.26.2[.]223、140.82.114[.]4、185.199.108[.]133、"
            "77.37.49[.]40（均为受害者入侵相关），173.194.194[.]94"
            "（托管受害者数据）。行为型指示器：非预期账户、远程管理"
            "活动、安全服务变更、异常出站传输。通告同时提供可下载的 "
            "STIX 格式情报包。注意：合法工具和历史 IP 必须结合上下文"
            "研判后再封禁，避免误伤。"
        ),
    },
    {
        "id": "safepay-mitigations",
        "title": "AA26-293A 官方缓解措施",
        "keywords": "缓解 防护 加固 mfa 零信任 备份 补丁 官方 建议",
        "body": (
            "通告给出的关键行动（Key Actions）很短，按优先级："
            "（1）紧急修补已知被利用漏洞，尤其防火墙与边界/VPN 设备；"
            "（2）落实身份与凭证访问管理（ICAM）策略并强制多因素认证"
            "（MFA）；（3）限制管理工具与特权；（4）推进零信任；"
            "（5）网络分段；（6）保留离线、加密、不可变的备份并定期"
            "测试恢复流程。通告敦促受害者向执法部门报告事件，并明确"
            "警告：支付赎金不保证文件能恢复。"
        ),
    },
    {
        "id": "ir-first-hour",
        "title": "应急第一小时：隔离与保全证据",
        "keywords": "第一小时 隔离 断网 证据 内存 镜像 日志 应急 响应 加密 勒索",
        "body": (
            "发现勒索加密迹象后的第一个小时只做四件事："
            "（1）隔离受影响主机——拔网线/禁用网卡/挂起虚拟机，优先断网"
            "不断电，避免内存证据丢失；（2）保全证据——内存镜像、系统与"
            "安全日志、勒索信原样保留，不要急着重装；（3）判定范围——"
            "哪些网段、哪些备份受影响，VPN 会话是否异常；（4）拉起应急"
            "小组并冻结变更。禁忌：不要先谈赎金、不要全网关机、不要"
            "在查清入口前恢复业务。"
        ),
    },
    {
        "id": "ir-containment",
        "title": "遏制：切断攻击者立足点",
        "keywords": "遏制 横向 切断 凭证 重置 vpn 会话 封禁",
        "body": (
            "遏制阶段目标是让攻击者动不了、看不见：全网分段隔离受感染"
            "区域；强制下线所有 VPN/远程接入会话并重置相关凭证；禁用"
            "异常账户、轮换域管与服务账户口令及 API 密钥；按 IOC 封禁"
            "恶意 IP/域名（先在 SIEM 确认上下文）；暂停计划任务与可疑"
            "的远程管理工具。做完一轮后做第二遍确认——SafePay 这类"
            "团伙常用合法工具潜伏，单轮清理极易漏网。"
        ),
    },
    {
        "id": "ir-eradication",
        "title": "根除：重建与堵入口",
        "keywords": "根除 重建 重装 补丁 入口 漏洞 修复",
        "body": (
            "确认遏制有效后再根除：从干净介质重建系统，不从被加密的"
            "镜像直接恢复业务；修补最初的入侵入口（SafePay 场景下优先"
            "是 VPN/边界设备漏洞与弱凭证）；全量轮换凭证、证书与密钥；"
            "审查并收紧防火墙/VPN 的对外暴露面。根除完成的标志是："
            "能说清攻击者怎么进来、动了哪里、拿走什么——说不清就不算"
            "根除，不能进入恢复阶段。"
        ),
    },
    {
        "id": "ir-recovery",
        "title": "恢复：从备份重建业务",
        "keywords": "恢复 备份 还原 上线 验证 业务",
        "body": (
            "只从离线、不可变、且经完整性校验的备份恢复；恢复前先在隔离"
            "沙箱验证备份本身未被投毒。按业务优先级分批上线，每批上线"
            "后做增强监控（重点看异常账户与外发流量）。恢复期间保留"
            "全部操作记录以备取证与保险理赔。记住 SafePay 会主动破坏"
            "备份：凡是与生产网络长期连通的 NAS/备份服务器，都要先当"
            "作已被污染来验证。"
        ),
    },
    {
        "id": "ir-backup",
        "title": "备份防护：3-2-1 与不可变备份",
        "keywords": "备份 321 不可变 离线 nas 测试 还原",
        "body": (
            "3-2-1 原则：至少 3 份数据、2 种不同介质、1 份离线异地。"
            "勒索时代再加两条：备份必须不可变（WORM/对象锁，保留期内"
            "谁都删不掉，包括管理员）且至少一份与生产网络物理/逻辑"
            "隔离。SafePay 通告的教训：把 NAS 当备份终点又长期在线，"
            "等于把备份送给攻击者重置。每季度至少做一次真实还原演练，"
            "没演练过的备份等于没有备份。"
        ),
    },
    {
        "id": "ir-double-extortion",
        "title": "双重勒索：付还是不付",
        "keywords": "双重 勒索 赎金 付 数据 泄露 决策",
        "body": (
            "双重勒索 = 加密 + 威胁公开窃取的数据，SafePay 是典型代表。"
            "决策框架：（1）先评估备份可恢复性——能完整恢复就不必考虑"
            "付款；（2）评估被盗数据的敏感度与公开后果；（3）记住官方"
            "立场：CISA/FBI 明确表示付款不保证恢复，且可能触及制裁与"
            "资助犯罪的法律风险；（4）任何付款决策必须经法务与管理层"
            "共同做出并留档。无论付不付，都要向执法部门报告事件。"
        ),
    },
    {
        "id": "ir-negotiation",
        "title": "与攻击者沟通/谈判要点",
        "keywords": "谈判 沟通 赎金信 拖延 取证",
        "body": (
            "如需接触攻击者（哪怕只是为了争取时间）：由固定发言人统一"
            "对外，全部沟通留档；不要透露数据价值、备份状态与保险额度；"
            "以拖延换取取证与恢复时间，要求对方提供解密验证样本；"
            "重要谈判建议交由专业 IR/谈判团队处理。切勿私下用个人渠道"
            "联系——所有往来都可能成为后续法律程序的证据。"
        ),
    },
    {
        "id": "ir-legal",
        "title": "合规报告义务",
        "keywords": "合规 报告 法律 执法 网安法 数据安全 义务",
        "body": (
            "AA26-293A 通告敦促受害者向执法部门报告事件。各国/各地区对"
            "网络安全事件与数据泄露另有法定报告义务（如向网信、公安等"
            "主管部门报告重大事件，向受影响个人告知数据泄露），时限"
            "通常以小时/天计，逾期可能面临处罚。应急预案里必须预置："
            "报告对象清单、报告时限、报告模板与法务对接人。注意：公开"
            "披露前先与法务确认措辞，避免承认超出事实的责任。"
        ),
    },
    {
        "id": "ir-hunting",
        "title": "威胁狩猎：SafePay 类入侵线索",
        "keywords": "狩猎 威胁 hunt 查询 siem 排查 线索",
        "body": (
            "在 SIEM/EDR 里按这组线索做一轮狩猎：新增/异常提权账户；"
            "非工作时间或非运维 IP 的远程管理工具（RDP/SSH/WinRM 类）"
            "会话；安全服务/EDR 被停止或卸载；短时间内大量文件改扩展名；"
            "向陌生外部 IP 的大流量外发；VPN 网关的异常登录（异地、"
            "爆破）。结合 AA26-293A 的 IOC 做关联，但合法工具类告警"
            "必须人工研判上下文后再处置。"
        ),
    },
    {
        "id": "ir-vpn-hardening",
        "title": "VPN/边界设备加固清单",
        "keywords": "vpn 防火墙 边界 加固 补丁 mfa 暴露面",
        "body": (
            "SafePay 的主入口就是 VPN/边界设备，加固清单："
            "（1）立即修补在 KEV 目录中的 VPN/防火墙漏洞；（2）VPN 强制"
            "MFA，禁用弱认证方式；（3）关闭不用的服务与管理端口的外网"
            "暴露；（4）开启并外发 VPN/防火墙日志到 SIEM，保留至少"
            "180 天；（5）定期做暴露面扫描，确认没有被遗忘的测试 VPN"
            "或旧固件设备。记住：边界设备补丁的 SLA 应该是小时级，"
            "不是月度窗口。"
        ),
    },
    {
        "id": "ir-phishing",
        "title": "钓鱼入口自查",
        "keywords": "钓鱼 邮件 附件 宏 培训 社工",
        "body": (
            "钓鱼仍是 SafePay 等团伙的常用初始向量。自查项：邮件网关"
            "是否拦截可执行附件与宏文档；是否部署链接改写/沙箱引爆；"
            "高管与财务是否做过针对性社工演练；员工上报可疑邮件的通道"
            "是否畅通且有反馈。技术上再加一层：禁用 Office 宏默认执行、"
            "落地附件自动送沙箱。一次全员钓鱼演练的点击率，就是你们"
            "真实的初始入侵概率抽样。"
        ),
    },
    {
        "id": "ir-phone-pressure",
        "title": "应对攻击者的电话/施压",
        "keywords": "电话 施压 威胁 公开 泄露 心理",
        "body": (
            "SafePay 会直接打电话向受害者施压要求付款。应对原则："
            "接电话的人只记录、不承诺、不争吵；立即把号码、时间、"
            "通话内容记入事件时间线并同步 IR 小组；不要按对方要求"
            "单独行动或私下转账；把施压行为本身作为证据留存并告知"
            "执法部门。提前在预案里指定唯一的对外发言人，避免多头"
            "回应被各个击破。"
        ),
    },
    {
        "id": "ir-lessons",
        "title": "复盘：把一次事件变成能力",
        "keywords": "复盘 总结 改进 演练 桌面 推演 教训",
        "body": (
            "事件关闭后 2 周内做无指责复盘，输出四样东西：完整攻击"
            "时间线、根因与失守环节、已落地的整改项（负责人+期限）、"
            "更新后的应急预案。把本次事件改编成桌面推演剧本，每半年"
            "演一次。对管理层的汇报只讲三句话：发生了什么、花了多少、"
            "下次同类事件能快多少。没有复盘的应急，等于为下一次交"
            "同样的学费。"
        ),
    },
]


# ------------------------------------------------------------------- BM25 ----
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
        for i, d in enumerate(self.docs):
            s = 0.0
            dl = len(d)
            for t in qt:
                if t not in self.idf:
                    continue
                f = d.count(t)
                denom = f + self.k1 * (1 - self.b + self.b * dl / self.avgdl)
                s += self.idf[t] * f * (self.k1 + 1) / denom
            out.append((s, i))
        return sorted(out, reverse=True)


CORPUS = ["%s %s %s" % (c["title"], c["keywords"], c["body"]) for c in CARDS]
_RETRIEVER = BM25(CORPUS)


# --------------------------------------------------------------- 抽取式回答 ----
SENT_SPLIT = re.compile(r"(?<=[。！？；])|(?<!\d)[.!?;](?!\d)")


def extract_answer(card, query, max_sentences=4):
    """按句子打分：句子与 query 的 token 重叠度，取 top-N 拼成回答。"""
    qset = set(tokenize(query))
    # 先保护脱敏 IP 中的 [.]，避免按小数点切句
    protected = card["body"].replace("[.]", "")
    sents = [s.strip() for s in SENT_SPLIT.split(protected) if s.strip()]
    sents = [s.replace("", "[.]") for s in sents]
    if not qset or not sents:
        return sents[0] if sents else card["body"][:220]
    scored = []
    for s in sents:
        st = set(tokenize(s))
        overlap = len(qset & st)
        kw_hit = sum(1 for k in card["keywords"].split() if k in s)
        scored.append((overlap + kw_hit, len(s), s))
    scored.sort(key=lambda x: (-x[0], x[1]))
    if scored[0][0] == 0:
        # 完全无重叠：退化为取前 max_sentences 句
        return "".join(sents[:max_sentences])
    return "".join(s for _, _, s in scored[:max_sentences])


def answer(query, top_k=2):
    ql = query.lower()
    ranked = _RETRIEVER.score(query)
    boosted = []
    for s, i in ranked:
        bonus = 0.0
        for kw in CARDS[i]["keywords"].split():
            if kw and kw in ql:
                bonus += 6.0
        boosted.append((s, bonus, i))
    boosted.sort(key=lambda t: (t[0] + t[1], t[0]), reverse=True)
    # 如实性兜底：最高分的卡片若既无关键词命中、原始分又很低，
    # 且 top_k 内也没有任何关键词命中的卡片，则判为无相关内容
    best_raw, best_bonus, _ = boosted[0]
    kw_hits = [t for t in boosted[:top_k] if t[1] > 0]
    if best_bonus == 0 and best_raw < 10.0 and not kw_hits:
        return None, []
    pool = kw_hits if (best_bonus == 0 and best_raw < 10.0) else boosted[:top_k]
    hits = [(s + b, CARDS[i]) for s, b, i in pool if s + b > 0]
    if not hits:
        return None, []
    best_score, best = hits[0]
    text = extract_answer(best, query)
    refs = [(c["id"], c["title"]) for _, c in hits]
    return {"title": best["title"], "answer": text,
            "score": round(best_score, 3)}, refs


# ------------------------------------------------------------------- CLI -----
def cmd_demo():
    queries = [
        "SafePay 是什么？通告编号是多少",
        "SafePay 是怎么入侵的",
        "发现被勒索加密，第一个小时该做什么",
        "备份被删了怎么办，NAS 还能信吗",
        "要不要付赎金",
        "攻击者打电话施压怎么应对",
        "VPN 怎么加固才能防住这类团伙",
    ]
    for q in queries:
        print("=" * 64)
        print("提问：%s" % q)
        res, refs = answer(q)
        if res is None:
            print("知识库里没有相关内容，换个问法试试～")
            continue
        print("命中卡片：%s（BM25=%.3f）" % (res["title"], res["score"]))
        print("回答：%s" % res["answer"])
        print("引用：%s" % "；".join("%s %s" % r for r in refs))
    print("=" * 64)


def cmd_repl():
    print("RansomQA 交互模式（输入 q 退出）。"
          "知识库：AA26-293A SafePay 情报 + 勒索应急 Playbook，共 %d 张卡片。"
          % len(CARDS))
    while True:
        try:
            q = input("\n你想问什么？> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n下次见～")
            break
        if q.lower() in ("q", "quit", "exit"):
            print("下次见～")
            break
        if not q:
            continue
        res, refs = answer(q)
        if res is None:
            print("知识库里没有相关内容，换个问法试试～")
            continue
        print("%s（BM25=%.3f）" % (res["title"], res["score"]))
        print("%s" % res["answer"])
        print("引用：%s" % "；".join("%s %s" % r for r in refs))


def main(argv=None):
    ap = argparse.ArgumentParser(description="RansomQA: 勒索软件应急响应离线问答")
    ap.add_argument("--query", "-q", help="单次提问")
    ap.add_argument("--demo", action="store_true", help="演示模式：跑一组示例问题")
    ap.add_argument("--list", action="store_true", help="列出全部知识卡片")
    args = ap.parse_args(argv)

    if args.demo:
        return cmd_demo()
    if args.list:
        for c in CARDS:
            print("%-18s %s" % (c["id"], c["title"]))
        return
    if args.query:
        res, refs = answer(args.query)
        if res is None:
            print("知识库里没有相关内容，换个问法试试。")
            return
        print("【%s】(BM25=%.3f)" % (res["title"], res["score"]))
        print(res["answer"])
        print("引用：" + "；".join("%s %s" % r for r in refs))
        return
    return cmd_repl()


if __name__ == "__main__":
    sys.exit(main() or 0)
