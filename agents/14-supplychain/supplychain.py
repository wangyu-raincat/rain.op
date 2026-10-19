#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SupplyChain-QA（14-supplychain）：供应链投毒事件速查助手。纯标准库。"""
import argparse
import math
import re
from datetime import datetime, timedelta, timezone

POISON_START = datetime(2026, 10, 15, 20, 2, tzinfo=timezone.utc)
POISON_END = datetime(2026, 10, 16, 7, 12, tzinfo=timezone.utc)
POISONED_VERSION = (3, 0, 123)
CLEAN_VERSION = (3, 0, 124)
WINDOW_TXT = "2026-10-15 20:02 → 2026-10-16 07:12（UTC）"

KB = [
    {
                "id": "INCIDENT",
                "title": "事件卡：Rank Math SEO PRO 供应链投毒",
                "body": "\n"
                                "Rank Math SEO PRO 3.0.123 的部分分发包被植入恶意代码（供应链投毒）。\n"
                                "投毒窗口（UTC）：2026-10-15 20:02 → 2026-10-16 07:12。\n"
                                "窗口内下载/更新到 3.0.123 → 视为沦陷；窗口外下载的不算沦陷；干净版本 3.0.124。\n"
                                "后门行为：C2 域名 rank1cdn[.]com；页面访问时重建隐藏 PHP 后门；\n"
                                "建未授权管理员账号；伪造 WP core 文件；投放可执行.cache 文件；\n"
                                "注册系统 cron 标记；窃取 WP 凭证、数据库密码、API keys；3 个恶意 wp_options 键。\n"
                                "信源：securityonline.info（2026-10-17）、Wordfence 报告、厂商公告。",
    },
    {
                "id": "IOC",
                "title": "沦陷指示器（IOCs）",
                "body": "命中任意一条即按沦陷处理：\n"
                                "1) 外联 C2：日志里搜 rank1cdn，有连接记录 = 实锤；\n"
                                "2) 隐藏 PHP 后门：插件/上传目录的异常 PHP，页面访问时被重建；\n"
                                "3) 未授权管理员账号：wp_users 里不认识的 administrator；\n"
                                "4) 伪造 WP core 文件：wp-admin/wp-includes 哈希与官方包不一致；\n"
                                "5) 可执行.cache 文件：上传/缓存目录带执行权限的.cache；\n"
                                "6) 系统 cron 标记：crontab / WP-Cron 未知定时任务；\n"
                                "7) 3 个恶意 wp_options 数据库键（对照厂商公告键名逐一查）；\n"
                                "8) 凭证外泄迹象：数据库密码、API keys 被异常使用。",
    },
    {
                "id": "CHECKLIST",
                "title": "自查清单（我是不是中招了）",
                "body": "① 查时间：3.0.123 的下载/更新时间（UTC），用 --triage 对照投毒窗口；\n"
                                "② 查外联：服务器/防火墙日志搜 rank1cdn；\n"
                                "③ 查账号：wp_users 管理员逐个认领，陌生账号先禁用；\n"
                                "④ 查文件：插件目录与 uploads 下异常 PHP 和可执行.cache；\n"
                                "⑤ 查数据库：wp_options 按公告的 3 个恶意键名精确匹配；\n"
                                "⑥ 查 cron：crontab -l 与 WP-Cron 未知任务；\n"
                                "⑦ 哈希比对：wp-admin、wp-includes 与官方包 diff。\n"
                                "结论：时间在窗口内 OR 命中任一 IOC → 视为沦陷，走 --fix。",
    },
    {
                "id": "REMEDIATE",
                "title": "处置链（已沦陷 / 疑似沦陷）",
                "body": "厂商定调：按「整站沦陷」做 forensic triage，光打补丁不够。\n"
                                "① 断网隔离，保留日志/数据库快照取证；\n"
                                "② 立即升级到干净版本 3.0.124（只走官方更新渠道）；\n"
                                "③ 清除：删隐藏后门 PHP、可执行.cache、未知 cron、陌生管理员账号；\n"
                                "④ 删 3 个恶意 wp_options 键；官方包哈希还原被伪造的 core 文件；\n"
                                "⑤ 轮换全部凭证：数据库密码、WP 管理员密码、所有 API keys、云密钥\n"
                                " （后门会窃取凭证，不换等于白修）；\n"
                                "⑥ 审计凭证外泄窗口内的异常操作（异常登录、异常 API 调用、账单）；\n"
                                "⑦ 全站复查干净后重新上线；复盘更新流程，见 --prevent。",
    },
    {
                "id": "DEFENSE-1",
                "title": "防护：签名/哈希校验",
                "body": "【防下一次·供应链投毒预防】· 优先选带签名发布的组件（GPG/代码签名），安装前验签；\n"
                                "· 无签名的比对官方 SHA-256，哈希对不上就不装；\n"
                                "· 把「校验通过」写进部署脚本，人工肉眼比对等于没比对。",
    },
    {
                "id": "DEFENSE-2",
                "title": "防护：只走官方更新渠道",
                "body": "【防下一次·供应链投毒预防】· 插件/依赖只从官方仓库、官方 CDN 更新，禁用第三方镜像源自动更新；\n"
                                "· 锁死更新源域名白名单，记录每次拉包的 URL+哈希；\n"
                                "· 警惕「官方渠道之外的紧急补丁包」——投毒常用钓鱼话术。",
    },
    {
                "id": "DEFENSE-3",
                "title": "防护：版本冻结与灰度",
                "body": "【防下一次·供应链投毒预防】· 生产版本冻结：新版本先在 staging 跑 24–72 小时；\n"
                                "· 灰度发布：先 1 台/1 站点，观察无异常再全量；\n"
                                "· 本次窗口仅 11 小时——灰度 + 延迟更新就是天然缓冲带。",
    },
    {
                "id": "DEFENSE-4",
                "title": "防护：更新后冒烟检查",
                "body": "【防下一次·供应链投毒预防】每次更新后自动跑冒烟检查：核心目录哈希 diff、管理员列表快照比对、\n"
                                "更新后 1 小时 DNS 日志看新未知域名、cron 快照比对。\n"
                                "任一异常 → 回滚 + 按事件响应流程走。",
    },
]

CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


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
                self.idf = {}
                for t, c in df.items():
                                self.idf[t] = math.log(1 + (self.N - c + 0.5) / (c + 0.5))
    def score(self, query):
                qt = tokenize(query)
                out = []
                for d in self.docs:
                                s = 0.0
                                dl = len(d)
                                for t in qt:
                                                f = d.count(t)
                                                if f and t in self.idf:
                                                                s += self.idf[t] * f * (self.k1 + 1) / (f + self.k1 * (1 - self.b + self.b * dl / self.avgdl))
                                out.append(s)
                return out


def doc_text(e):
    return e["id"] + " " + e["title"] + " " + e["body"]


RETRIEVER = BM25([doc_text(e) for e in KB])
BY_ID = {}
for e in KB:
    BY_ID[e["id"]] = e


def show_card(e, score=None):
    line = "-" * 60
    print(line)
    print("## " + e["title"])
    print(e["body"])
    if score is not None:
                print("（检索得分 %.2f）" % score)
    print(line)


def by_cve(query):
    m = CVE_RE.search(query)
    if m and m.group(0).upper() == "CVE-2026-111862":
                return BY_ID["INCIDENT"]
    return None


TS_RE = re.compile(r"(\d{4}-\d{2}-\d{2})[\sT](\d{2}:\d{2})(?::(\d{2}))?\s*(Z|UTC|\+08:00|\+0800|北京时间)?", re.IGNORECASE)
VER_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")


def parse_ts(text):
    """解析下载/更新时间，返回 UTC 感知的 datetime；失败返回 None。"""
    m = TS_RE.search(text or "")
    if not m:
                return None
    date, hm, sec, tz = m.group(1), m.group(2), m.group(3) or "00", m.group(4)
    dt = datetime.strptime("%s %s:%s" % (date, hm, sec), "%Y-%m-%d %H:%M:%S")
    if tz and (tz == "北京时间" or tz.replace(":", "") == "+0800"):
                dt = dt - timedelta(hours=8)
    return dt.replace(tzinfo=timezone.utc)


def parse_version(text):
    m = VER_RE.search(text or "")
    if not m:
                return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def verdict(version, ts):
    """返回 (结论, 解释)。结论 ∈ COMPROMISED / NOT_AFFECTED / UNKNOWN。"""
    v = parse_version(version)
    if v is None:
                return ("UNKNOWN", "没解析到版本号（如 3.0.123），请用 --triage \"2026-10-16 03:00\" --version 3.0.123 的格式。")
    if v >= CLEAN_VERSION:
                return ("NOT_AFFECTED", "版本 %s ≥ 干净版本 3.0.124，本次投毒事件未命中。" % version)
    if v < POISONED_VERSION:
                return ("NOT_AFFECTED", "版本 %s 早于被投毒的 3.0.123，本次事件未命中（仍建议升到 3.0.124）。" % version)
    t = parse_ts(ts)
    if t is None:
                return ("UNKNOWN",
                                "版本是 3.0.123，但没给出可解析的下载/更新时间。\n"
                                "请补上时间再研判（如 --triage \"2026-10-16 03:00Z\"），\n"
                                "或直接按 CHECKLIST 卡做 IOC 自查——命中任一条即按沦陷处理。")
    stamp = t.strftime("%Y-%m-%d %H:%M")
    if POISON_START <= t <= POISON_END:
                return ("COMPROMISED",
                                "版本 3.0.123 且下载/更新时间 %s（UTC）落在投毒窗口\n%s内 → 视为沦陷。\n"
                                "立即走 REMEDIATE 处置链：升 3.0.124 + 清后门 + 轮换全部凭证。" % (stamp, WINDOW_TXT))
    return ("NOT_AFFECTED",
                "版本 3.0.123，但下载/更新时间 %s（UTC）在投毒窗口之外 → 本次事件未命中。\n"
                "仍建议升到 3.0.124，并顺手跑一遍 CHECKLIST 自查。" % stamp)


def label_of(v):
    return {"COMPROMISED": "视为沦陷", "NOT_AFFECTED": "本次事件未命中", "UNKNOWN": "信息不足"}[v]


def cmd_triage(args):
    v, expl = verdict(args.version, args.triage)
    banner = {"COMPROMISED": "!! 研判结论：视为沦陷",
                                "NOT_AFFECTED": "++ 研判结论：本次事件未命中",
                                "UNKNOWN": "?? 研判结论：信息不足，需补充"}[v]
    print("=" * 60)
    print(banner)
    print("=" * 60)
    print(expl)
    print()
    if v == "COMPROMISED":
                print(">> 完整处置链：\n")
                show_card(BY_ID["IOC"])
                show_card(BY_ID["CHECKLIST"])
                show_card(BY_ID["REMEDIATE"])
    elif v == "UNKNOWN":
                print(">> 先做自查：\n")
                show_card(BY_ID["CHECKLIST"])


def cmd_ask(query):
    e = by_cve(query)
    if e:
                print(">> 编号精确命中：\n")
                show_card(e)
                return
    scores = RETRIEVER.score(query)
    ranked = sorted(range(len(KB)), key=lambda i: scores[i], reverse=True)
    hits = []
    for i in ranked:
                if scores[i] > 0 and len(hits) < 3:
                                hits.append((KB[i], scores[i]))
    if not hits:
                print("没找到相关内容。试试：--triage（研判）、--check（自查）、--fix（处置）、--prevent（防护）。")
                return
    print(">> 检索结果（按相关度）：\n")
    for e, s in hits:
                show_card(e, s)


def cmd_check():
    print(">> 沦陷指示器 + 自查清单：\n")
    show_card(BY_ID["IOC"])
    show_card(BY_ID["CHECKLIST"])


def cmd_fix():
    print(">> 处置链（按整站沦陷处理）：\n")
    show_card(BY_ID["REMEDIATE"])


def cmd_prevent():
    print(">> 供应链防护四条：\n")
    for cid in ("DEFENSE-1", "DEFENSE-2", "DEFENSE-3", "DEFENSE-4"):
                show_card(BY_ID[cid])


def cmd_demo():
    print("=" * 60)
    print("** SupplyChain-QA 离线演示 **")
    print(" 案例：CVE-2026-111862｜Rank Math SEO PRO 3.0.123 供应链投毒")
    print(" 投毒窗口（UTC）：2026-10-15 20:02 → 2026-10-16 07:12")
    print("=" * 60)
    print("\n[演示 1] 窗口内更新到 3.0.123 → 判沦陷\n")
    v, expl = verdict("3.0.123", "2026-10-16 03:00Z")
    print(("!! " if v == "COMPROMISED" else "++ ") + "研判结论：" + label_of(v))
    print(expl)
    print("\n[演示 2] 窗口外下载的 3.0.123 → 未命中\n")
    v, expl = verdict("3.0.123", "2026-10-14 10:00Z")
    print(("!! " if v == "COMPROMISED" else "++ ") + "研判结论：" + label_of(v))
    print(expl)
    print("\n[演示 3] 自然语言提问：「密钥要换哪些」\n")
    scores = RETRIEVER.score("密钥要换哪些 凭证轮换")
    best = 0
    for i in range(len(KB)):
                if scores[i] > scores[best]:
                                best = i
    show_card(KB[best], scores[best])
    print("\n[演示 4] 自然语言提问：「怎么防下一次」\n")
    scores = RETRIEVER.score("怎么防下一次 供应链防护")
    best = 0
    for i in range(len(KB)):
                if scores[i] > scores[best]:
                                best = i
    show_card(KB[best], scores[best])
    print("\nOK 演示结束。试试：")
    print(" python supplychain.py --triage \"2026-10-16 03:00Z\" --version 3.0.123")
    print(" python supplychain.py --check / --fix / --prevent")
    print(" python supplychain.py \"我是不是中招了\"")


def main(argv=None):
    ap = argparse.ArgumentParser(description="SupplyChain-QA：供应链投毒事件速查（纯标准库）")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--triage", metavar="TIME", help="研判：3.0.123 的下载/更新时间")
    g.add_argument("--check", action="store_true", help="自查：沦陷指示器 + 自查清单")
    g.add_argument("--fix", action="store_true", help="处置：完整处置链")
    g.add_argument("--prevent", action="store_true", help="防护：供应链防护四条")
    g.add_argument("--demo", action="store_true", help="离线演示")
    ap.add_argument("--version", default="", help="配合 --triage：当前插件版本，如 3.0.123")
    ap.add_argument("query", nargs="?", default="", help="自然语言提问，或 CVE 编号")
    args = ap.parse_args(argv)
    if args.demo:
                return cmd_demo()
    if args.triage:
                return cmd_triage(args)
    if args.check:
                return cmd_check()
    if args.fix:
                return cmd_fix()
    if args.prevent:
                return cmd_prevent()
    if not args.query:
                ap.print_help()
                return
    return cmd_ask(args.query)


if __name__ == "__main__":
    main()
