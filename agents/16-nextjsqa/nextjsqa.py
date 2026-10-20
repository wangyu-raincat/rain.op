#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NextJS-QA（16-nextjsqa）：Next.js 2026-10-14 双 RCE 沦陷速查。纯标准库。"""
import argparse
import math
import re

# ---------------------------------------------------------------- 数据 ----
DISCLOSURE = "2026-10-14"
FIX_16 = (16, 4, 1)
FIX_15 = (15, 5, 28)
SHARP_FIX = (0, 35, 5)

KB = [
    {
        "id": "VULN-1",
        "title": "漏洞卡①：GHSA-673q-mjm6-r5xr（use cache typed array RCE）",
        "body": "【Critical · CVSS 9.5】App Router + 开启 Cache Components 时，`use cache` 函数\n"
                "返回多个 typed array（Uint8Array、Float64Array、Int32Array 等）→ 未授权远程代码执行。\n"
                "根源在 React Server Components 序列化层（CWE-20 输入校验不当）；\n"
                "React 上游也有对应公告 GHSA-xqc2-xf4c-x3h3（react-server-dom-webpack / parcel /\n"
                "turbopack 的 19.0.0–19.3.0，修复版 19.0.9 / 19.1.10 / 19.2.9 / 19.3.1）。\n"
                "影响：Next.js 16.0.0–16.4.0（16.x 专属，use cache 是 16 新特性）。\n"
                "修复：升级到 16.4.1。★ 无 workaround —— 官方原话：\n"
                "“没有已知的缓解措施，即使你的应用没有这类函数也应立即升级。”",
    },
    {
        "id": "VULN-2",
        "title": "漏洞卡②：CVE-2026-96889 / GHSA-2464-fhr4-w9xw（SVG 图片优化 RCE）",
        "body": "【Critical · CVSS 9.5】librsvg 的 use-after-free（CWE-416），Next.js 通过 bundled\n"
                "sharp 间接调用它。Image Optimization API（或 next/og 图片生成）处理攻击者\n"
                "可控的 SVG（嵌套 XInclude + 重复实体声明）→ 在 glibc 系 Linux（常见 Debian/\n"
                "Ubuntu 容器）上可转成远程代码执行。无需登录、无需用户交互。\n"
                "影响：Next.js 10.0.0–15.5.27 和 16.0.0–16.4.0（本批范围最广的一条）。\n"
                "修复：15.5.28（要求 sharp ≥ 0.35.5）/ 16.4.1。★ 唯一 workaround：\n"
                "把 Next.js 实际使用的 sharp 升级到 0.35.5+（只解这条，不解另外两条）。\n"
                "注意：sharp 只做缓解过渡，最终还是要升 Next.js。",
    },
    {
        "id": "VULN-3",
        "title": "漏洞卡③：GHSA-p3m5-59mp-jv5r（Server Actions DoS）",
        "body": "【High · CVSS 8.2】App Router 应用只要有一个 Server Action，攻击者用精心构造\n"
                "的请求就能把单个 server 进程的 CPU 吃满，阻塞该进程的其它请求（进程级 DoS）。\n"
                "影响：Next.js 13.0.0–15.5.27 和 16.0.0–16.4.0。\n"
                "Pages Router 应用、以及没有任何 Server Action 的应用不受影响。\n"
                "修复：升级到 15.5.28 / 16.4.1。★ 无 workaround。",
    },
    {
        "id": "VERSIONS",
        "title": "版本边界表与升级路径",
        "body": "三条漏洞的受影响版本边界（以 GHSA 官方为准，2026-10-14 披露）：\n"
                "VULN-1 use cache RCE : 16.0.0 – 16.4.0              → 修 16.4.1\n"
                "VULN-2 SVG RCE       : 10.0.0 – 15.5.27 / 16.0.0 – 16.4.0 → 修 15.5.28 / 16.4.1\n"
                "VULN-3 Server DoS    : 13.0.0 – 15.5.27 / 16.0.0 – 16.4.0 → 修 15.5.28 / 16.4.1\n"
                "升级路径（同线就近修，跨线看条件）：\n"
                "· 16.0.0–16.4.0 → npm install next@16.4.1（一条修三处）；\n"
                "· 15.0.0–15.5.27 → npm install next@15.5.28，再确认 sharp ≥ 0.35.5；\n"
                "· 13.x–14.x（受 VULN-2/VULN-3 影响）→ 跳线升 15.5.28 或 16.4.1；\n"
                "· 10.x–12.x（受 VULN-2 影响）→ 跳线升 15.5.28 或 16.4.1；\n"
                "· 早于 10.0.0 → 官方已无修复线，直接跳线升 15.5.28 / 16.4.1；\n"
                "· 已在 15.5.28+ / 16.4.1+ → 本批三洞都不中，只需确认 sharp ≥ 0.35.5。",
    },
    {
        "id": "SHARP",
        "title": "sharp 自查要点",
        "body": "VULN-2 的关键不在 next 版本号本身，而在「实际跑起来的 sharp 版本」。\n"
                "① 查：npm ls sharp（看实际解析到的版本；yarn/npm overrides 可能锁死旧版）；\n"
                "② 线：< 0.35.5 受影响（librsvg 旧版带 use-after-free），≥ 0.35.5 安全；\n"
                "③ 条件：只有 glibc 系 Linux（Debian/Ubuntu 容器、多数 Docker 部署）能被打成 RCE，\n"
                "   Alpine（musl）/ macOS / Windows 的利用条件不同，但照样该升；\n"
                "④ 场景：攻击者可控 SVG 进入 Image Optimization（_next/image）、或 next/og 的\n"
                "   ImageResponse 都算触发面；默认不开 dangerouslyAllowSVG 也不代表 next/og 没面；\n"
                "⑤ sharp 只覆盖 VULN-2，VULN-1/VULN-3 必须靠升 Next.js——别被「sharp 升了」麻痹。",
    },
    {
        "id": "CHECKLIST",
        "title": "自查清单（我有没有中招）",
        "body": "① 查版本：package.json / package-lock.json 里的 next 版本，用 --version 判受影响范围；\n"
                "② 查 sharp：npm ls sharp，< 0.35.5 则 VULN-2 暴露；\n"
                "③ 查特性面：use cache 函数是否返回多个 typed array（16.x）；是否有 Server Action（13+ App Router）；\n"
                "   next.config 有没有 dangerouslyAllowSVG；有没有 next/og 的 ImageResponse 接口；\n"
                "④ 查日志：_next/image 接口的可疑 SVG 请求、Server Action 接口的 CPU 异常峰值、\n"
                "   进程的异常子进程/异常外联（RCE 落地后的通用迹象）；\n"
                "⑤ 结论：版本在受影响区间 = 已暴露（即使暂时没被利用迹象），先按 --fix 升级；\n"
                "   本批漏洞截至 2026-10-15 尚无公开在野利用报告，但双 RCE 无需登录——\n"
                "   「没被利用」不等于「不会被利用」，先补洞后找证据。",
    },
    {
        "id": "FIX",
        "title": "处置清单（升级 / 验证 / 依赖检查）",
        "body": "【升级】① 同线直升：npm install next@16.4.1（16.x）或 next@15.5.28（15.x）；\n"
                "② 旧线（≤14.x）跳线到 15.5.28 / 16.4.1，注意先看 breaking changes；\n"
                "③ 依赖检查：npm ls sharp 确认 ≥ 0.35.5；16.x 顺带确认 react-server-dom-* ≥ 19.0.9/19.1.10/19.2.9/19.3.1；\n"
                "【验证】④ 升级后重新构建部署，staging 先跑冒烟（图片优化、Server Action 核心链路）；\n"
                "⑤ 生产确认 next 版本与 sharp 版本（npm ls / 容器内 node -e）；\n"
                "⑥ 回看升级窗口前后的日志：异常 SVG 请求、Server Action CPU 峰值、异常子进程；\n"
                "【扫尾】⑦ 若升级前长期暴露在受影响版本，按 RCE 预案做一次完整性检查\n"
                "（异常文件、异常账号、异常外联）——补洞不等于已沦陷自动痊愈；\n"
                "⑧ 把 sharp/next 版本钉进 CI 检查（npm ls 断言），下次别靠人肉。",
    },
    {
        "id": "INTEL",
        "title": "在野状态（检测先行窗口）",
        "body": "· 披露时间：2026-10-14（Vercel out-of-band 安全更新，含两个因上游依赖延迟\n"
                "  而从 9 月推迟的修复）。\n"
                "· 截至 2026-10-15：尚无公开的在野利用报告，也没有公开 PoC —— \n"
                "  现在正是「检测先行」窗口：先把版本边界和 sharp 检查铺好，等利用出现时不抓瞎。\n"
                "· 双 RCE 均为 CVSS 9.5、未授权可达：窗口一旦关闭，利用门槛极低。\n"
                "· 优先级排序：16.x 先看 VULN-1（无 workaround）；全线看 VULN-2（面最广，\n"
                "  默认 Docker 部署基本都在 glibc 上）；App Router 看 VULN-3（DoS 易被忽视）。",
    },
]

CVE_RE = re.compile(r"(CVE-\d{4}-\d+|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})", re.IGNORECASE)
VER_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")


# ---------------------------------------------------------------- BM25 ----
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
            s, dl = 0.0, len(d)
            for t in qt:
                f = d.count(t)
                if f and t in self.idf:
                    s += self.idf[t] * f * (self.k1 + 1) / (f + self.k1 * (1 - self.b + self.b * dl / self.avgdl))
            out.append(s)
        return out


def doc_text(e):
    return e["id"] + " " + e["title"] + " " + e["body"]


RETRIEVER = BM25([doc_text(e) for e in KB])
BY_ID = {e["id"]: e for e in KB}


def show_card(e, score=None):
    print("-" * 60)
    print("## " + e["title"])
    print(e["body"])
    if score is not None:
        print("（检索得分 %.2f）" % score)
    print()


# ------------------------------------------------------------ 版本判定 ----
def parse_version(text):
    m = VER_RE.search(text or "")
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def vstr(v):
    return "%d.%d.%d" % v


def in_range(v, lo, hi):
    return lo <= v <= hi


def fix_for(v):
    """同线修复版本；未知线返回 None。"""
    if v[0] == 16:
        return FIX_16
    if v[0] in (10, 11, 12, 13, 14, 15):
        return FIX_15
    return None


def assess(version):
    v = parse_version(version)
    if v is None:
        return None, "没解析到版本号，请用 --version 15.5.20 这样的格式。"
    results = []
    results.append(("VULN-1", "GHSA-673q-mjm6-r5xr · use cache typed array RCE · Critical 9.5",
                    in_range(v, (16, 0, 0), (16, 4, 0))))
    results.append(("VULN-2", "CVE-2026-96889 · SVG 图片优化 RCE · Critical 9.5",
                    in_range(v, (10, 0, 0), (15, 5, 27)) or in_range(v, (16, 0, 0), (16, 4, 0))))
    results.append(("VULN-3", "GHSA-p3m5-59mp-jv5r · Server Actions DoS · High 8.2",
                    in_range(v, (13, 0, 0), (15, 5, 27)) or in_range(v, (16, 0, 0), (16, 4, 0))))
    return v, results


def cmd_version(args):
    v, res = assess(args.version)
    if v is None:
        print("?? " + res)
        return
    print("=" * 60)
    print("Next.js %s 受影响判定（披露 %s）" % (vstr(v), DISCLOSURE))
    print("=" * 60)
    hit = False
    for vid, name, affected in res:
        mark = "!! 中招" if affected else "++ 未命中"
        print("[%s] %s" % (mark, name))
        if affected:
            hit = True
            print("      -> 详情：--ask %s" % vid)
    print()
    fix = fix_for(v)
    if hit and fix:
        print(">> 升级路径：npm install next@%s" % vstr(fix))
        if any(r[0] == "VULN-2" and r[2] for r in res):
            print(">> VULN-2 必查 sharp：npm ls sharp，要求 >= %s" % vstr(SHARP_FIX))
    elif hit:
        print(">> 该版本线已无官方修复版本：直接跳线升 15.5.28 / 16.4.1（先看 breaking changes）。")
    else:
        if v >= FIX_16 or (v[0] == 15 and v >= FIX_15):
            print(">> 本批三洞都不中：保持更新即可。")
        else:
            print(">> 版本过旧（< 10.0.0）：本批三洞的官方修复线已不覆盖，建议跳线升 15.5.28 / 16.4.1。")
    if args.sharp:
        sv = parse_version(args.sharp)
        if sv and sv < SHARP_FIX:
            print(">> !! sharp %s < %s：VULN-2 仍暴露，先升 sharp。" % (vstr(sv), vstr(SHARP_FIX)))
        elif sv:
            print(">> sharp %s >= %s：VULN-2 的 sharp 侧已封堵。" % (vstr(sv), vstr(SHARP_FIX)))
    elif hit:
        print(">> 提示：加上 --sharp <版本>（npm ls sharp 的结果）可同时判定 sharp 侧。")
    print()
    if hit:
        print(">> 完整处置清单：\n")
        show_card(BY_ID["FIX"])


def cmd_ask(query):
    m = CVE_RE.search(query or "")
    if m:
        key = m.group(0).upper()
        mapping = {"GHSA-673Q-MJM6-R5XR": "VULN-1", "CVE-2026-96889": "VULN-2",
                   "GHSA-2464-FHR4-W9XW": "VULN-2", "GHSA-P3M5-59MP-JV5R": "VULN-3"}
        if key in mapping:
            print(">> 编号精确命中：\n")
            show_card(BY_ID[mapping[key]])
            return
    scores = RETRIEVER.score(query or "")
    ranked = sorted(range(len(KB)), key=lambda i: scores[i], reverse=True)
    hits = [(KB[i], scores[i]) for i in ranked if scores[i] > 0][:3]
    if not hits:
        print("没找到相关内容。试试：--version <版本号>、--check（自查）、--fix（处置）。")
        return
    print(">> 检索结果（按相关度）：\n")
    for e, s in hits:
        show_card(e, s)


def cmd_check():
    print(">> 自查清单：\n")
    show_card(BY_ID["CHECKLIST"])
    print(">> sharp 专项：\n")
    show_card(BY_ID["SHARP"])


def cmd_fix():
    print(">> 处置清单：\n")
    show_card(BY_ID["FIX"])
    print(">> 在野状态参考：\n")
    show_card(BY_ID["INTEL"])


def cmd_demo():
    print("### 演示 1：16.4.0（全中）+ sharp 0.35.4\n")
    cmd_version(argparse.Namespace(version="16.4.0", sharp="0.35.4"))
    print("### 演示 2：15.5.28（本批干净）\n")
    cmd_version(argparse.Namespace(version="15.5.28", sharp=None))
    print("### 演示 3：14.2.35（SVG RCE + Server DoS）\n")
    cmd_version(argparse.Namespace(version="14.2.35", sharp=None))
    print("### 演示 4：自然语言提问\n")
    cmd_ask("sharp 多少版本才安全")


def main():
    ap = argparse.ArgumentParser(description="NextJS-QA：Next.js 双 RCE 沦陷速查（2026-10-14 披露）")
    ap.add_argument("--version", help="判定 Next.js 版本是否受影响，如 15.5.20")
    ap.add_argument("--sharp", help="一并判定 sharp 版本，如 0.34.2（npm ls sharp）")
    ap.add_argument("--ask", help="按编号或自然语言提问")
    ap.add_argument("--check", action="store_true", help="自查清单")
    ap.add_argument("--fix", action="store_true", help="处置清单")
    ap.add_argument("--demo", action="store_true", help="离线演示")
    args = ap.parse_args()
    if args.demo:
        cmd_demo()
    elif args.version:
        cmd_version(args)
    elif args.ask:
        cmd_ask(args.ask)
    elif args.check:
        cmd_check()
    elif args.fix:
        cmd_fix()
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
