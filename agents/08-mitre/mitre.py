#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MITRE-QA 🎯 MITRE ATT&CK 战术技战术离线问答小助手

用 BM25 检索内置的 18 条真实 ATT&CK 技术知识库，回答
"这是什么攻击手法、属于哪个战术、怎么检测/缓解"，输出战术卡片。
纯 Python 标准库，离线可运行，不依赖任何外部 API。

用法:
    python mitre.py --demo            演示模式：自动回答 4 个示例问题
    python mitre.py "勒索软件常用哪些手法"
    python mitre.py --id T1059        按 ATT&CK 编号精确查询
    python mitre.py --list            列出知识库全部技术
"""

import math
import re
import sys
from collections import Counter

# ---------------------------------------------------------------- 知识库
# 18 条真实 MITRE ATT&CK 技术（Enterprise, v13 起编号体系稳定）
KB = [
    dict(id="T1566", name="Phishing / 钓鱼攻击",
         tactic="初始访问", platform="全部",
         desc="攻击者通过钓鱼邮件、链接或附件引诱用户执行恶意操作，是勒索软件与 APT 最常见的初始入口。",
         detect="邮件网关告警、附件沙箱行为、用户上报可疑邮件；关注发件人域名仿冒。",
         mitigate="邮件过滤与附件沙箱、钓鱼演练、关闭宏与危险附件类型。",
         keys="钓鱼 邮件 附件 链接 社会工程 phishing email"),
    dict(id="T1190", name="Exploit Public-Facing Application / 利用面向公网的应用",
         tactic="初始访问", platform="Linux/Windows/网络设备",
         desc="直接利用暴露在互联网的应用漏洞（如 Log4Shell、ProxyLogon）获得初始立足点，无需用户交互。",
         detect="WAF 拦截日志、应用异常进程拉起、公网应用漏洞扫描命中。",
         mitigate="公网资产收敛、漏洞 48 小时内修复、WAF 虚拟补丁。",
         keys="漏洞利用 公网 应用 rce exploit web"),
    dict(id="T1078", name="Valid Accounts / 有效账户",
         tactic="初始访问/持久化", platform="全部",
         desc="使用窃取或购买的合法账号登录，绕过大部分基于签名的检测，是内网横向移动的常用跳板。",
         detect="异地/非常用时间登录、同一账号多地并发、登录后异常行为基线偏离。",
         mitigate="多因素认证、弱口令治理、特权账号定期轮换、登录行为基线。",
         keys="账号 密码 登录 横向 valid account credential"),
    dict(id="T1059", name="Command and Scripting Interpreter / 命令与脚本解释器",
         tactic="执行", platform="全部",
         desc="滥用 PowerShell、cmd、bash、Python 等系统自带解释器执行恶意命令，是\"无文件攻击\"的核心。",
         detect="PowerShell Script Block Logging、命令行全量审计、父进程异常（如 winword 拉起 powershell）。",
         mitigate="Constrained Language Mode、禁用未用解释器、脚本签名策略。",
         keys="powershell cmd 脚本 命令 无文件 command script"),
    dict(id="T1053", name="Scheduled Task/Job / 计划任务",
         tactic="执行/持久化", platform="Windows/Linux/macOS",
         desc="创建计划任务或 cron 实现定时执行与开机自启，隐蔽且重启后依然有效。",
         detect="计划任务创建事件（EventID 4698）、cron 文件变更、任务指向可疑路径。",
         mitigate="任务创建审批、最小权限、EDR 拦截可疑任务注册。",
         keys="计划任务 cron 定时 自启 scheduled task"),
    dict(id="T1105", name="Ingress Tool Transfer / 工具传入",
         tactic="命令与控制", platform="全部",
         desc="从外部下载攻击工具到受害主机（certutil、curl、wget、bitsadmin），是投递载荷的经典手法。",
         detect="上述 LOLBins 的网络外联行为、下载后文件落地告警。",
         mitigate="LOLBins 使用管控、 egress 白名单、下载行为基线。",
         keys="下载 工具 certutil bitsadmin curl wget LOLBins"),
    dict(id="T1055", name="Process Injection / 进程注入",
         tactic="防御规避/提权", platform="Windows/Linux/macOS",
         desc="把恶意代码注入合法进程内存中执行，规避基于进程名的检测，常见于免杀载荷。",
         detect="EDR 内存扫描、CreateRemoteThread 等 API 调用链、可疑的内存权限（RWX）。",
         mitigate="EDR 行为拦截、内存完整性保护、应用白名单。",
         keys="注入 内存 免杀 injection shellcode"),
    dict(id="T1547", name="Boot or Logon Autostart Execution / 开机自启动",
         tactic="持久化", platform="Windows/Linux/macOS",
         desc="通过注册表 Run 键、启动文件夹、systemd 服务等实现登录/开机自动运行。",
         detect="自启动项变更监控（Sysmon/EDR）、注册表 Run 键审计。",
         mitigate="自启动项基线化、普通用户无写入权限、EDR 拦截未知自启动。",
         keys="自启动 注册表 开机 autostart persistence 注册表run"),
    dict(id="T1133", name="External Remote Services / 外部远程服务",
         tactic="持久化", platform="全部",
         desc="利用暴露的 RDP/SSH/VPN 等远程服务维持访问，常配合有效账户使用。",
         detect="远程服务非常用时间登录、爆破日志、VPN 异常接入。",
         mitigate="远程服务收敛到跳板机、MFA、爆破封禁、非必要端口关闭。",
         keys="rdp ssh vpn 远程 爆破 remote"),
    dict(id="T1003", name="OS Credential Dumping / 系统凭证转储",
         tactic="凭证访问", platform="Windows/Linux/macOS",
         desc="从内存或 SAM/LSASS 转储密码哈希（如 Mimikatz），是提权与横向的前提步骤。",
         detect="LSASS 内存访问告警、Mimikatz 特征、Credential Guard 状态。",
         mitigate="Credential Guard / LSA 保护、禁用 WDigest、最小权限。",
         keys="mimikatz 凭证 哈希 lsass 转储 dumping"),
    dict(id="T1027", name="Obfuscated Files or Information / 混淆",
         tactic="防御规避", platform="全部",
         desc="对载荷做编码、加密、打包混淆以躲避静态查杀，几乎所有现代恶意软件都会用。",
         detect="高熵文件落地、沙箱动态行为、解码后二次扫描。",
         mitigate="动态沙箱分析、行为检测为主、禁用可疑解码器。",
         keys="混淆 编码 加密 免杀 打包 obfuscation"),
    dict(id="T1070", name="Indicator Removal / 痕迹清除",
         tactic="防御规避", platform="全部",
         desc="删除日志、清空事件查看器、时间戳篡改（timestomp），破坏取证链条。",
         detect="日志服务异常停止、日志出现断档、关键日志被清空事件。",
         mitigate="日志外发到 SIEM/不可变存储、日志完整性监控。",
         keys="日志 删除 痕迹 timestomp 清除 anti-forensic"),
    dict(id="T1083", name="File and Directory Discovery / 文件目录发现",
         tactic="发现", platform="全部",
         desc="入侵后枚举文件系统寻找有价值目标，是\"踩点\"阶段的典型行为。",
         detect="短时间内大量目录遍历、敏感目录访问（财务/研发）。",
         mitigate="最小权限、敏感目录访问审计、蜜罐文件。",
         keys="枚举 发现 踩点 目录 discovery recon"),
    dict(id="T1021", name="Remote Services / 远程服务横向",
         tactic="横向移动", platform="全部",
         desc="用 SMB/WinRM/RDP/SSH 在内网主机间跳转，是内网渗透的主干手法。",
         detect="主机间异常横向连接图谱、WinRM/PSExec 使用告警。",
         mitigate="网段隔离、跳板机、横向流量 NDR 检测。",
         mitigate2="",
         keys="横向 smb winrm psexec 内网 lateral"),
    dict(id="T1071", name="Application Layer Protocol / 应用层协议 C2",
         tactic="命令与控制", platform="全部",
         desc="把 C2 流量伪装成 HTTP/HTTPS/DNS 等正常协议，混入业务流量躲避检测。",
         detect="长连接/心跳流量、JA3 指纹异常、DNS 隧道特征、代理日志分析。",
         mitigate="TLS 解密检测、DNS 安全网关、C2 情报封堵。",
         keys="c2 远控 隧道 http dns beacon 命令控制"),
    dict(id="T1048", name="Exfiltration Over Alternative Protocol / 替代协议渗出",
         tactic="渗出", platform="全部",
         desc="不用 C2 主通道，而用 FTP、DNS、ICMP 等替代协议把数据偷运出去。",
         detect="异常协议的大流量外发、DNS 查询量突增、DLP 告警。",
         mitigate="DLP、DNS 过滤、非业务协议出站封禁。",
         keys="渗出 数据泄露 dns 外发 exfiltration dLP"),
    dict(id="T1486", name="Data Encrypted for Impact / 加密勒索",
         tactic="影响", platform="全部",
         desc="勒索软件加密文件索要赎金，常配合双重勒索（先渗出再加密）。",
         detect="短时间内大量文件重命名/加密、勒索信落地、卷影副本删除。",
         mitigate="3-2-1 备份、卷影副本保护、EDR 勒索行为拦截、补丁与钓鱼防御前置。",
         keys="勒索 加密 ransomware 赎金"),
    dict(id="T1490", name="Inhibit System Recovery / 破坏系统恢复",
         tactic="影响", platform="Windows/Linux",
         desc="删除卷影副本、禁用恢复模式，让受害者无法自行恢复，放大勒索效果。",
         detect="vssadmin delete shadows、bcdedit 恢复项修改告警。",
         mitigate="备份离线化、卷影副本防删除策略、EDR 拦截相关命令。",
         keys="卷影副本 恢复 vss 勒索 recovery"),
]

for e in KB:
    e.pop("mitigate2", None)

# ---------------------------------------------------------------- 分词与 BM25
STOP = {"的", "了", "是", "在", "和", "与", "或", "如何", "怎么", "什么", "为什么",
        "哪些", "哪个", "这种", "那个", "以及", "被", "把", "对", "就", "而", "及",
        "并", "等", "有关", "漏洞", "高危", "修复", "攻击", "技术", "手法", "检测", "缓解"}

def tokenize(text):
    text = text.lower()
    toks = []
    toks += re.findall(r"[a-z0-9]+(?:[.\-][a-z0-9]+)*", text)   # 英文词/编号
    chs = re.findall(r"[\u4e00-\u9fff]", text)
    toks += [a + b for a, b in zip(chs, chs[1:])]                # 中文二元组
    return [t for t in toks if t not in STOP and len(t) > 1 or t.isdigit()]

def build_index(docs):
    df = Counter()
    doc_tf = []
    for d in docs:
        field = " ".join([d["id"], d["name"], d["tactic"], d["platform"],
                          d["desc"], d["detect"], d["mitigate"], d["keys"]])
        tf = Counter(tokenize(field))
        # id / name / keys 加权
        boost = Counter(tokenize(d["id"] + " " + d["name"] + " " + d["keys"]))
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

def find_by_id(tid):
    tid = tid.strip().upper()
    if not tid.startswith("T"):
        tid = "T" + tid
    for e in KB:
        if e["id"].upper() == tid:
            return e
    return None

def card(e):
    line = "─" * 46
    return (
        f"\n{line}\n"
        f"🎯 {e['id']} · {e['name']}\n"
        f"战术: {e['tactic']} ｜ 平台: {e['platform']}\n"
        f"{line}\n"
        f"📖 简介: {e['desc']}\n"
        f"🔍 检测: {e['detect']}\n"
        f"🛡️ 缓解: {e['mitigate']}\n"
    )

def answer(query):
    m = re.search(r"\bT\d{3,4}\b", query.upper())
    if m:
        e = find_by_id(m.group(0))
        if e:
            print(f"✅ 编号精确命中 {m.group(0)}")
            print(card(e))
            return
    hits = search(query)
    if not hits:
        print("😅 知识库里没找到相关技术，换个关键词试试（如: 钓鱼 / 横向 / 勒索 / powershell）。")
        return
    top, score = hits[0]
    print(f"🔎 检索到 {len(hits)} 条相关技术，最相关：")
    for e, s in hits:
        print(card(e))

def demo():
    print("=" * 50)
    print("🎯 MITRE-QA 演示：MITRE ATT&CK 战术技战术离线问答")
    print(f"   知识库: {len(KB)} 条真实 ATT&CK 技术 ｜ 检索: BM25 ｜ 依赖: 仅标准库")
    print("=" * 50)
    for q in [
        "勒索软件常用哪些攻击手法？",
        "内网横向移动一般用什么技术",
        "T1059 是什么",
        "钓鱼邮件进来之后攻击者还会做什么",
    ]:
        print(f"\n❓ 问: {q}")
        answer(q)
    print("\n✨ 演示结束。直接 `python mitre.py \"你的问题\"` 开始提问。")

def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
    elif argv[0] == "--demo":
        demo()
    elif argv[0] == "--list":
        for e in KB:
            print(f"{e['id']:6} {e['name']:28} [{e['tactic']}]")
    elif argv[0] == "--id" and len(argv) > 1:
        e = find_by_id(argv[1])
        print(card(e) if e else f"😅 没找到编号 {argv[1]}")
    else:
        answer(" ".join(argv))

if __name__ == "__main__":
    main(sys.argv[1:])
