# 🔥 LiveFire-QA（12-livefire）

「正在着火的漏洞」离线问答小助手。RAG 方向。

和 Day 10 的 VulnIntel-QA（泛 10 月 CVE 速查）不同，这个库只收录**正在被利用、或暂无补丁**的高危漏洞，按"威胁状态"组织，回答两个实战问题：

- **哪个最该先修？** → `--exploited` 看在野利用中的
- **没补丁的怎么缓？** → `--unpatched` 看暂无补丁的，`--fix` 查修复/缓解方案

## 知识库（5 条，2026-10-13/14 披露）

| 编号 | 产品 | 状态 |
|---|---|---|
| CVE-2026-104935 | Ivanti Connect Secure | 在野利用中（认证绕过 → root RCE）|
| CVE-2026-104937 | Shopware 6.7 | 暂无补丁（存储型 XSS → 管理员 token 被盗 → RCE）|
| ZDI-26-756 | Genesis World | 无补丁 zero-day（`load_checkpoint` 反序列化 RCE）|
| CVE-2026-103572 | Visual Studio Copilot | PoC 已公开（间接 prompt injection RCE，CVSS 8.8）|
| CVE-2026-89107 | SAP S/4HANA | 已披露需认证（规则脚本 RCE，CVSS 9.9）|

## 怎么跑

纯 Python 标准库，无需网络、无需 API Key（Python 3.8+）：

```bash
cd agents/12-livefire
python livefire.py --demo            # 离线演示
python livefire.py --exploited       # 在野利用中的（最优先修）
python livefire.py --unpatched       # 暂无补丁的（看缓解措施）
python livefire.py --fix "Ivanti 怎么修"   # 修复/缓解速查（支持自然语言）
python livefire.py CVE-2026-104937   # 编号精确查（CVE / ZDI 都行）
python livefire.py "shopware xss"    # 自然语言 BM25 检索
```

## 示例输出

```
$ python livefire.py --unpatched

++ 暂无补丁的漏洞（2 条，靠缓解措施顶着）：

------------------------------------------------------------
HOT CVE-2026-104937  |  Shopware 6.7
   CVSS：未公布（高危） ｜ 披露：2026-10-14 ｜ 状态：【暂无补丁】
   利用条件：媒体上传功能接受 HTML 文件且缺少安全响应头；管理员点击恶意链接即触发存储型 XSS。
   影响：管理员 token 被盗；若管理员有扩展管理权限，可进一步升级为整机 RCE。
   修复/缓解：暂无官方补丁。缓解：限制/禁用媒体上传中的 HTML 文件类型；……
   来源：https://securityonline.info/shopware-vulnerability-cve-2026-104937/
------------------------------------------------------------
```

## 实现要点

- **双语 BM25**：英文按词、中文按单字切分，同一索引里混排检索
- **意图分流**：`--exploited` / `--unpatched` 按威胁状态过滤，`--fix` 聚焦修复/缓解字段
- **编号精确查**：正则识别 `CVE-YYYY-NNNN` / `ZDI-YY-NNN`，大小写不敏感
- 每条目结构：编号 / 产品 / CVSS / 披露时间 / 威胁状态 / 利用条件 / 影响 / 修复或缓解 / 来源
