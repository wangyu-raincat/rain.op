# VulnIntel-QA 🛡️ 2026年10月高危漏洞情报离线问答

用 BM25 检索内置的 **4 条 2026 年 10 月真实高危 CVE** 知识库，回答
"这个漏洞影响谁、利用条件是什么、修复版本是多少、是否已被在野利用"。
纯 Python 标准库，离线可运行，不依赖任何外部 API。

## 知识库（2026-10-13 核验整理）

| CVE | CVSS | 产品 | 在野利用 |
| --- | --- | --- | --- |
| CVE-2026-85097 | 10.0（Patchstack；官方 CVE 记录 9.8） | WordPress Bricksforge 插件 | ✅ 已在野利用 |
| CVE-2026-76465 | 9.8 | Cisco Nexus 3000 / 9000 | ❌ 未发现利用 |
| CVE-2026-107406 | 9.5（CVSS v4.0） | Citrix NetScaler ADC / Gateway | ❌ 未发现利用 |
| CVE-2026-90970 | 9.9 | GitLab AI Gateway（自托管） | ❌ 未发现利用 |

条目字段统一为：CVE 编号 / CVSS / 产品 / 影响版本 / 前置条件 / 认证要求 /
根因 / 攻击链 / 修复版本 / 在野利用状态 / 排查要点 / 来源链接。
细节来自 Patchstack / Cisco / Citrix / GitHub 安全公告及多家安全媒体报道的
二手转述（非 NVD 原文），以"影响范围 / 修复版本 / 利用条件"为检索要点；
正式研判请以 NVD / CVE 公开描述和厂商公告为准。

## 怎么跑

```bash
python vulnintel.py --demo                 # 演示模式：自动回答 5 个示例问题
python vulnintel.py "CVE-2026-85097 是什么漏洞"   # 编号精确查询 + 自然语言提问
python vulnintel.py --id CVE-2026-76465    # 按 CVE 编号精确查询
python vulnintel.py --list                  # 列出知识库全部 CVE
python vulnintel.py --exploited             # 哪些已被在野利用
python vulnintel.py --needs-config          # 哪些需要特殊配置才受影响
python vulnintel.py --fix                   # 全部修复版本速查
```

## 示例输出

```
❓ 问: 哪些漏洞已经被在野利用了
🔎 知识库中 1 条已被在野利用：

──────────────────────────────────────────────
🛡️ CVE-2026-85097 · CVSS 10.0（Patchstack；官方 CVE 记录 9.8）
产品: WordPress Bricksforge 插件（Pro Forms 模块）
──────────────────────────────────────────────
📌 影响范围: Bricksforge ≤ 3.1.8.9；表单含上传字段的站点均受影响；……
🔑 前置条件: 无特殊配置前置：Pro Forms 激活即可。
👤 认证要求: 无需登录（unauthenticated）
🐛 根因: 上传时校验了 MIME，但表单提交时信任客户端传的 temporaryFileUploads 参数里的 url 字段，不做二次校验。
⛓️ 攻击链: ① 未授权 AJAX bricksforge_regenerate_nonce 取有效 nonce → ② 上传 GIF/PHP polyglot……
🩹 修复版本: 升级到 3.1.8.10 起（供应商同时建议直接升级到最新 4.0.1）。
🌐 在野利用: ✅ 已在野利用：Patchstack 于 2026-10-07 21:47 UTC 首次观测到……
🔍 排查要点: 审计对 /wp-json/bricksforge/v1/form_submit 和 admin-ajax.php……
📚 来源: thehackernews.com / scworld.com / deafnews.it / wpdeeply.com
```

## 实现要点

- **BM25 检索**：中英文双索引（英文词 / 编号 / 版本号 + 中文二元组分词），
  CVE 编号 / 产品 / 关键词字段加权；参考 08-mitre 的分词方式。
- **三种回答路径**：CVE 编号精确命中 → 聚合类意图分流（在野利用 / 特殊配置 /
  修复版本速查）→ BM25 自然语言检索。
- **意图分流**：问"哪些已被在野利用"只返回 CVE-2026-85097；
  问"哪些需要特殊配置才受影响"返回 Cisco MPLS OAM 默认关闭、
  Citrix SAML 配置两条；问"修复版本"无指定 CVE 时返回全部速查表。

## 依赖

无第三方依赖，仅 Python 3.8+ 标准库（`requirements.txt` 为空说明）。
