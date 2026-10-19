# CollaboraWatch — Nextcloud Collabora 利用链检测

针对 **CVE-2026-110447** 的日志侧检测小工具：Nextcloud Collabora Online
内置 CODE 服务器（`richdocumentscode`）< 26.4.303 存在 OS 命令注入，
未授权远程攻击者可 RCE。CVSS 9.2（v4.0 Critical），2026 年 9–10 月
在野利用，攻击者落地 PHP webshell 后搜刮密码库与加密钱包。

检测逻辑直接来自公开取证（Collabora `richdocumentscode` issue #354）
与安全媒体报道的攻击链，按攻击 IP 输出 0–100 风险分，每条命中都给
规则名、证据行和处置建议。

## 攻击链 → 检测规则

| 阶段 | 真实攻击手法 | 规则 |
| --- | --- | --- |
| 探测/利用 | `GET /apps/richdocumentscode/proxy.php?status` 带 `%2e%2e` 编码穿越，经 `remote_font_config.url` 未转义传入 `sh`，用 `$()` + `${IFS}` 空白混淆执行命令 | R1：proxy.php 命中编码穿越 / shell 注入指纹 / 超长 Base64 载荷，+30；同一 IP 多次命中再 +10 |
| 落地 | Base64 载荷在 `/apps/richdocumentscode/` 下释放 `shx*.php` / `shrf*.php` | R2：请求命中 webshell 文件名模式，+40 |
| 确认 | 把系统信息发往外部 `webhook.site` | R3：攻击 IP 出站到 webhook.site，+25 |
| 发现 | 以 www-data 身份搜 `*.kdbx` / `wallet.dat` / 密码管理器与钱包目录 | R4：webshell 请求含发现关键字，+15 |
| 暴露面 | 仅 `richdocumentscode` < 26.4.303 受影响（Docker/外部独立部署不受影响） | R5：版本快照确认未修复，攻击过它的 IP +10 |

风险分 ≥50 告警。纯 Python 标准库。

## 与 Day 07 WebAttack 的区别

- **WebAttack 看通用 Web 攻击**：访问日志里的 SQLi / XSS / 遍历 / 命令注入通用启发式。
- **CollaboraWatch 看一条真实利用链**：CVE-2026-110447 的 proxy.php 注入指纹 →
  `shx*`/`shrf*` webshell → webhook.site 外联确认 → 版本暴露面自查，
  五个阶段互相印证，误报更低。

一个看"面"，一个看"链"。先用 CollaboraWatch 确认有没有被这条在野利用链打中，
再用 WebAttack 扫全站通用攻击。

## 怎么跑

```bash
python collaborawatch.py --demo
```

离线可运行：`--demo` 自带合成数据（1 个正常管理员、1 个只探测的扫描器、
1 个走完利用链的攻击者 + 两台主机的版本快照），无第三方依赖。

也可以喂真实日志：

```bash
python collaborawatch.py --access access.log --flows egress.log --config apps.json
```

加 `--json` 输出机器可读结果（方便接入 SIEM）。

## 输入格式

| 文件 | 格式 | 示例 |
| --- | --- | --- |
| 访问日志 | `ts=<ISO> ip=<ip> method=<M> uri="<路径>" status=<码> bytes=<n>` | `ts=2026-10-18T22:30:00 ip=185.220.70.9 method=GET uri="/apps/richdocumentscode/proxy.php?status&..." status=500 bytes=96` |
| 出站流量 | `ts=<ISO> src=<内网IP> dst=<IP> host=<域名> bytes=<n>` | `ts=... src=185.220.70.9 dst=46.101.88.12 host=webhook.site bytes=2314` |
| 版本快照 | JSON | `{"apps":[{"host":"cloud.example.com","app":"richdocumentscode","version":"26.4.302"}]}` |

## 示例输出（--demo）

```
[暴露面] 以下主机 richdocumentscode 未修复(<26.4.303):
  - cloud.example.com : 26.4.302  -> 建议立即升级到 26.4.303+ 或卸载该应用
------------------------------------------------------------
告警 IP: 185.220.70.9   风险分: 100/100
  命中: R1 proxy.php命令注入、R1 持续利用、R2 webshell落地、
        R3 外联确认、R4 凭证/钱包发现、R5 暴露面
  建议: 隔离该 IP→封禁; 检查 /apps/richdocumentscode/ 下 shx*/shrf*.php;
        杀 www-data 可疑进程; 轮换 Web 服务用户可触达的密钥。
```

## 处置清单（命中告警后）

1. 升级 `richdocumentscode` 到 26.4.303+，或不用就直接卸载（补丁清不掉已落地的后门）。
2. 查 `/apps/richdocumentscode/` 下 `shx*.php` / `shrf*.php` 并删除。
3. 封禁告警 IP，查同一时段该 IP 的其他请求。
4. 终止 www-data 名下的可疑进程，轮换 Web 服务用户可触达的全部密钥/凭证。

## 参考

- CVE-2026-110447：Nextcloud Collabora Online Built-in CODE Server OS 命令注入，
  CVSS 9.2，在野利用（2026-09~10）
- 取证细节：Collabora Online `richdocumentscode` GitHub issue #354
- 报道：securityonline.info（2026-10-14）
