# SEGWatch — Cisco 邮件网关沦陷检测

针对 **CVE-2026-76519** 的网关侧沦陷检测小工具：Cisco Secure Email Gateway（SEG）AMP 的
File Reputation 附件处理路径存在相对路径穿越（CWE-23），未授权远程攻击者只需发一封带
精心构造附件的邮件穿过网关，即可在底层 OS 写任意文件并以 root 执行命令。
CVSS 9.8，Cisco 定级 Critical，2026 年 10 月已确认在野利用，CISA KEV 在列，
联邦机构修复死线 2026-10-17。

检测逻辑直接来自 **Cisco 官方沦陷排查指南** + 公告中的影响条件，
按网关主机输出 0–100 风险分，每条命中都给出规则名、证据行和建议动作。

## 与 Day 08 PhishHunt 的区别

- **PhishHunt 看邮件内容**：这封邮件钓不钓鱼（发件人伪造、链接、话术）。
- **SEGWatch 看网关设备自身**：设备有没有被打穿（系统日志沦陷指示器、附件穿越投递、
网关向外部的可疑上传下载、自身版本是否可被利用）。

一个看"信"，一个看"门"。两个配合才是完整的邮件安全闭环。

## 怎么跑

```bash
python segwatch.py --demo
```

离线可运行：`--demo` 自带两台网关的合成数据（seg-01 干净、seg-02 被打穿），
纯 Python 标准库，无第三方依赖。

也可以喂真实日志：

```bash
python segwatch.py --syslog system_logs.txt --maillog mail.log \
--flows flow.log --config snapshot.json
```

## 输入格式

| 文件 | 格式 | 示例 |
| --- | --- | --- |
| system 日志 | `ts=<ISO> gateway=<名> msg=<消息>` | `ts=2026-10-16T14:02:11 gateway=seg-02 msg=System Security: Compromise detected.` |
| 邮件日志 | `ts=… gateway=… sender=… file=<附件名> size=<字节>` | `ts=… gateway=seg-02 sender=evil@x.tld file=..%2f..%2fx.pdf size=2048` |
| 流量日志 | `ts=… gateway=… dst=<目标IP> direction=upload\|download bytes=<字节>` | `ts=… gateway=seg-02 dst=185.220.70.9 direction=upload bytes=157286400` |
| 配置快照 | JSON | `{"gateway":"seg-02","file_reputation":true,"content_scanner":"25.2.1.1000"}` |

## 四组检测规则

| 规则 | 来源 | 逻辑 |
| --- | --- | --- |
| R1 沦陷指示器 | Cisco 官方排查法第 1 条 | system_logs 里 "System Security" 行命中 "Suspected compromise indicator was found" / "Compromise detected."（不区分大小写），单次 +60 |
| R2 附件异常 | CVE-2026-76519 攻击路径 | 附件名含路径穿越（`../`、`..\`、URL/双重编码变体、绝对路径、空字节），单次 +15；同一发件人 10 分钟内 ≥3 封带附件邮件 +10 |
| R3 网关外联异常 | Cisco 官方排查法第 2 条 | 网关向未知外部 IP 上传/下载 +8；新出现的外联目标 +4；非工作时间(00–06点) +4；向未知外部大额上传(>10MB) +6 |
| R4 暴露面自查 | 公告影响条件 | File Reputation 启用 **且** Content Scanner Tools < 25.3.0.5525 → 标记；若同时有 R1–R3 命中，风险分保底 85 |

每条命中附带建议动作：R1 命中 → 立即隔离网关、按 Cisco 指南重建可信配置、
轮换凭证与 SSH 密钥（Cisco 警告集群内 SSH 私钥可能已泄露）；
R4 命中 → 升级 Content Scanner Tools ≥ 25.3.0.5525（无需重启）或 AsyncOS 到修复版。

## 示例输出（`--demo`）

```
网关 seg-01 风险分: 0/100 ✅ 未见异常
----------------------------------------------------------------
[R4-信息] File Reputation=启用, Content Scanner Tools=25.3.0.5525 (已修复)

网关 seg-02 风险分: 100/100 🔴 极高危（疑似已被打穿）
----------------------------------------------------------------
[R1-沦陷指示器] system_logs:... msg=System Security: Suspected compromise indicator was found...
→ 隔离该网关(断开集群/管理网), 按 Cisco 官方指南重建可信配置; 轮换集群内全部凭证与 SSH 密钥 ……
[R2-附件穿越] 附件名命中穿越模式 '\.\.%2f':... file=..%2f..%2f..%2ftmp%2fx.pdf...
→ 隔离命中邮件/附件, 检查网关文件系统是否被写入异常文件 ……
[R3-外联异常] 网关 seg-02 向未知外部 IP 185.220.70.9 upload 157286400 bytes; 新出现的外联目标; 非工作时间传输; 向未知外部大额上传
→ 核查防火墙日志确认上传/下载目标与内容, 封锁可疑外部 IP, 注意攻击者可能已抹掉本机日志 —— 以网络侧日志为准。
[R4-可被利用] File Reputation=启用, Content Scanner Tools=25.2.1.1000 (< 25.3.0.5525)
→ 尽快升级 Content Scanner Tools ≥ 25.3.0.5525(无需重启) ……
```

## 局限

- 合成数据只覆盖典型形态，真实网关日志字段需按上面表格做简单适配。
- 可信外联名单（`KNOWN_GOOD_PREFIXES`）是示例值，生产使用请换成自家资产清单。
- 本工具是检测辅助，不能替代 Cisco 官方的完整取证流程。

## 参考

- Cisco 安全公告 cisco-sa-esa-afw-zqYJkjxp（CVE-2026-76519）
- CISA KEV 目录（联邦机构修复死线 2026-10-17）
