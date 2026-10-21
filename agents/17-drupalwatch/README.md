# DrupalWatch 🛡️

针对 **CVE-2026-108097**（Drupal Field UI RCE）的 Web 访问日志检测 agent。

## 漏洞背景

- CVE-2026-108097：Drupal core Field UI 模块远程代码执行，官方公告 SA-CORE-2026-014（2026-10-14），Drupal 评级 Critical 19/25。
- FORTBRIDGE 研究员 Adrian Tiron 于 2026-10-20 发布完整技术分析与 lab PoC：Field UI 有一行代码"把表格行里命名的 PHP callable 当作代码直接执行"，但核心本身无法从外部到达——需要某个桥接模块 / 自定义代码把请求数据喂进这些表格行（至少一条预认证利用路径已确认）。
- 受影响：8.9.0–10.6.18 / 11.0.0–11.3.18 / 11.4.0–11.4.9 / 12.0.0-alpha1–beta1；
  修复：**10.6.19 / 11.3.19 / 11.4.10 / 12.0.0-beta2**；无法立即升级时可卸载 field_ui 模块临时缓解。

## 检测思路（7 组规则）

| 规则组 | 看什么 | 权重 |
|---|---|---|
| Field UI 端点访问/探测 | `/admin/structure/.../fields` 等管理端点（4xx 探测形态加权更高） | 5 / 15 |
| callable 载荷 | 参数里命名 PHP callable：`rows[0][callable]=system` 形态 + `system(`/`eval(` 等函数形态 + `${IFS}`/反引号/`chr()` 混淆 | 35 |
| 文件读取探测 | `%2e%2e` 编码穿越、`settings.php`、`config/sync`、`/etc/passwd` | 20 |
| webshell 落地/交互 | `sites/default/files` 下异常 `.php`、`?cmd=`、`whoami`、`wget … | sh` 等 | 40 |
| 长 Base64 载荷 | 查询串 60+ 字符 Base64（callable 名混淆常用） | 15 |
| 扫描器 UA | nuclei / sqlmap / python-requests 等 | 10 |
| 爆发速率 | 10 分钟窗口 > 60 请求 | 15 |

每个 IP 按命中加权求和封顶 100 分：≥80 高危、≥50 可疑、≥20 探测、<20 低。
输出每个可疑 IP 的命中证据链与处置建议（隔离取证 → 升级/卸载 field_ui → 审计桥接模块 → 检查 files 目录 `.htaccess` 与异常出站连接）。

## 怎么跑

纯标准库，无需安装：

```bash
python drupalwatch.py --demo          # 内置演示：4 个 IP 的合成攻击日志
python drupalwatch.py --log /var/log/nginx/access.log
python drupalwatch.py --log access.log --json   # JSON 输出，接 SIEM
```

## 示例输出

```
共分析 4 个源 IP，3 个需要关注（≥20 分）

[高危] 192.0.2.77  风险分 100/100  请求 4 次
      - scanner_ua: 4 次
      - callable_payload: 3 次
      - file_disclosure: 1 次
      - webshell_activity: 1 次
      处置建议：
        * 立即隔离该 IP 的访问并取证：检查 sites/default/files 与模块目录新增 .php 文件
        * 升级到修复版本（10.6.19 / 11.3.19 / 11.4.10 / 12.0.0-beta2）；无法立即升级则卸载 field_ui 模块
        * 审查自定义模块/贡献模块中把请求数据喂给 Field UI 表格的代码（桥接点）
        * 检查 files 目录 .htaccess 是否被改动、是否有异常出站连接/意外 PHP 进程

[探测] 192.0.2.99  风险分 40/100  请求 2 次
      - file_disclosure: 2 次
      处置建议：
        * 属常规扫描噪声；若同一资产反复出现，检查版本并收紧管理端点访问
```

## 局限

- 启发式检测：PoC 公开初期扫描器噪声大，"高危"仍需人工复核确认是否真实打中桥接模块。
- 只解析 combined 格式访问日志；POST body 里的载荷看不到，需要配合 WAF/应用层日志。
- 合法管理员访问 Field UI 只给 5 分基线，不会误报。
