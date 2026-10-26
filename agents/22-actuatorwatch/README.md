# ActuatorWatch

Spring Boot Actuator 暴露面探测检测：分析 Web 访问日志，识别针对 Actuator 管理端点的枚举、敏感信息窃取与危险写操作，按 IP 打 0–100 风险分，输出告警与处置建议。纯 Python 标准库，离线可运行。

## 它检测什么

| 规则 | 例子 | 风险 |
| --- | --- | --- |
| 敏感端点读取 | `GET /actuator/env`、`/actuator/configprops`、`/actuator/heapdump` | 窃取数据库密码、云密钥、堆内存凭证 |
| 危险写操作 | `POST /actuator/env`、`POST /actuator/refresh`、`POST /actuator/shutdown` | 篡改配置、停服务，env+refresh 链可导致 RCE |
| SpEL / 配置注入 | `/actuator/gateway/routes` 带 SpEL 表达式 | Spring Cloud Gateway CVE-2022-22947 同类利用 |
| 路径绕过形态 | `//actuator/env`、`/actuator/../`、编码点号 | 绕过网关/鉴权规则的探测 |
| 枚举爆发 | 同一 IP 短窗口内命中 4 个以上不同端点 | 系统性踩点 |
| 疑似成功窃取 | heapdump/env 返回 200 且响应体 ≥ 1MB | 按凭证泄露处置 |

合法监控只打 `/actuator/health` 时只记 5 分，不会误报成高危。

## 怎么跑

```bash
# 离线演示（含合成攻击流量：正常用户 + 合法监控 + 2 个攻击者）
python actuatorwatch.py --demo

# 分析自己的日志（Nginx/Apache combined 格式）
python actuatorwatch.py --log access.log --json-out alerts.json

# 只生成演示日志
python actuatorwatch.py --demo-log demo.log
```

## 示例输出

```text
ActuatorWatch 暴露面探测检测报告  |  分析日志: 49 条
发现 3 个可疑 IP:
[1] [高危] 203.0.113.77  风险分: 100  端点: beans, configprops, env, heapdump, mappings, sessions, threaddump
    信号: read_sensitive×7, big_dump×1, enum_burst×1
    建议: heapdump/env 疑似成功下载：按凭证泄露处置，轮换数据库密码与云密钥。
    建议: 确认 actuator 是否误对外开放：收紧到内网/鉴权，关闭不必要的端点。
[2] [高危] 198.51.100.44  风险分: 100  端点: env, gateway/routes, refresh, shutdown
    信号: write_dangerous×4, spel_payload×1, bypass_shape×1, read_sensitive×1, enum_burst×1
    建议: 立即核查配置是否被篡改，检查 env/refresh/gateway 路由变更记录，必要时回滚并重启。
    建议: 检查应用日志有无 SpEL 执行痕迹，排查新增路由与异常进程。
    建议: 确认 actuator 是否误对外开放：收紧到内网/鉴权，关闭不必要的端点。
[3] [低危] 10.0.0.5  风险分: 30  端点: health
    信号: benign_probe×6
    建议: 仅健康检查类探测：确认来源是否为合法监控，误报可忽略。
JSON 告警已写入: alerts.json
```

> 出现高危告警时程序按设计返回退出码 1；演示里出现此退出码表示告警被触发。

## 输入格式

每行一条 Nginx/Apache combined 格式访问日志，例如：

```text
203.0.113.77 - - [26/Oct/2026:09:00:10 +0800] "GET /actuator/env HTTP/1.1" 200 48210
```

无法解析的行会被跳过。日志里没有响应体，因此“疑似成功窃取”只是加分信号，不是定罪证据；命中规则也不等于确认入侵，请结合 IP 归属与时间窗口复核。

## 处置清单（命中高危时）

1. 确认 actuator 是否误对外开放：只放内网访问，或加鉴权；关闭 `env`、`heapdump`、`shutdown` 等不需要的端点。
2. 若命中写操作：核查配置变更记录，必要时回滚并重启应用。
3. 若 heapdump/env 疑似成功下载：按凭证泄露处置，轮换数据库密码、云密钥、会话密钥。
4. 若命中 SpEL 载荷：检查应用日志与新增网关路由，排查异常进程。
