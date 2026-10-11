# WebAttack · Web 攻击检测小 Agent

`rain.op` 每日安全小 Agent 系列的第 7 个：**流量监测**方向。

Web 服务天天被扫：SQL 注入、XSS、目录遍历、命令注入、敏感文件探测……
WebAttack 读取 Web 服务器访问日志（Apache / Nginx Combined 格式），按客户端 IP
聚合，用 **6 组启发式规则** 揪出攻击者，输出 0–100 风险评分、命中类型和证据链。

## 检测逻辑

| 规则组 | 权重 | 例子 |
|---|---|---|
| SQL注入 | 15 | `UNION SELECT`、`' OR '1'='1`、`information_schema`、`SLEEP(`/`BENCHMARK(` |
| XSS | 10 | `<script`、`javascript:`、`onerror=`、`document.cookie` |
| 路径遍历/LFI | 12 | `../`、`/etc/passwd`、`php://`（含 `%2e%2e`、双重编码绕过） |
| 命令注入 | 18 | `;cat`、`` `whoami` ``、`$(`、`;wget` |
| 敏感文件扫描 | 8 | `/.git/`、`/.env`、`/wp-admin`、`/actuator`、`/phpmyadmin` |
| 扫描器指纹 | 8 | sqlmap、nikto、nmap、gobuster 等 UA |

先对请求目标做两轮 URL 解码（`+` 视为空格），再匹配；每组规则每条请求只计一次。
评分 0–100：**≥70 高危，≥40 可疑**，其余正常。评分 = 规则权重和（上限 60）
+ 攻击类型多样性（最多 +24）+ 持续攻击量（最多 +24）+ 大量 4xx 扫描加成。

## 目录结构

```
agents/07-webattack/
├── webattack.py      # 主程序：解析 → 规则匹配 → 按 IP 聚合打分 → 报告
├── requirements.txt  # 纯标准库，无第三方依赖
└── README.md         # 本文件
```

## 怎么跑

```bash
# 演示模式：内置正常流量 + SQLi / XSS / 遍历 / 命令注入 / 敏感文件扫描 5 类攻击
python webattack.py --demo

# 分析本地日志（Combined 格式）
python webattack.py --file /var/log/nginx/access.log

# 管道输入
tail -f /var/log/nginx/access.log | python webattack.py

# 指定告警 JSON 输出路径
python webattack.py --demo --json /tmp/alerts.json
```

需要 Python 3.8+，无第三方依赖。

## 示例输出

```
$ python webattack.py --demo
共解析 39 条访问日志
客户端IP           评分    等级    命中    攻击类型
--------------------------------------------------------------------------------
203.0.113.99    92    高危    18    敏感文件扫描、扫描器指纹
192.0.2.55      76    高危    4     路径遍历/LFI、命令注入
192.0.2.10      72    高危    6     SQL注入
198.51.100.9    56    可疑    4     路径遍历/LFI
203.0.113.7     48    可疑    4     XSS
```

正常用户流量和 Googlebot 均未误报（演示里 0 误报）。告警 JSON 结构：

```json
{"alerts": [{"ip": "203.0.113.99", "score": 92, "level": "高危",
             "hits": 18, "attack_types": ["敏感文件扫描", "扫描器指纹"],
             "evidence": ["敏感文件扫描: GET /.git/HEAD", "..."]}]}
```
