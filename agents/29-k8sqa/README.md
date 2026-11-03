# K8sSecQA

Kubernetes 安全离线问答：针对 K8s 集群最常见的 12 类配置风险做知识检索与抽取式回答，纯标准库，离线可运行，不联网、不调用外部 API。

## 它是做什么的

Kubernetes 的风险大多不在 CVE，而在配置：RBAC 给宽了、容器开了特权、Secret 没加密、Pod 之间默认互通。K8sSecQA 内置 12 张知识卡片，覆盖：

- RBAC 过度授权、ServiceAccount Token 自动挂载
- 特权容器、hostPath 挂载、节点暴露面
- Secret 明文存放与 etcd 未加密
- 不可信镜像、准入控制缺失、NetworkPolicy 缺失
- API Server 匿名访问、云元数据 SSRF、审计日志缺失

## 怎么跑

```bash
python agents/29-k8sqa/k8sqa.py --demo
python agents/29-k8sqa/k8sqa.py --ask "RBAC 权限给太大了怎么收紧？"
python agents/29-k8sqa/k8sqa.py --list
```

`--ask` 会按词项重叠打分（标题命中权重最高），输出最相关的卡片原文并标注卡片编号与匹配分，便于核对来源。也可以用 `--kb` 指定自己的知识库 JSON（格式见 `kb.json`：`{"cards": [{"id", "title", "text", "tags"}]}`）。

## 示例输出

```text
问题：RBAC 权限给太大了怎么收紧？

[1] 【K01】RBAC 过度授权：集群管理员权限泛滥（匹配分 21）
RBAC 过度授权是 Kubernetes 最常见的配置失误：把 cluster-admin 绑给普通 ServiceAccount……
标签：RBAC、权限、cluster-admin、最小权限
```

## 边界说明

- 知识卡片讲的是通用防御思路，不是针对某个具体集群版本或云厂商的审计结论。
- 检索是词项匹配，不是语义理解；换个关键词往往能命中更相关的卡片。
- 落地到自家集群时，请结合实际的 RBAC 绑定、准入策略与审计日志复核，并用 CIS Kubernetes Benchmark 做完整自查。
