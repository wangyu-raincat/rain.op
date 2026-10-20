# NextJS-QA 🛡️ Next.js 双 RCE 沦陷速查

RAG 方向。锚定 **2026-10-14** 披露的 Next.js 三漏洞补丁（两个 Critical RCE + 一个 High DoS）：

| 漏洞 | 编号 | 严重度 | 一句话 |
| --- | --- | --- | --- |
| VULN-1 | GHSA-673q-mjm6-r5xr | Critical 9.5 | `use cache` 返回多个 typed array → 未授权 RCE（16.x 专属，**无 workaround**） |
| VULN-2 | CVE-2026-96889 / GHSA-2464-fhr4-w9xw | Critical 9.5 | librsvg use-after-free 经 sharp 触发的 SVG 图片优化 RCE（10.0.0 起全线受影响） |
| VULN-3 | GHSA-p3m5-59mp-jv5r | High 8.2 | Server Actions CPU 打满的进程级 DoS（13.x 起） |

截至 2026-10-15 尚无公开在野利用报告、无公开 PoC——正是「检测先行」窗口。

## 怎么跑

纯标准库，Python 3.8+，离线可跑：

```bash
# 1. 版本判定：输 Next.js 版本号 → 是否中招 + 升级路径
python nextjsqa.py --version 15.5.20

# 2. 带上 sharp 版本一起判（npm ls sharp 的结果）
python nextjsqa.py --version 16.4.0 --sharp 0.35.4

# 3. 问答：按编号或自然语言
python nextjsqa.py --ask "GHSA-673q-mjm6-r5xr"
python nextjsqa.py --ask "sharp 多少版本才安全"

# 4. 自查清单 / 处置清单
python nextjsqa.py --check
python nextjsqa.py --fix

# 5. 一键演示
python nextjsqa.py --demo
```

## 示例输出

```
$ python nextjsqa.py --version 16.4.0 --sharp 0.35.4
============================================================
Next.js 16.4.0 受影响判定（披露 2026-10-14）
============================================================
[!! 中招] GHSA-673q-mjm6-r5xr · use cache typed array RCE · Critical 9.5
      → 详情：--ask VULN-1
[!! 中招] CVE-2026-96889 · SVG 图片优化 RCE · Critical 9.5
      → 详情：--ask VULN-2
[!! 中招] GHSA-p3m5-59mp-jv5r · Server Actions DoS · High 8.2
      → 详情：--ask VULN-3

>> 升级路径：npm install next@16.4.1
>> VULN-2 必查 sharp：npm ls sharp，要求 ≥ 0.35.5
>> !! sharp 0.35.4 < 0.35.5：VULN-2 仍暴露，先升 sharp（npm i sharp@0.35.5+）。

>> 完整处置清单：
...
```

## 升级路径速记

- 16.0.0–16.4.0 → `npm install next@16.4.1`（三洞全修；另确认 react-server-dom-* ≥ 19.0.9/19.1.10/19.2.9/19.3.1）
- 15.x（≤15.5.27）→ `npm install next@15.5.28`，再确认 `npm ls sharp` ≥ 0.35.5
- ≤14.x / 10.x–12.x → 跳线升 15.5.28 或 16.4.1（先看 breaking changes）

## 实现说明

- 版本边界表直接编码自 GHSA 官方公告（VULN-2 的 sharp 条件、VULN-1 的「无 workaround」均按官方口径）。
- 问答用手写 BM25（中英文混合分词，中文单字 + 英文 token），编号输入走精确匹配。
- 知识库为披露时的静态快照；在野状态、修复版本如有更新，以 GHSA 官方为准。
