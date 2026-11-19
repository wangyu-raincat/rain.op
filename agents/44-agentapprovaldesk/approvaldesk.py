#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AgentApprovalDesk —— 智能体人工审批审计台（rain.op Day 44 · 监测向）

人工审批点是 agent 安全的最后一道闸：删文件、调外部 API、发数据、
改配置这类高危操作，理论上都要先有人点头再执行。但“批了”不等于
“批对了”——自批自审、批完改参、被拒仍执行、批的人没资格、批完拖
太久才执行，都是审批链上真实出现过的绕过形态。

本工具读 agent 的审批台账（JSONL，每行一条审批请求），做七组审计：
无审批执行、自批自审、已拒仍执行、批后改参、越权审批、审批超时、
审批过期后执行。按请求打 0–100 风险分，输出合规率、SLA 达成率与
逐条违规清单，可直接作为 Day 36 AgentIncidentDesk 的事件来源。

与 Day 34 MCPGuard（调用时拦截）不同：这里是事后审计 —— 调用已经
发生，从台账上定位审批链哪里被绕过、哪一类绕过最常见。
与 Day 40 ToolChainWatch（调用链异常）不同：这里只盯审批环节 ——
调用链可以完全“正常”，但批的人不对、批的内容被偷换，照样是绕过。
与 Day 35 AgentEvalBench（评测台）不同：这里审计的是真实运行台账，
不是测试集；跑出来的合规率就是线上审批链的真实成色。

只用 Python 标准库，离线可运行，不调用任何外部 API。
演示与示例数据均为虚构占位值，不对应任何真实人员或真实操作。

台账格式（JSONL，每行一条审批请求）：
    {"req_id": "APR-0001", "agent": "ops-agent", "action": "delete_file",
     "tool": "shell", "risk": "high",
     "requested_by": "agent:ops-agent", "approved_by": "alice",
     "approver_role": "sre-lead",
     "status": "approved",
     "requested_at": "2026-11-18T09:00:00", "decided_at": "2026-11-18T09:05:00",
     "executed_at": "2026-11-18T09:06:00",
     "approved_params": {"path": "/tmp/cache"}, "executed_params": {"path": "/tmp/cache"},
     "requires_approval": true}
status 取值：approved / rejected / pending / expired /
executed_without_approval。risk 取值：low / medium / high / critical。
时间取 ISO 8601（可带时区后缀 Z 或 +08:00）。

用法：
    python approvaldesk.py --demo              # 内置演示：10 条请求，植入 7 类违规
    python approvaldesk.py -i approvals.jsonl  # 审计自己的台账文件
    python approvaldesk.py -i approvals.jsonl --json report.json
    python approvaldesk.py -i approvals.jsonl --sla-hours 8   # 审批 SLA 改为 8 小时
"""
import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_INPUT = os.path.join(HERE, "sample_approvals.jsonl")

# 高危操作、及其审批人必须具备的角色（最小权限：只给够得着这件事的角色批）
REQUIRED_ROLES = {
    "delete_file": {"sre-lead", "security-lead"},
    "exec_shell": {"sre-lead", "security-lead"},
    "send_external": {"security-lead", "data-owner"},
    "modify_config": {"sre-lead"},
    "rotate_secret": {"security-lead"},
    "deploy": {"sre-lead", "release-manager"},
    "read_secret": {"security-lead"},
}
# 哪些操作无论如何都必须经过审批（require_approval 为 false 的记录也不豁免）
ALWAYS_REQUIRE_APPROVAL = {"delete_file", "exec_shell", "send_external",
                            "rotate_secret", "read_secret"}
HIGH_RISK = {"high", "critical"}

SCORE = {"no_approval_exec": 40, "self_approval": 25,
         "rejected_exec": 40, "param_drift": 30,
         "unauthorized_approver": 25, "approval_timeout": 15,
         "stale_approval": 20}
LEVELS = {"no_approval_exec": "高危", "rejected_exec": "高危",
          "param_drift": "高危", "self_approval": "中危",
          "unauthorized_approver": "中危", "stale_approval": "中危",
          "approval_timeout": "低危"}


def parse_time(value):
    """解析 ISO 8601 时间；无时区时按 UTC 处理，失败返回 None。"""
    if not value:
        return None
    try:
        text = str(value).replace("Z", "+00:00")
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def needs_approval(req):
    if req.get("requires_approval") is True:
        return True
    if req.get("action") in ALWAYS_REQUIRE_APPROVAL:
        return True
    return req.get("risk") in HIGH_RISK


def params_differ(approved, executed):
    """比对批准参数与执行参数：只看关键字段的增删改。"""
    if not isinstance(approved, dict) or not isinstance(executed, dict):
        return approved != executed
    keys = set(approved) | set(executed)
    return {k: (approved.get(k), executed.get(k)) for k in keys
            if approved.get(k) != executed.get(k)}


# ---------- 七组审计 ----------

def detect_no_approval_exec(records):
    findings = []
    for idx, req in enumerate(records, 1):
        executed = bool(req.get("executed_at"))
        approved = req.get("status") == "approved" and req.get("approved_by")
        if not executed or approved or req.get("status") == "rejected":
            continue  # 已拒仍执行由 rejected_exec 单独计，避免同一记录重复扣分
        if req.get("status") == "executed_without_approval" or needs_approval(req):
            findings.append({
                "rule": "no_approval_exec", "level": LEVELS["no_approval_exec"],
                "score": SCORE["no_approval_exec"], "records": [idx],
                "detail": f"请求 {req.get('req_id', f'#{idx}')}（{req.get('agent', '?')} "
                          f"执行 {req.get('action', '?')}，风险 {req.get('risk', '?')}）："
                          "高危操作在没有任何批准的情况下执行，审批链被完全绕过。"
                          + ("台账已明确标注 executed_without_approval。"
                             if req.get("status") == "executed_without_approval"
                             else "需要审批的操作未见批准记录。"),
            })
    return findings


def detect_self_approval(records):
    findings = []
    for idx, req in enumerate(records, 1):
        if req.get("status") != "approved":
            continue
        requester = req.get("requested_by") or ""
        approver = req.get("approved_by") or ""
        if approver and requester and approver == requester:
            findings.append({
                "rule": "self_approval", "level": LEVELS["self_approval"],
                "score": SCORE["self_approval"], "records": [idx],
                "detail": f"请求 {req.get('req_id', f'#{idx}')}：审批人 "
                          f"{approver} 与申请人是同一人，自批自审，审批失去制衡意义。"
                          "须确认是身份冒用、账号共用，还是审批流程本身允许自批。",
            })
    return findings


def detect_rejected_exec(records):
    findings = []
    for idx, req in enumerate(records, 1):
        if req.get("status") == "rejected" and req.get("executed_at"):
            findings.append({
                "rule": "rejected_exec", "level": LEVELS["rejected_exec"],
                "score": SCORE["rejected_exec"], "records": [idx],
                "detail": f"请求 {req.get('req_id', f'#{idx}')}（{req.get('agent', '?')} "
                          f"执行 {req.get('action', '?')}）：审批已拒绝，操作仍在 "
                          f"{req.get('executed_at')} 执行，拒绝没有产生任何约束力。"
                          "须立即核查执行结果并排查拒绝信号是否根本没传到执行侧。",
            })
    return findings


def detect_param_drift(records):
    findings = []
    for idx, req in enumerate(records, 1):
        if req.get("status") != "approved" or not req.get("executed_at"):
            continue
        diff = params_differ(req.get("approved_params"),
                             req.get("executed_params"))
        if not diff:
            continue
        changes = "；".join(f"{k}：{v[0]!r} → {v[1]!r}" for k, v in diff.items())
        findings.append({
            "rule": "param_drift", "level": LEVELS["param_drift"],
            "score": SCORE["param_drift"], "records": [idx],
            "detail": f"请求 {req.get('req_id', f'#{idx}')}：批完改参，执行参数"
                      f"与批准参数不一致（{changes}）。审批人点头的是 A，"
                      "实际执行的是 B，等于批了个空壳。",
        })
    return findings


def detect_unauthorized_approver(records):
    findings = []
    for idx, req in enumerate(records, 1):
        if req.get("status") != "approved" or not req.get("approved_by"):
            continue
        required = REQUIRED_ROLES.get(req.get("action") or "")
        if not required:
            continue
        role = req.get("approver_role") or ""
        if role not in required:
            findings.append({
                "rule": "unauthorized_approver",
                "level": LEVELS["unauthorized_approver"],
                "score": SCORE["unauthorized_approver"], "records": [idx],
                "detail": f"请求 {req.get('req_id', f'#{idx}')}（操作 "
                          f"{req.get('action', '?')}）：审批人 "
                          f"{req.get('approved_by')} 的角色是 {role or '（未标注）'}，"
                          f"但该操作要求审批角色为 {'/'.join(sorted(required))}。"
                          "越权审批：批的人没有资格为这件事背书。",
            })
    return findings


def detect_approval_timeout(records, sla_hours, now):
    findings = []
    sla = timedelta(hours=sla_hours)
    for idx, req in enumerate(records, 1):
        if req.get("status") not in ("pending", "expired"):
            continue
        requested = parse_time(req.get("requested_at"))
        if not requested:
            continue
        decided = parse_time(req.get("decided_at"))
        waited = (decided or now) - requested
        if waited > sla:
            findings.append({
                "rule": "approval_timeout",
                "level": LEVELS["approval_timeout"],
                "score": SCORE["approval_timeout"], "records": [idx],
                "detail": f"请求 {req.get('req_id', f'#{idx}')}（{req.get('action', '?')}，"
                          f"风险 {req.get('risk', '?')}）：审批等待 "
                          f"{waited.total_seconds() / 3600:.1f} 小时，超过 SLA "
                          f"{sla_hours} 小时仍未决"
                          + ("（已过期无人处理）。" if req.get("status") == "expired"
                             else "（仍在排队）。")
                          + "长期未决的高危请求最容易被执行侧“先斩后奏”。",
            })
    return findings


def detect_stale_approval(records, ttl_hours):
    findings = []
    ttl = timedelta(hours=ttl_hours)
    for idx, req in enumerate(records, 1):
        if req.get("status") != "approved" or not req.get("executed_at"):
            continue
        decided = parse_time(req.get("decided_at"))
        executed = parse_time(req.get("executed_at"))
        if not decided or not executed:
            continue
        gap = executed - decided
        if gap > ttl:
            findings.append({
                "rule": "stale_approval", "level": LEVELS["stale_approval"],
                "score": SCORE["stale_approval"], "records": [idx],
                "detail": f"请求 {req.get('req_id', f'#{idx}')}：批准 "
                          f"{gap.total_seconds() / 3600:.1f} 小时后才执行，超过批准"
                          f"有效期 {ttl_hours} 小时。批准时的上下文（参数、目标、"
                          "权限）可能早已变化，等于拿旧批文办新事。",
            })
    return findings


# ---------- 审计主流程 ----------

def audit(records, sla_hours=24, ttl_hours=24, now=None):
    now = now or datetime.now(timezone.utc)
    findings = []
    findings += detect_no_approval_exec(records)
    findings += detect_self_approval(records)
    findings += detect_rejected_exec(records)
    findings += detect_param_drift(records)
    findings += detect_unauthorized_approver(records)
    findings += detect_approval_timeout(records, sla_hours, now)
    findings += detect_stale_approval(records, ttl_hours)
    seen = set()
    uniq = []
    for f in findings:
        key = (f["rule"], tuple(f["records"]))
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    score = min(100, sum(f["score"] for f in uniq))
    decided = [r for r in records if r.get("status") in ("approved", "rejected")]
    violated_idx = {idx for f in uniq for idx in f["records"]}
    compliant = len(records) - len(violated_idx)
    compliance = round(100 * compliant / len(records), 1) if records else 100.0
    sla_met = 0
    sla_total = 0
    for r in records:
        if r.get("status") not in ("approved", "rejected"):
            continue
        requested = parse_time(r.get("requested_at"))
        decided_at = parse_time(r.get("decided_at"))
        if not requested or not decided_at:
            continue
        sla_total += 1
        if decided_at - requested <= timedelta(hours=sla_hours):
            sla_met += 1
    sla_rate = round(100 * sla_met / sla_total, 1) if sla_total else 100.0
    if score >= 70:
        level, verdict = "高危", "审批链存在可被绕过的缺口：立即冻结涉事 agent " \
                         "的高危操作，人工复核全部高危告警并补齐审批记录"
    elif score >= 40:
        level, verdict = "中危", "审批链有明确违规：逐条复核告警，" \
                         "确认是否已造成实际执行影响，收紧审批角色与有效期"
    elif score > 0:
        level, verdict = "低危", "仅低危信号（多为审批超时）：留档观察，" \
                         "看超时是否反复出现，必要时缩短 SLA 或增加值班审批人"
    else:
        level, verdict = "正常", "未检出审批违规：高危操作均有合规审批，" \
                         "审批人、参数与执行时间一致"
    by_rule = Counter(f["rule"] for f in uniq)
    by_action = Counter(r.get("action", "?") for r in records)
    return {"total_requests": len(records), "score": score, "level": level,
            "verdict": verdict, "compliance_rate": compliance,
            "decided": len(decided), "sla_hours": sla_hours,
            "sla_met_rate": sla_rate, "findings": uniq,
            "by_rule": dict(by_rule), "by_action": dict(by_action)}


def load_ledger(path):
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for ln, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                print(f"跳过第 {ln} 行：不是合法 JSON", file=sys.stderr)
    return records


def print_report(report, source):
    print("=" * 64)
    print(f"AgentApprovalDesk 审批审计报告 · 来源：{source}")
    print("=" * 64)
    print(f"审批请求：{report['total_requests']} 条（已决 {report['decided']} 条）"
          f" · 风险分：{report['score']}/100 · 评级：{report['level']}")
    print(f"合规率：{report['compliance_rate']}% · "
          f"SLA（{report['sla_hours']}h 内决断）达成率：{report['sla_met_rate']}%")
    print(f"结论：{report['verdict']}")
    print(f"操作分布：{', '.join(f'{k}×{n}' for k, n in report['by_action'].items())}")
    if report["by_rule"]:
        print(f"违规分类：{', '.join(f'{k}×{n}' for k, n in report['by_rule'].items())}")
    print()
    if not report["findings"]:
        print("未检出审批违规。")
        return
    print(f"检出 {len(report['findings'])} 条违规：")
    for i, f in enumerate(report["findings"], 1):
        print(f"\n[{i}] [{f['level']}] {f['rule']}（+{f['score']} 分）")
        print(f"    {f['detail']}")
    print()
    print("处置建议：高危先冻结涉事 agent 的高危操作、再补审批记录；"
          "中危逐条确认执行影响并收紧审批角色；低危（超时）看是否反复出现。"
          "审计结论只针对这份台账；台账本身若缺记录（如未记 executed_at），"
          "漏检的违规不会出现在这里，先保证台账完整再谈合规率。")


DEMO_LEDGER = [
    {"req_id": "APR-0001", "agent": "ops-agent", "action": "delete_file",
     "tool": "shell", "risk": "high", "requested_by": "agent:ops-agent",
     "approved_by": "alice", "approver_role": "sre-lead", "status": "approved",
     "requested_at": "2026-11-18T09:00:00", "decided_at": "2026-11-18T09:05:00",
     "executed_at": "2026-11-18T09:06:00",
     "approved_params": {"path": "/tmp/cache"}, "executed_params": {"path": "/tmp/cache"},
     "requires_approval": True},
    {"req_id": "APR-0002", "agent": "ops-agent", "action": "exec_shell",
     "tool": "shell", "risk": "critical", "requested_by": "agent:ops-agent",
     "approved_by": None, "approver_role": None,
     "status": "executed_without_approval",
     "requested_at": "2026-11-18T09:10:00", "decided_at": None,
     "executed_at": "2026-11-18T09:11:00",
     "approved_params": {}, "executed_params": {"cmd": "rm -rf /data/tmp"},
     "requires_approval": True},
    {"req_id": "APR-0003", "agent": "data-agent", "action": "send_external",
     "tool": "http", "risk": "high", "requested_by": "bob",
     "approved_by": "bob", "approver_role": "data-owner", "status": "approved",
     "requested_at": "2026-11-18T09:20:00", "decided_at": "2026-11-18T09:25:00",
     "executed_at": "2026-11-18T09:26:00",
     "approved_params": {"url": "https://partner.example.com/report"},
     "executed_params": {"url": "https://partner.example.com/report"},
     "requires_approval": True},
    {"req_id": "APR-0004", "agent": "ops-agent", "action": "modify_config",
     "tool": "config", "risk": "high", "requested_by": "agent:ops-agent",
     "approved_by": "carol", "approver_role": "security-lead", "status": "rejected",
     "requested_at": "2026-11-18T09:30:00", "decided_at": "2026-11-18T09:35:00",
     "executed_at": "2026-11-18T09:40:00",
     "approved_params": {"key": "auth.mode", "value": "strict"},
     "executed_params": {"key": "auth.mode", "value": "none"},
     "requires_approval": True},
    {"req_id": "APR-0005", "agent": "ops-agent", "action": "delete_file",
     "tool": "shell", "risk": "high", "requested_by": "agent:ops-agent",
     "approved_by": "alice", "approver_role": "sre-lead", "status": "approved",
     "requested_at": "2026-11-18T10:00:00", "decided_at": "2026-11-18T10:05:00",
     "executed_at": "2026-11-18T10:06:00",
     "approved_params": {"path": "/tmp/cache"},
     "executed_params": {"path": "/data/prod.db"},
     "requires_approval": True},
    {"req_id": "APR-0006", "agent": "data-agent", "action": "read_secret",
     "tool": "vault", "risk": "critical", "requested_by": "agent:data-agent",
     "approved_by": "dave", "approver_role": "developer", "status": "approved",
     "requested_at": "2026-11-18T10:10:00", "decided_at": "2026-11-18T10:12:00",
     "executed_at": "2026-11-18T10:13:00",
     "approved_params": {"secret": "db/password"},
     "executed_params": {"secret": "db/password"},
     "requires_approval": True},
    {"req_id": "APR-0007", "agent": "ops-agent", "action": "deploy",
     "tool": "ci", "risk": "medium", "requested_by": "agent:ops-agent",
     "approved_by": None, "approver_role": None, "status": "pending",
     "requested_at": "2026-11-16T08:00:00", "decided_at": None,
     "executed_at": None, "approved_params": {}, "executed_params": {},
     "requires_approval": True},
    {"req_id": "APR-0008", "agent": "ops-agent", "action": "rotate_secret",
     "tool": "vault", "risk": "high", "requested_by": "agent:ops-agent",
     "approved_by": "alice", "approver_role": "sre-lead", "status": "approved",
     "requested_at": "2026-11-17T08:00:00", "decided_at": "2026-11-17T08:10:00",
     "executed_at": "2026-11-18T09:00:00",
     "approved_params": {"secret": "api/key-a"},
     "executed_params": {"secret": "api/key-a"},
     "requires_approval": True},
    {"req_id": "APR-0009", "agent": "research-agent", "action": "send_external",
     "tool": "http", "risk": "low", "requested_by": "agent:research-agent",
     "approved_by": "erin", "approver_role": "data-owner", "status": "approved",
     "requested_at": "2026-11-18T11:00:00", "decided_at": "2026-11-18T11:02:00",
     "executed_at": "2026-11-18T11:03:00",
     "approved_params": {"url": "https://docs.example.com/faq"},
     "executed_params": {"url": "https://docs.example.com/faq"},
     "requires_approval": False},
    {"req_id": "APR-0010", "agent": "ops-agent", "action": "exec_shell",
     "tool": "shell", "risk": "medium", "requested_by": "agent:ops-agent",
     "approved_by": "alice", "approver_role": "sre-lead", "status": "approved",
     "requested_at": "2026-11-18T11:10:00", "decided_at": "2026-11-18T11:12:00",
     "executed_at": "2026-11-18T11:13:00",
     "approved_params": {"cmd": "systemctl status app"},
     "executed_params": {"cmd": "systemctl status app"},
     "requires_approval": True},
]


def cmd_demo(args):
    print("AgentApprovalDesk 演示：10 条审批请求，植入 7 类违规")
    print("违规：无审批执行、自批自审、已拒仍执行、批后改参、越权审批、"
          "审批超时、审批过期后执行。")
    print()
    now = datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc)
    report = audit(DEMO_LEDGER, sla_hours=args.sla_hours,
                   ttl_hours=args.ttl_hours, now=now)
    print_report(report, "内置演示台账")
    return 1 if report["score"] >= 70 else 0


def cmd_audit(args):
    if not os.path.exists(args.input):
        print(f"台账文件不存在：{args.input}")
        return 2
    records = load_ledger(args.input)
    if not records:
        print("台账为空或无合法 JSON 行。")
        return 2
    report = audit(records, sla_hours=args.sla_hours, ttl_hours=args.ttl_hours)
    print_report(report, args.input)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print(f"\n报告 JSON 已写入 {args.json}")
    return 1 if report["score"] >= 70 else 0


def main(argv=None):
    p = argparse.ArgumentParser(description="AgentApprovalDesk：智能体人工审批审计台")
    p.add_argument("-i", "--input", default=DEFAULT_INPUT,
                   help="审批台账 JSONL 文件（默认 sample_approvals.jsonl）")
    p.add_argument("--demo", action="store_true", help="演示：审计内置违规台账")
    p.add_argument("--sla-hours", type=float, default=24,
                   help="审批 SLA（小时），默认 24")
    p.add_argument("--ttl-hours", type=float, default=24,
                   help="批准有效期（小时），默认 24")
    p.add_argument("--json", help="把审计报告写成 JSON 文件")
    args = p.parse_args(argv)
    if args.demo:
        return cmd_demo(args)
    return cmd_audit(args)


if __name__ == "__main__":
    sys.exit(main())
