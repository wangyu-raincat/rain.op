# -*- coding: utf-8 -*-
"""AgentApprovalDesk 七组审计规则测试。

运行：python -m pytest tests/ -q
"""
import json
from datetime import datetime, timezone

import approvaldesk as ad

NOW = datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc)


def rec(**kw):
    """一条默认完全合规的审批记录，关键字参数覆盖单个字段。"""
    r = {"req_id": "APR-T1", "agent": "ops-agent", "action": "delete_file",
         "tool": "shell", "risk": "high", "requested_by": "agent:ops-agent",
         "approved_by": "alice", "approver_role": "sre-lead",
         "status": "approved",
         "requested_at": "2026-11-18T09:00:00",
         "decided_at": "2026-11-18T09:05:00",
         "executed_at": "2026-11-18T09:06:00",
         "approved_params": {"path": "/tmp/cache"},
         "executed_params": {"path": "/tmp/cache"},
         "requires_approval": True}
    r.update(kw)
    return r


def rules_of(report):
    return [f["rule"] for f in report["findings"]]


# ---------- 基础工具 ----------

def test_parse_time_variants():
    assert ad.parse_time("2026-11-18T09:00:00Z").tzinfo is not None
    naive = ad.parse_time("2026-11-18T09:00:00")  # 无时区按 UTC 处理
    assert naive.tzinfo == timezone.utc
    assert ad.parse_time("2026-11-18T09:00:00+08:00").utcoffset().total_seconds() == 8 * 3600
    assert ad.parse_time("not-a-time") is None
    assert ad.parse_time("") is None
    assert ad.parse_time(None) is None


def test_params_differ():
    assert ad.params_differ({"a": 1}, {"a": 1}) == {}
    assert ad.params_differ({"a": 1}, {"a": 2}) == {"a": (1, 2)}
    assert "b" in ad.params_differ({"a": 1}, {"a": 1, "b": 3})  # 新增字段
    assert ad.params_differ(None, {"a": 1}) is True              # 非 dict 退化为整体比较
    assert ad.params_differ(None, None) is False


def test_needs_approval():
    assert ad.needs_approval({"requires_approval": True, "action": "deploy",
                              "risk": "low"}) is True
    # 五类高危操作恒需审批，台账标 false 也不豁免
    assert ad.needs_approval({"requires_approval": False,
                              "action": "delete_file", "risk": "low"}) is True
    # 高风险等级也需要审批
    assert ad.needs_approval({"requires_approval": False, "action": "deploy",
                              "risk": "critical"}) is True
    assert ad.needs_approval({"requires_approval": False, "action": "deploy",
                              "risk": "low"}) is False


# ---------- 主流程：合规与空输入 ----------

def test_clean_record_no_findings():
    report = ad.audit([rec()], now=NOW)
    assert report["findings"] == []
    assert report["score"] == 0
    assert report["level"] == "正常"
    assert report["compliance_rate"] == 100.0


def test_audit_empty_records():
    report = ad.audit([], now=NOW)
    assert report["total_requests"] == 0
    assert report["score"] == 0
    assert report["compliance_rate"] == 100.0


# ---------- 七组规则逐条 ----------

def test_no_approval_exec_detected():
    r = rec(status="executed_without_approval", approved_by=None,
            approver_role=None, decided_at=None, action="exec_shell",
            risk="critical")
    assert rules_of(ad.audit([r], now=NOW)) == ["no_approval_exec"]


def test_self_approval_detected():
    r = rec(action="send_external", requested_by="bob", approved_by="bob",
            approver_role="data-owner")
    assert rules_of(ad.audit([r], now=NOW)) == ["self_approval"]


def test_rejected_exec_detected_without_double_count():
    r = rec(action="modify_config", status="rejected", approved_by="carol",
            approver_role="security-lead",
            executed_params={"key": "auth.mode", "value": "none"},
            approved_params={"key": "auth.mode", "value": "strict"})
    # 已拒仍执行只记 rejected_exec，不与 no_approval_exec / param_drift 重复扣分
    assert rules_of(ad.audit([r], now=NOW)) == ["rejected_exec"]


def test_param_drift_detected():
    r = rec(executed_params={"path": "/data/prod.db"})
    assert rules_of(ad.audit([r], now=NOW)) == ["param_drift"]


def test_unauthorized_approver_detected():
    r = rec(action="read_secret", approved_by="dave",
            approver_role="developer", risk="critical")
    assert rules_of(ad.audit([r], now=NOW)) == ["unauthorized_approver"]


def test_approval_timeout_detected_for_pending():
    r = rec(action="deploy", risk="medium", status="pending",
            approved_by=None, approver_role=None, decided_at=None,
            executed_at=None, requested_at="2026-11-16T08:00:00")
    # 2026-11-16 08:00 到 NOW 已等待 52 小时 > SLA 24 小时
    assert rules_of(ad.audit([r], now=NOW)) == ["approval_timeout"]


def test_stale_approval_detected():
    r = rec(action="rotate_secret", approver_role="security-lead",
            requested_at="2026-11-17T08:00:00",
            decided_at="2026-11-17T08:10:00",
            executed_at="2026-11-18T09:00:00")  # 批准 24.8 小时后才执行
    assert rules_of(ad.audit([r], now=NOW)) == ["stale_approval"]


# ---------- 演示台账整体回归 ----------

def test_demo_ledger_report():
    report = ad.audit(ad.DEMO_LEDGER, now=NOW)
    assert report["total_requests"] == 10
    assert report["score"] == 100           # 多条高危违规，封顶 100
    assert report["level"] == "高危"
    assert report["compliance_rate"] == 30.0
    assert report["by_rule"] == {
        "no_approval_exec": 1, "self_approval": 1, "rejected_exec": 1,
        "param_drift": 1, "unauthorized_approver": 2,
        "approval_timeout": 1, "stale_approval": 1,
    }


# ---------- 台账读取 ----------

def test_load_ledger_skips_bad_lines(tmp_path):
    path = tmp_path / "ledger.jsonl"
    path.write_text(
        json.dumps(rec()) + "\n"
        "\n"
        "this is not json\n"
        + json.dumps(rec(req_id="APR-T2")) + "\n",
        encoding="utf-8")
    records = ad.load_ledger(str(path))
    assert len(records) == 2
    assert records[1]["req_id"] == "APR-T2"
