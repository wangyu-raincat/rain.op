# -*- coding: utf-8 -*-
"""FlowScan 核心检测逻辑测试。

运行：python -m pytest tests/ -q
"""
import flowscan


def flow(ts, src="192.168.1.10", dst="10.0.0.5", dport=80, proto="TCP",
         flags="A", sport=12345):
    return {"ts": ts, "src_ip": src, "dst_ip": dst, "src_port": sport,
            "dst_port": dport, "proto": proto, "packets": 1, "bytes": 60,
            "tcp_flags": flags}


# ---------- 基础工具 ----------

def test_is_syn_only():
    assert flowscan.is_syn_only("S") is True
    assert flowscan.is_syn_only("s") is True        # 大小写不敏感
    assert flowscan.is_syn_only("SA") is False      # 完成握手不算半开
    assert flowscan.is_syn_only("A") is False
    assert flowscan.is_syn_only("") is False
    assert flowscan.is_syn_only(None) is False


def test_is_internal():
    assert flowscan.is_internal("192.168.1.10") is True
    assert flowscan.is_internal("10.0.0.5") is True
    assert flowscan.is_internal("8.8.8.8") is False
    assert flowscan.is_internal("not-an-ip") is False


def test_load_flows_skips_bad_rows_and_sorts(tmp_path):
    csv_text = (
        "ts,src_ip,dst_ip,src_port,dst_port,proto,packets,bytes,tcp_flags\n"
        "200,192.168.1.10,10.0.0.5,1234,80,TCP,1,60,A\n"
        "bad,192.168.1.10,10.0.0.5,1234,80,TCP,1,60,A\n"          # 坏时间戳
        "100,192.168.1.11,10.0.0.5,1235,443,TCP,2,120,SA\n"
        ",192.168.1.12,10.0.0.5,1236,80,TCP,1,60,A\n"             # 空时间戳
    )
    path = tmp_path / "flows.csv"
    path.write_text(csv_text, encoding="utf-8")
    flows = flowscan.load_flows(str(path))
    assert len(flows) == 2                       # 坏行被跳过
    assert [f["ts"] for f in flows] == [100, 200]  # 按时间升序
    assert flows[0]["dst_port"] == 443


# ---------- 端口扫描 ----------

def test_detect_port_scan_positive():
    flows = [flow(ts=i, src="192.168.1.50", dport=1000 + i, flags="S")
             for i in range(20)]
    alerts = flowscan.detect_port_scan(flows)
    assert len(alerts) == 1
    assert alerts[0]["type"] == "port_scan"
    assert alerts[0]["severity"] == "high"
    assert alerts[0]["evidence"]["ports"] == 20


def test_detect_port_scan_below_threshold():
    flows = [flow(ts=i, src="192.168.1.50", dport=1000 + i, flags="S")
             for i in range(10)]  # 10 个端口 < 阈值 15
    assert flowscan.detect_port_scan(flows) == []


def test_detect_port_scan_ignores_udp():
    flows = [flow(ts=i, src="192.168.1.50", dport=1000 + i, proto="UDP",
                  flags="") for i in range(30)]
    assert flowscan.detect_port_scan(flows) == []


# ---------- SYN Flood ----------

def test_detect_syn_flood_positive():
    # 120 个纯 SYN 包挤在 60 秒内（每秒 2 个）
    flows = [flow(ts=i // 2, src="192.168.1.60", flags="S")
             for i in range(120)]
    alerts = flowscan.detect_syn_flood(flows)
    assert len(alerts) == 1
    assert alerts[0]["type"] == "syn_flood"
    assert alerts[0]["evidence"]["syn_count"] == 120


def test_detect_syn_flood_ignores_completed_handshakes():
    flows = [flow(ts=i // 2, src="192.168.1.60", flags="SA")
             for i in range(120)]
    assert flowscan.detect_syn_flood(flows) == []


# ---------- Beaconing ----------

def test_detect_beaconing_positive():
    flows = [flow(ts=i * 120, src="192.168.1.70", dst="45.155.204.9",
                  dport=443) for i in range(10)]
    alerts = flowscan.detect_beaconing(flows)
    assert len(alerts) == 1
    assert alerts[0]["type"] == "beaconing"
    assert alerts[0]["evidence"]["connections"] == 10
    assert alerts[0]["evidence"]["interval_mean"] == 120.0
    assert alerts[0]["evidence"]["interval_cv"] == 0.0


def test_detect_beaconing_irregular_intervals_no_alert():
    tss = [0, 30, 200, 260, 700, 760, 1500, 1560, 2400, 2500]  # 间隔杂乱
    flows = [flow(ts=t, src="192.168.1.70", dst="45.155.204.9", dport=443)
             for t in tss]
    assert flowscan.detect_beaconing(flows) == []


def test_detect_beaconing_requires_internal_source():
    # 规律外联但源不是内网主机，不属于“内网 Beacon”
    flows = [flow(ts=i * 120, src="8.8.8.8", dst="45.155.204.9", dport=443)
             for i in range(10)]
    assert flowscan.detect_beaconing(flows) == []


def test_detect_beaconing_too_few_connections():
    flows = [flow(ts=i * 120, src="192.168.1.70", dst="45.155.204.9",
                  dport=443) for i in range(4)]  # 少于 min_beacons+1
    assert flowscan.detect_beaconing(flows) == []


# ---------- 主流程 ----------

def test_analyze_empty_input():
    assert flowscan.analyze([]) == []


def test_analyze_demo_sample_finds_all_three_attacks():
    import gen_sample
    flows = gen_sample.generate()
    alerts = flowscan.analyze(flows)
    assert [a["type"] for a in alerts] == ["port_scan", "syn_flood",
                                           "beaconing"]
    # 高危排在中危前面
    assert alerts[0]["severity"] == "high"
    assert alerts[-1]["severity"] == "medium"
