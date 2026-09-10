import pytest
import time
from backend.ingest.models import FlowRecord
from backend.ingest.sliding_window import SlidingWindowAggregator


def test_ddos_metrics_calculation():
    agg = SlidingWindowAggregator(window_seconds=5.0)
    
    # Ingest 20 SYN-heavy flows
    for i in range(20):
        flow = FlowRecord(
            src_ip=f"192.168.1.{i % 5}",
            src_port=1000 + i,
            dst_ip="10.0.0.1",
            dst_port=443,
            tcp_flags={"SYN": 10, "ACK": 1, "FIN": 0, "RST": 0, "PSH": 0}
        )
        agg.add_flow(flow)

    metrics = agg.compute_ddos_metrics()
    assert metrics["total_window_flows"] == 20
    assert metrics["syn_ack_ratio"] > 5.0
    assert metrics["src_ip_entropy"] > 0.0


def test_beaconing_metrics_calculation():
    agg = SlidingWindowAggregator(window_seconds=60.0)
    now = time.time()
    
    # Ingest 10 flows with very regular 2.0s intervals to target C2 IP
    target_ip = "198.51.100.50"
    for i in range(10):
        t = now - ((10 - i) * 2.0)
        flow = FlowRecord(
            src_ip="10.0.0.5",
            src_port=4444,
            dst_ip=target_ip,
            dst_port=8443
        )
        agg.add_flow(flow, current_time=t)

    beacon = agg.compute_beaconing_metrics(target_ip)
    assert beacon["sample_count"] == 10
    assert beacon["iat_variance"] < 0.01
    assert beacon["periodicity_score"] > 0.70


def test_dns_metrics_entropy_and_dga():
    # Normal query
    normal_metrics = SlidingWindowAggregator.compute_dns_metrics("api.github.com", "A")
    assert normal_metrics["char_entropy"] < 3.8
    assert normal_metrics["vowel_ratio"] > 0.25

    # DGA query
    dga_query = "k9x8q2z1m4b7v9p3l8w2.exfil.cc"
    dga_metrics = SlidingWindowAggregator.compute_dns_metrics(dga_query, "TXT")
    assert dga_metrics["char_entropy"] > 3.8
    assert dga_metrics["is_txt_null_anomaly"] == 1.0


def test_recon_scan_cardinality():
    agg = SlidingWindowAggregator(window_seconds=10.0)
    scanner_ip = "185.220.101.5"
    
    # Scanner contacts 25 different ports
    for port in range(100, 125):
        flow = FlowRecord(
            src_ip=scanner_ip,
            src_port=50000,
            dst_ip="192.168.1.100",
            dst_port=port,
            tcp_flags={"SYN": 1, "ACK": 0}
        )
        agg.add_flow(flow)

    scan_metrics = agg.compute_recon_scan_metrics(scanner_ip)
    assert scan_metrics["unique_dst_ports_10s"] == 25
    assert scan_metrics["fanout_cardinality"] >= 25


def test_data_exfiltration_asymmetry():
    flow = FlowRecord(
        src_ip="10.0.0.12",
        src_port=52000,
        dst_ip="203.0.113.88",
        dst_port=443,
        bytes_sent=5_000_000,  # 5 MB upload
        bytes_recv=12_000,     # 12 KB download
        packets_sent=3500,
        packets_recv=100
    )
    exfil = SlidingWindowAggregator.compute_exfiltration_metrics(flow)
    assert exfil["byte_asymmetry_ratio"] > 400.0
