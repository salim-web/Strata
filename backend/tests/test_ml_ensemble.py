import pytest
import time
from backend.ingest.models import FlowRecord
from backend.ml_engine.ensemble import ensemble_instance


def test_ensemble_detects_all_threat_classes():
    # 1. DDoS Flow
    ddos_flow = FlowRecord(
        src_ip="192.168.1.50", src_port=1234, dst_ip="10.0.0.1", dst_port=443
    )
    ddos_metrics = {
        "flow_rate_per_sec": 3500.0,
        "syn_ack_ratio": 12.5,
        "src_ip_entropy": 7.2
    }
    alerts = ensemble_instance.inspect_flow(
        flow=ddos_flow,
        ddos_metrics=ddos_metrics,
        beacon_metrics={},
        dns_metrics={},
        encrypted_metrics={},
        recon_metrics={},
        exfil_metrics={}
    )
    assert any(a.threat_class == "VOLUMETRIC_DDOS" for a in alerts)
    ddos_alert = next(a for a in alerts if a.threat_class == "VOLUMETRIC_DDOS")
    assert ddos_alert.confidence_score >= 0.70
    assert ddos_alert.severity in ["HIGH", "CRITICAL"]
    assert "flow_rate_rps" in ddos_alert.evidence

    # 2. C2 Beacon Flow
    c2_flow = FlowRecord(
        src_ip="10.0.0.8", src_port=49152, dst_ip="198.51.100.99", dst_port=8443
    )
    c2_metrics = {
        "periodicity_score": 0.95,
        "iat_variance": 0.001,
        "iat_mean": 5.0,
        "sample_count": 8
    }
    alerts = ensemble_instance.inspect_flow(
        flow=c2_flow,
        ddos_metrics={},
        beacon_metrics=c2_metrics,
        dns_metrics={},
        encrypted_metrics={},
        recon_metrics={},
        exfil_metrics={}
    )
    assert any(a.threat_class == "BOTNET_C2" for a in alerts)

    # 3. DGA / DNS Tunnel
    dns_flow = FlowRecord(
        src_ip="10.0.0.9", src_port=5312, dst_ip="8.8.8.8", dst_port=53,
        is_dns=True, dns_query="k9x8q2z1m4b7v9p3l8w2.exfil.cc", dns_query_type="TXT"
    )
    dns_metrics = {
        "char_entropy": 4.25,
        "vowel_ratio": 0.15,
        "max_label_length": 26,
        "subdomain_depth": 3,
        "is_txt_null_anomaly": 1.0
    }
    alerts = ensemble_instance.inspect_flow(
        flow=dns_flow,
        ddos_metrics={},
        beacon_metrics={},
        dns_metrics=dns_metrics,
        encrypted_metrics={},
        recon_metrics={},
        exfil_metrics={}
    )
    assert any(a.threat_class == "DGA_DNS_TUNNEL" for a in alerts)

    # 4. Encrypted Malware
    enc_flow = FlowRecord(
        src_ip="10.0.0.10", src_port=54000, dst_ip="203.0.113.5", dst_port=443,
        is_tls=True, ja3_hash="e7d705a39f6c0a54e601275bfbb0a221"
    )
    enc_metrics = {
        "matched_malware_profile": "AsyncRAT C2 Client",
        "ja3_hash": "e7d705a39f6c0a54e601275bfbb0a221",
        "ja4_fingerprint": "t13d1516h2_c2_botnet_pulse",
        "sni": "sync-service.dynamic-dns.net"
    }
    alerts = ensemble_instance.inspect_flow(
        flow=enc_flow,
        ddos_metrics={},
        beacon_metrics={},
        dns_metrics={},
        encrypted_metrics=enc_metrics,
        recon_metrics={},
        exfil_metrics={}
    )
    assert any(a.threat_class == "ENCRYPTED_MALWARE" for a in alerts)

    # 5. Recon Scan
    scan_flow = FlowRecord(
        src_ip="192.0.2.10", src_port=44444, dst_ip="10.0.1.20", dst_port=22
    )
    scan_metrics = {
        "unique_dst_ips_10s": 5,
        "unique_dst_ports_10s": 35,
        "fanout_cardinality": 35,
        "syn_only_ratio": 0.95
    }
    alerts = ensemble_instance.inspect_flow(
        flow=scan_flow,
        ddos_metrics={},
        beacon_metrics={},
        dns_metrics={},
        encrypted_metrics={},
        recon_metrics=scan_metrics,
        exfil_metrics={}
    )
    assert any(a.threat_class == "RECON_SCAN" for a in alerts)

    # 6. Data Exfiltration
    exfil_flow = FlowRecord(
        src_ip="10.0.0.15", src_port=55555, dst_ip="198.51.100.22", dst_port=443,
        bytes_sent=2_500_000, bytes_recv=5_000
    )
    exfil_metrics = {
        "byte_asymmetry_ratio": 500.0,
        "packet_asymmetry_ratio": 25.0,
        "bytes_sent": 2_500_000
    }
    alerts = ensemble_instance.inspect_flow(
        flow=exfil_flow,
        ddos_metrics={},
        beacon_metrics={},
        dns_metrics={},
        encrypted_metrics={},
        recon_metrics={},
        exfil_metrics=exfil_metrics
    )
    assert any(a.threat_class == "DATA_EXFIL" for a in alerts)


def test_ensemble_bounded_latency_sla():
    """Verify that ensemble evaluates batch of 500 flows well under 50ms."""
    flow = FlowRecord(
        src_ip="192.168.1.1", src_port=1234, dst_ip="10.0.0.1", dst_port=443
    )
    metrics = {
        "flow_rate_per_sec": 50.0, "syn_ack_ratio": 1.0, "src_ip_entropy": 2.0
    }

    t0 = time.perf_counter()
    for _ in range(500):
        ensemble_instance.inspect_flow(
            flow=flow,
            ddos_metrics=metrics,
            beacon_metrics={"periodicity_score": 0.1, "iat_variance": 5.0, "sample_count": 5},
            dns_metrics={"char_entropy": 2.5, "vowel_ratio": 0.4},
            encrypted_metrics={"ja3_hash": "clean", "matched_malware_profile": None},
            recon_metrics={"fanout_cardinality": 2},
            exfil_metrics={"byte_asymmetry_ratio": 0.5, "bytes_sent": 1000}
        )
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    print(f"\nTime for 500 flow inspections: {elapsed_ms:.2f} ms")
    assert elapsed_ms < 50.0, f"Latency {elapsed_ms}ms exceeded SLA of 50ms!"
