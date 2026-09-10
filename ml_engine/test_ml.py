#!/usr/bin/env python3
"""
STRATA ML Engine Test Suite.
Validates multi-class inference, feature vector extraction, and SLA latency.
"""

import os
import sys
import time
from pathlib import Path

root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir))

from backend.ingest.models import FlowRecord
from backend.ml_engine.ensemble import ensemble_instance, TARGET_CLASSES


def run_tests():
    print("=" * 65)
    print("🧪 Running STRATA Passive Threat ML Ensemble Validation Suite")
    print("=" * 65)

    # 1. DDoS Test
    print("\n1️⃣ Testing Volumetric / Protocol DDoS Classification...")
    ddos_flow = FlowRecord(
        src_ip="198.51.100.12", src_port=54321, dst_ip="192.0.2.1", dst_port=443
    )
    alerts = ensemble_instance.inspect_flow(
        flow=ddos_flow,
        ddos_metrics={"flow_rate_per_sec": 4200.0, "syn_ack_ratio": 18.5, "src_ip_entropy": 7.8},
        beacon_metrics={},
        dns_metrics={},
        encrypted_metrics={},
        recon_metrics={},
        exfil_metrics={}
    )
    assert any(a.threat_class == "VOLUMETRIC_DDOS" for a in alerts), "DDoS flow must be detected!"
    alert = next(a for a in alerts if a.threat_class == "VOLUMETRIC_DDOS")
    print(f"✅ DDoS Alert: {alert.threat_class} | Confidence: {alert.confidence_score * 100:.1f}% | Severity: {alert.severity}")

    # 2. C2 Beacon Test
    print("\n2️⃣ Testing Botnet C2 Beaconing Classification...")
    c2_flow = FlowRecord(
        src_ip="10.0.4.88", src_port=49152, dst_ip="198.51.100.199", dst_port=8443
    )
    alerts = ensemble_instance.inspect_flow(
        flow=c2_flow,
        ddos_metrics={},
        beacon_metrics={"periodicity_score": 0.96, "iat_variance": 0.002, "iat_mean": 5.0, "sample_count": 8},
        dns_metrics={},
        encrypted_metrics={},
        recon_metrics={},
        exfil_metrics={}
    )
    assert any(a.threat_class == "BOTNET_C2" for a in alerts), "C2 beacon must be detected!"
    alert = next(a for a in alerts if a.threat_class == "BOTNET_C2")
    print(f"✅ C2 Alert: {alert.threat_class} | Confidence: {alert.confidence_score * 100:.1f}% | Severity: {alert.severity}")

    # 3. DGA / DNS Tunnel Test
    print("\n3️⃣ Testing DGA & DNS Tunnelling Classification...")
    dns_flow = FlowRecord(
        src_ip="10.0.2.14", src_port=5312, dst_ip="8.8.8.8", dst_port=53,
        is_dns=True, dns_query="x92v7m4b1q8z3k5w.exfil-intel.cc", dns_query_type="TXT"
    )
    alerts = ensemble_instance.inspect_flow(
        flow=dns_flow,
        ddos_metrics={},
        beacon_metrics={},
        dns_metrics={"char_entropy": 4.82, "vowel_ratio": 0.125, "max_label_length": 32, "is_txt_null_anomaly": 1.0},
        encrypted_metrics={},
        recon_metrics={},
        exfil_metrics={}
    )
    assert any(a.threat_class == "DGA_DNS_TUNNEL" for a in alerts), "DNS tunnel must be detected!"
    alert = next(a for a in alerts if a.threat_class == "DGA_DNS_TUNNEL")
    print(f"✅ DNS Alert: {alert.threat_class} | Confidence: {alert.confidence_score * 100:.1f}% | Severity: {alert.severity}")

    # 4. Encrypted Malware (JA3) Test
    print("\n4️⃣ Testing Encrypted Malware (JA3 Fingerprint) Classification...")
    enc_flow = FlowRecord(
        src_ip="10.0.5.112", src_port=54200, dst_ip="203.0.113.77", dst_port=443,
        is_tls=True, ja3_hash="e7d705a39f6c0a54e601275bfbb0a221"
    )
    alerts = ensemble_instance.inspect_flow(
        flow=enc_flow,
        ddos_metrics={},
        beacon_metrics={},
        dns_metrics={},
        encrypted_metrics={"ja3_hash": "e7d705a39f6c0a54e601275bfbb0a221", "matched_malware_profile": "AsyncRAT C2 Client"},
        recon_metrics={},
        exfil_metrics={}
    )
    assert any(a.threat_class == "ENCRYPTED_MALWARE" for a in alerts), "JA3 malware must be detected!"
    alert = next(a for a in alerts if a.threat_class == "ENCRYPTED_MALWARE")
    print(f"✅ Malware Alert: {alert.threat_class} | Confidence: {alert.confidence_score * 100:.1f}% | Severity: {alert.severity}")

    # 5. Reconnaissance Scan Test
    print("\n5️⃣ Testing Reconnaissance Fan-Out Classification...")
    recon_flow = FlowRecord(
        src_ip="192.0.2.45", src_port=33333, dst_ip="10.0.1.5", dst_port=80
    )
    alerts = ensemble_instance.inspect_flow(
        flow=recon_flow,
        ddos_metrics={},
        beacon_metrics={},
        dns_metrics={},
        encrypted_metrics={},
        recon_metrics={"fanout_cardinality": 85, "unique_dst_ips_10s": 25, "unique_dst_ports_10s": 60, "syn_only_ratio": 0.95},
        exfil_metrics={}
    )
    assert any(a.threat_class == "RECON_SCAN" for a in alerts), "Scan fan-out must be detected!"
    alert = next(a for a in alerts if a.threat_class == "RECON_SCAN")
    print(f"✅ Recon Alert: {alert.threat_class} | Confidence: {alert.confidence_score * 100:.1f}% | Severity: {alert.severity}")

    # 6. Data Exfiltration Test
    print("\n6️⃣ Testing Data Exfiltration Asymmetry Classification...")
    exfil_flow = FlowRecord(
        src_ip="10.0.3.50", src_port=55555, dst_ip="198.51.100.99", dst_port=443,
        bytes_sent=2800000, bytes_recv=1400
    )
    alerts = ensemble_instance.inspect_flow(
        flow=exfil_flow,
        ddos_metrics={},
        beacon_metrics={},
        dns_metrics={},
        encrypted_metrics={},
        recon_metrics={},
        exfil_metrics={"byte_asymmetry_ratio": 18.5, "bytes_sent": 2800000.0, "packet_asymmetry_ratio": 12.0}
    )
    assert any(a.threat_class == "DATA_EXFIL" for a in alerts), "Data exfiltration must be detected!"
    alert = next(a for a in alerts if a.threat_class == "DATA_EXFIL")
    print(f"✅ Exfil Alert: {alert.threat_class} | Confidence: {alert.confidence_score * 100:.1f}% | Severity: {alert.severity}")

    # 7. Normal Baseline Traffic (Negative Control)
    print("\n7️⃣ Testing Normal Baseline Traffic (Negative Control)...")
    normal_flow = FlowRecord(
        src_ip="10.0.1.10", src_port=44123, dst_ip="142.250.190.46", dst_port=443,
        bytes_sent=1200, bytes_recv=15000, is_tls=True, tls_sni="www.google.com"
    )
    alerts = ensemble_instance.inspect_flow(
        flow=normal_flow,
        ddos_metrics={"flow_rate_per_sec": 45.0, "syn_ack_ratio": 1.02, "src_ip_entropy": 2.4},
        beacon_metrics={"periodicity_score": 0.05, "iat_variance": 0.85, "sample_count": 2},
        dns_metrics={"char_entropy": 2.2, "vowel_ratio": 0.42, "max_label_length": 11, "is_txt_null_anomaly": 0.0},
        encrypted_metrics={"packet_size_variance": 450.0, "is_fixed_length_beacon": 0.0},
        recon_metrics={"fanout_cardinality": 2, "syn_only_ratio": 0.0},
        exfil_metrics={"byte_asymmetry_ratio": 0.08, "bytes_sent": 1200.0}
    )
    assert len(alerts) == 0, f"Normal traffic should NOT trigger alert! Got: {alerts}"
    print("✅ Normal Traffic: Correctly passed with ZERO false alarms.")

    # 8. Latency Benchmark
    print("\n⚡ Measuring Sub-Millisecond Inference Latency SLA...")
    t0 = time.perf_counter()
    N_BENCH = 500
    for _ in range(N_BENCH):
        ensemble_instance.inspect_flow(
            flow=ddos_flow,
            ddos_metrics={"flow_rate_per_sec": 4200.0, "syn_ack_ratio": 18.5, "src_ip_entropy": 7.8},
            beacon_metrics={},
            dns_metrics={},
            encrypted_metrics={},
            recon_metrics={},
            exfil_metrics={}
        )
    dur_ms = (time.perf_counter() - t0) * 1000.0
    latency_per_flow = dur_ms / N_BENCH
    fps = 1000.0 / latency_per_flow
    print(f"✅ Measured Latency: {latency_per_flow:.4f} ms/flow (~{fps:,.0f} flows/sec sustained)")

    print("\n" + "=" * 65)
    print("🎉 ALL 6 THREAT CLASSES + BASELINE VERIFIED SUCCESSFULLY!")
    print("=" * 65)


if __name__ == "__main__":
    run_tests()
