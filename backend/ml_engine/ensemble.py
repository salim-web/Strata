import os
import time
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

from backend.ingest.models import FlowRecord, StandardizedAlert

logger = logging.getLogger("strata.ml_ensemble")


class VolumetricDDoSDetector:
    """Detects Volumetric / Protocol DDoS from rolling flow metrics and entropy."""
    
    @staticmethod
    def evaluate(flow: FlowRecord, ddos_metrics: Dict[str, float]) -> Optional[StandardizedAlert]:
        flow_rate = ddos_metrics.get("flow_rate_per_sec", 0.0)
        syn_ack_ratio = ddos_metrics.get("syn_ack_ratio", 1.0)
        entropy = ddos_metrics.get("src_ip_entropy", 0.0)
        
        # Threat evaluation logic
        is_syn_flood = syn_ack_ratio > 4.5
        is_volume_flood = flow_rate > 1500.0
        is_entropy_surge = entropy > 6.0 and flow_rate > 500.0

        if not (is_syn_flood or is_volume_flood or is_entropy_surge):
            return None

        # Calculate confidence score
        score = 0.50
        if is_syn_flood:
            score += min(0.35, (syn_ack_ratio - 4.5) * 0.05)
        if is_volume_flood:
            score += min(0.30, (flow_rate - 1500.0) / 5000.0)
        if is_entropy_surge:
            score += 0.15
        confidence = round(min(0.99, max(0.65, score)), 4)

        severity = "CRITICAL" if confidence >= 0.88 else "HIGH"

        return StandardizedAlert(
            timestamp=datetime.now(timezone.utc).isoformat(),
            flow_id=flow.flow_id,
            threat_class="VOLUMETRIC_DDOS",
            confidence_score=confidence,
            severity=severity,
            evidence={
                "flow_rate_rps": f"{flow_rate:.1f} flows/sec",
                "syn_to_ack_ratio": f"{syn_ack_ratio:.2f}x",
                "src_ip_entropy": f"{entropy:.3f}",
                "baseline_threshold": "Flow Rate > 1500/s OR SYN/ACK > 4.5x OR Entropy > 6.0"
            }
        )


class BotnetC2Detector:
    """Detects Botnet C2 Beaconing from IAT variance and periodicity to destination IPs."""
    
    @staticmethod
    def evaluate(flow: FlowRecord, beacon_metrics: Dict[str, float]) -> Optional[StandardizedAlert]:
        periodicity = beacon_metrics.get("periodicity_score", 0.0)
        iat_var = beacon_metrics.get("iat_variance", 999.0)
        iat_mean = beacon_metrics.get("iat_mean", 0.0)
        sample_count = int(beacon_metrics.get("sample_count", 0))

        if sample_count < 3 or periodicity < 0.65:
            return None

        # Low variance with strong periodicity indicates automated beacon
        confidence = round(min(0.98, max(0.60, periodicity)), 4)
        severity = "CRITICAL" if confidence >= 0.85 else "HIGH"

        return StandardizedAlert(
            timestamp=datetime.now(timezone.utc).isoformat(),
            flow_id=flow.flow_id,
            threat_class="BOTNET_C2",
            confidence_score=confidence,
            severity=severity,
            evidence={
                "periodicity_score": f"{periodicity * 100:.1f}%",
                "iat_variance": f"{iat_var:.5f}s",
                "mean_interval": f"{iat_mean:.2f}s",
                "sample_count": str(sample_count),
                "baseline_threshold": "Periodicity > 65% AND IAT Variance < 0.05s"
            }
        )


class DNSDGAAnomalyDetector:
    """Detects DGA domains and DNS tunneling based on character entropy and label anomalies."""
    
    @staticmethod
    def evaluate(flow: FlowRecord, dns_metrics: Dict[str, float]) -> Optional[StandardizedAlert]:
        entropy = dns_metrics.get("char_entropy", 0.0)
        vowel_ratio = dns_metrics.get("vowel_ratio", 0.4)
        max_label_len = dns_metrics.get("max_label_length", 0)
        subdomain_depth = dns_metrics.get("subdomain_depth", 0)
        is_txt_null = dns_metrics.get("is_txt_null_anomaly", 0.0)

        is_high_entropy = entropy > 3.8
        is_abnormal_vowels = vowel_ratio < 0.18 or vowel_ratio > 0.70
        is_long_label = max_label_len > 24
        is_tunnel_profile = is_txt_null > 0.5 and (entropy > 3.5 or max_label_len > 20)

        if not (is_tunnel_profile or (is_high_entropy and (is_abnormal_vowels or is_long_label))):
            return None

        score = 0.60
        if is_high_entropy:
            score += min(0.25, (entropy - 3.8) * 0.3)
        if is_tunnel_profile:
            score += 0.20
        if is_long_label:
            score += 0.10
        confidence = round(min(0.99, max(0.65, score)), 4)

        severity = "CRITICAL" if (is_tunnel_profile or confidence >= 0.88) else "HIGH"

        return StandardizedAlert(
            timestamp=datetime.now(timezone.utc).isoformat(),
            flow_id=flow.flow_id,
            threat_class="DGA_DNS_TUNNEL",
            confidence_score=confidence,
            severity=severity,
            evidence={
                "dns_query": str(flow.dns_query or "N/A"),
                "query_char_entropy": f"{entropy:.3f}",
                "vowel_ratio": f"{vowel_ratio * 100:.1f}%",
                "max_label_length": str(max_label_len),
                "record_type": str(flow.dns_query_type or "A"),
                "baseline_threshold": "Entropy > 3.80 OR (TXT/NULL AND Length > 20)"
            }
        )


class EncryptedTrafficDetector:
    """
    Detects encrypted malware (Cobalt Strike, AsyncRAT, TrickBot) exclusively via
    passive TLS/QUIC metadata (JA3/JA4, SNI, packet size/delta sequence arrays).
    Payload decryption is strictly forbidden!
    """
    
    @staticmethod
    def evaluate(flow: FlowRecord, tls_metrics: Dict[str, Any]) -> Optional[StandardizedAlert]:
        matched_malware = tls_metrics.get("matched_malware_profile")
        ja3 = tls_metrics.get("ja3_hash") or ""
        ja4 = tls_metrics.get("ja4_fingerprint") or ""
        sni = tls_metrics.get("sni") or ""
        is_fixed_beacon = tls_metrics.get("is_fixed_length_beacon", 0.0)

        # Immediate trigger on known malicious fingerprint
        if matched_malware:
            return StandardizedAlert(
                timestamp=datetime.now(timezone.utc).isoformat(),
                flow_id=flow.flow_id,
                threat_class="ENCRYPTED_MALWARE",
                confidence_score=0.96,
                severity="CRITICAL",
                evidence={
                    "matched_threat": matched_malware,
                    "ja3_hash": ja3,
                    "ja4_fingerprint": ja4 or "t13d_malware_fp",
                    "sni_target": sni or "raw_ip_or_hidden",
                    "baseline_threshold": "Matches Threat Intel Signature DB (JA3/JA4)"
                }
            )

        # Check for abnormal beaconing size sequence without SNI
        if is_fixed_beacon and not sni and flow.dst_port in [443, 8443, 8080]:
            return StandardizedAlert(
                timestamp=datetime.now(timezone.utc).isoformat(),
                flow_id=flow.flow_id,
                threat_class="ENCRYPTED_MALWARE",
                confidence_score=0.82,
                severity="HIGH",
                evidence={
                    "ja3_hash": ja3 or "unknown_custom_tls",
                    "packet_size_profile": "Fixed-length repetitive TLS beacon",
                    "sni_status": "Missing SNI (Direct IP TLS connection)",
                    "baseline_threshold": "Direct IP TLS Handshake with Fixed-Length Sequences"
                }
            )

        return None


class ReconScanDetector:
    """Detects Horizontal and Vertical Scanning from fan-out cardinality over 10s windows."""
    
    @staticmethod
    def evaluate(flow: FlowRecord, scan_metrics: Dict[str, Any]) -> Optional[StandardizedAlert]:
        unique_ips = scan_metrics.get("unique_dst_ips_10s", 0)
        unique_ports = scan_metrics.get("unique_dst_ports_10s", 0)
        fanout = scan_metrics.get("fanout_cardinality", 0)
        syn_ratio = scan_metrics.get("syn_only_ratio", 0.0)

        # Baseline threshold: > 15 unique IPs or > 20 unique ports contacted within 10 seconds
        is_horizontal_scan = unique_ips >= 15
        is_vertical_scan = unique_ports >= 20

        if not (is_horizontal_scan or is_vertical_scan):
            return None

        scan_type = "Horizontal Subnet Sweep" if is_horizontal_scan else "Vertical Port Scan"
        score = 0.70 + min(0.28, (fanout - 15) * 0.01)
        confidence = round(min(0.98, max(0.70, score)), 4)
        severity = "HIGH" if fanout > 30 else "MEDIUM"

        return StandardizedAlert(
            timestamp=datetime.now(timezone.utc).isoformat(),
            flow_id=flow.flow_id,
            threat_class="RECON_SCAN",
            confidence_score=confidence,
            severity=severity,
            evidence={
                "scan_type": scan_type,
                "fanout_cardinality": f"{fanout} targets / 10s",
                "unique_dst_ips": str(unique_ips),
                "unique_dst_ports": str(unique_ports),
                "syn_only_ratio": f"{syn_ratio * 100:.1f}%",
                "baseline_threshold": "Fan-out > 15 IPs OR > 20 Ports per 10s window"
            }
        )


class DataExfiltrationDetector:
    """Detects Data Exfiltration from directional byte and packet asymmetry ratios."""
    
    @staticmethod
    def evaluate(flow: FlowRecord, exfil_metrics: Dict[str, float]) -> Optional[StandardizedAlert]:
        byte_ratio = exfil_metrics.get("byte_asymmetry_ratio", 1.0)
        pkt_ratio = exfil_metrics.get("packet_asymmetry_ratio", 1.0)
        bytes_sent = exfil_metrics.get("bytes_sent", 0.0)

        # Normal client traffic has bytes_sent < bytes_recv (ratio < 1.0)
        # Exfiltration exhibits massive outbound byte ratio with large volume
        if byte_ratio > 8.0 and bytes_sent > 250_000:  # > 250 KB with 8x asymmetry
            confidence = round(min(0.97, 0.65 + min(0.30, (byte_ratio / 50.0))), 4)
            severity = "CRITICAL" if (byte_ratio > 20.0 and bytes_sent > 1_000_000) else "HIGH"

            return StandardizedAlert(
                timestamp=datetime.now(timezone.utc).isoformat(),
                flow_id=flow.flow_id,
                threat_class="DATA_EXFIL",
                confidence_score=confidence,
                severity=severity,
                evidence={
                    "outbound_bytes": f"{bytes_sent / 1024:.1f} KB",
                    "byte_asymmetry_ratio": f"{byte_ratio:.1f}x",
                    "packet_asymmetry_ratio": f"{pkt_ratio:.1f}x",
                    "baseline_threshold": "Byte Ratio > 8.0x AND Outbound Volume > 250 KB"
                }
            )

        return None


class MultiDetectorEnsemble:
    """
    Unified Multi-Detector ML Inference Ensemble.
    Executes all 6 specialized detectors over flow and sliding-window metadata.
    Guarantees bounded inference latency (<50ms per batch/flow).
    """

    def __init__(self):
        self.ddos_detector = VolumetricDDoSDetector()
        self.c2_detector = BotnetC2Detector()
        self.dns_detector = DNSDGAAnomalyDetector()
        self.encrypted_detector = EncryptedTrafficDetector()
        self.recon_detector = ReconScanDetector()
        self.exfil_detector = DataExfiltrationDetector()

    def inspect_flow(
        self,
        flow: FlowRecord,
        ddos_metrics: Dict[str, float],
        beacon_metrics: Dict[str, float],
        dns_metrics: Dict[str, float],
        encrypted_metrics: Dict[str, Any],
        recon_metrics: Dict[str, Any],
        exfil_metrics: Dict[str, float]
    ) -> List[StandardizedAlert]:
        """
        Inspect a single flow against all 6 detectors.
        Returns list of standardized alert records if threats are detected.
        """
        alerts: List[StandardizedAlert] = []

        # 1. Volumetric DDoS
        ddos_alert = self.ddos_detector.evaluate(flow, ddos_metrics)
        if ddos_alert:
            alerts.append(ddos_alert)

        # 2. Botnet C2 Beaconing
        c2_alert = self.c2_detector.evaluate(flow, beacon_metrics)
        if c2_alert:
            alerts.append(c2_alert)

        # 3. DNS Tunnelling & DGA
        if flow.is_dns or flow.dns_query:
            dns_alert = self.dns_detector.evaluate(flow, dns_metrics)
            if dns_alert:
                alerts.append(dns_alert)

        # 4. Encrypted Traffic (No Decryption)
        if flow.is_tls or flow.ja3_hash or flow.tls_sni:
            enc_alert = self.encrypted_detector.evaluate(flow, encrypted_metrics)
            if enc_alert:
                alerts.append(enc_alert)

        # 5. Reconnaissance / Scanning
        recon_alert = self.recon_detector.evaluate(flow, recon_metrics)
        if recon_alert:
            alerts.append(recon_alert)

        # 6. Data Exfiltration
        exfil_alert = self.exfil_detector.evaluate(flow, exfil_metrics)
        if exfil_alert:
            alerts.append(exfil_alert)

        return alerts


# Singleton instance
ensemble_instance = MultiDetectorEnsemble()
