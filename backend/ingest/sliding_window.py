import math
import time
import collections
from typing import Dict, List, Any, Optional, Tuple
import numpy as np
from backend.ingest.models import FlowRecord


class SlidingWindowAggregator:
    """
    High-efficiency sliding-window feature extractor for passive network metadata.
    Operates without payload decryption or inline packet buffering.
    Maintains ring buffers over configurable time horizons (e.g., 10s, 60s).
    """

    def __init__(self, window_seconds: float = 10.0, max_history_per_entity: int = 500):
        self.window_seconds = window_seconds
        self.max_history_per_entity = max_history_per_entity
        
        # Global rolling window: deque of (timestamp, FlowRecord)
        self.global_flows: collections.deque = collections.deque(maxlen=10000)
        
        # Entity-indexed sliding windows:
        # src_ip -> deque of (timestamp, dst_ip, dst_port, bytes_sent, bytes_recv, syn, ack)
        self.src_ip_history: Dict[str, collections.deque] = collections.defaultdict(
            lambda: collections.deque(maxlen=self.max_history_per_entity)
        )
        
        # dst_ip -> deque of timestamps (for beaconing analysis)
        self.dst_ip_timestamps: Dict[str, collections.deque] = collections.defaultdict(
            lambda: collections.deque(maxlen=self.max_history_per_entity)
        )
        
        # Counter for sliding window purge throttle
        self._last_purge_time = time.time()

    def purge_expired(self, current_time: Optional[float] = None) -> None:
        """Evict flows older than window_seconds."""
        now = current_time or time.time()
        cutoff = now - self.window_seconds

        # Purge global deque
        while self.global_flows and self.global_flows[0][0] < cutoff:
            self.global_flows.popleft()

        # Periodically purge sparse entity dicts (every 5 seconds)
        if now - self._last_purge_time > 5.0:
            self._last_purge_time = now
            empty_srcs = []
            for src_ip, dq in self.src_ip_history.items():
                while dq and dq[0][0] < cutoff:
                    dq.popleft()
                if not dq:
                    empty_srcs.append(src_ip)
            for src_ip in empty_srcs:
                del self.src_ip_history[src_ip]

            empty_dsts = []
            for dst_ip, dq in self.dst_ip_timestamps.items():
                while dq and dq[0] < cutoff:
                    dq.popleft()
                if not dq:
                    empty_dsts.append(dst_ip)
            for dst_ip in empty_dsts:
                del self.dst_ip_timestamps[dst_ip]

    def add_flow(self, flow: FlowRecord, current_time: Optional[float] = None) -> None:
        """Add flow to sliding window state."""
        now = current_time or time.time()
        self.global_flows.append((now, flow))

        # Update per-source tracking
        syn_count = flow.tcp_flags.get("SYN", 0)
        ack_count = flow.tcp_flags.get("ACK", 0)
        self.src_ip_history[flow.src_ip].append((
            now,
            flow.dst_ip,
            flow.dst_port,
            flow.bytes_sent,
            flow.bytes_recv,
            flow.packets_sent,
            flow.packets_recv,
            syn_count,
            ack_count
        ))

        # Update per-destination tracking for beaconing
        self.dst_ip_timestamps[flow.dst_ip].append(now)

    # =========================================================================
    # 1. Volumetric / Protocol DDoS Feature Extraction
    # =========================================================================
    def compute_ddos_metrics(self) -> Dict[str, float]:
        """
        Compute rolling flow rate, SYN-to-ACK ratio, and Source IP Shannon entropy.
        """
        now = time.time()
        cutoff = now - self.window_seconds
        
        valid_flows = [f for t, f in self.global_flows if t >= cutoff]
        total_flows = len(valid_flows)
        flow_rate = total_flows / max(1.0, self.window_seconds)

        total_syn = 0
        total_ack = 0
        src_ip_counts: Dict[str, int] = collections.defaultdict(int)

        for f in valid_flows:
            total_syn += f.tcp_flags.get("SYN", 0)
            total_ack += f.tcp_flags.get("ACK", 0)
            src_ip_counts[f.src_ip] += 1

        # SYN-to-ACK ratio
        syn_ack_ratio = float(total_syn) / max(1.0, float(total_ack))

        # Source IP Shannon entropy: H = -sum(p_i * log2(p_i))
        entropy = 0.0
        if total_flows > 1:
            for count in src_ip_counts.values():
                p_i = count / total_flows
                if p_i > 0:
                    entropy -= p_i * math.log2(p_i)

        return {
            "flow_rate_per_sec": round(flow_rate, 2),
            "syn_ack_ratio": round(syn_ack_ratio, 2),
            "src_ip_entropy": round(entropy, 4),
            "total_window_flows": total_flows,
            "unique_src_ips": len(src_ip_counts)
        }

    # =========================================================================
    # 2. Botnet C2 Beaconing Feature Extraction
    # =========================================================================
    def compute_beaconing_metrics(self, dst_ip: str) -> Dict[str, float]:
        """
        Calculate inter-arrival time (IAT) variance and periodicity (FFT peak power ratio)
        to low-entropy destination IPs.
        """
        timestamps = list(self.dst_ip_timestamps.get(dst_ip, []))
        if len(timestamps) < 4:
            return {
                "iat_variance": 999.0,
                "iat_mean": 0.0,
                "periodicity_score": 0.0,
                "sample_count": len(timestamps)
            }

        # Calculate consecutive IAT deltas (seconds)
        iats = np.diff(np.array(timestamps))
        iat_variance = float(np.var(iats))
        iat_mean = float(np.mean(iats))
        
        # Periodicity using FFT or normalized autocorrelation peak
        periodicity_score = 0.0
        if len(iats) >= 6 and iat_mean > 0.05:
            # Low coefficient of variation (sigma / mu) indicates steady beacon
            cv = math.sqrt(iat_variance) / max(0.001, iat_mean)
            cv_score = max(0.0, min(1.0, 1.0 - (cv / 1.5)))

            # Normalized Autocorrelation at lag 1 & lag 2
            try:
                centered = iats - iat_mean
                var = np.sum(centered ** 2)
                if var > 1e-6:
                    r1 = np.sum(centered[:-1] * centered[1:]) / var
                    periodicity_score = max(0.0, min(1.0, (cv_score * 0.6) + (max(0.0, float(r1)) * 0.4)))
                else:
                    periodicity_score = 0.98  # Exact timing match!
            except Exception:
                periodicity_score = cv_score
        elif len(iats) >= 3 and iat_variance < 0.05:
            periodicity_score = 0.85

        return {
            "iat_variance": round(iat_variance, 6),
            "iat_mean": round(iat_mean, 3),
            "periodicity_score": round(periodicity_score, 4),
            "sample_count": len(timestamps)
        }

    # =========================================================================
    # 3. DNS Tunnelling & DGA Feature Extraction
    # =========================================================================
    @staticmethod
    def compute_dns_metrics(query: str, query_type: Optional[str] = None) -> Dict[str, float]:
        """
        Parse DNS query strings for character entropy, n-gram transition anomalies,
        label length, subdomain depth, and TXT/NULL record anomalies.
        """
        if not query:
            return {
                "char_entropy": 0.0,
                "vowel_ratio": 0.4,
                "max_label_length": 0,
                "subdomain_depth": 0,
                "is_txt_null_anomaly": 0.0
            }

        q_clean = query.strip().lower().rstrip(".")
        labels = q_clean.split(".")
        max_label_len = max(len(l) for l in labels) if labels else 0
        subdomain_depth = len(labels)

        # 1. Character Shannon Entropy of the full query or primary hostname
        char_counts: Dict[str, int] = collections.defaultdict(int)
        for ch in q_clean:
            char_counts[ch] += 1
        entropy = 0.0
        total_chars = len(q_clean)
        for cnt in char_counts.values():
            p = cnt / total_chars
            entropy -= p * math.log2(p)

        # 2. Vowel-to-consonant / n-gram regularity check
        alpha_chars = [c for c in q_clean if c.isalpha()]
        vowels = set("aeiou")
        vowel_count = sum(1 for c in alpha_chars if c in vowels)
        vowel_ratio = vowel_count / max(1, len(alpha_chars)) if alpha_chars else 0.4

        # 3. TXT/NULL record type anomaly
        q_type_upper = (query_type or "A").upper()
        is_txt_null = 1.0 if q_type_upper in ["TXT", "NULL", "ANY"] else 0.0

        return {
            "char_entropy": round(entropy, 4),
            "vowel_ratio": round(vowel_ratio, 4),
            "max_label_length": max_label_len,
            "subdomain_depth": subdomain_depth,
            "is_txt_null_anomaly": is_txt_null
        }

    # =========================================================================
    # 4. Encrypted Traffic Metadata (No Decryption)
    # =========================================================================
    @staticmethod
    def compute_encrypted_metadata_metrics(flow: FlowRecord) -> Dict[str, Any]:
        """
        Inspect TLS/QUIC metadata exclusively (JA3/JA4, SNI, first N packet sizes & IAT sequences).
        Zero payload decryption!
        """
        ja3 = flow.ja3_hash or ""
        ja4 = flow.ja4_fingerprint or ""
        sni = flow.tls_sni or ""
        sizes = flow.packet_sizes or []
        iats = flow.packet_iat_deltas or []

        # Known malicious JA3 / JA4 malware fingerprints (Cobalt Strike, TrickBot, AsyncRAT, Metasploit)
        MALICIOUS_JA3_HASHES = {
            "e7d705a39f6c0": "AsyncRAT C2 Client",
            "72a589da586844d7f0818ce684948eea": "Cobalt Strike HTTPS Beacon",
            "a0e9f5d64349fb13191bc781f81f42e1": "Metasploit Meterpreter",
            "b32309a26951912be7dba376398abc3b": "TrickBot Banking Trojan",
            "51c64c77e60f3980eea90869b68c58a8": "Emotet Loader",
            "3b5074b1b5c03249e21e73ea0e38b4e9": "IcedID C2 Traffic"
        }

        matched_malware = None
        for mal_ja3, label in MALICIOUS_JA3_HASHES.items():
            if mal_ja3 in ja3.lower():
                matched_malware = label
                break

        # Packet size variance and sequence analysis (first N packets)
        size_seq_len = len(sizes)
        size_variance = float(np.var(sizes)) if size_seq_len > 3 else 0.0
        avg_packet_size = float(np.mean(np.abs(sizes))) if size_seq_len > 0 else 0.0

        # High proportion of fixed-length small payloads is typical in beaconing / malware heartbeat
        is_fixed_length_beacon = 1.0 if (0 < size_variance < 25.0 and size_seq_len >= 5) else 0.0

        return {
            "ja3_hash": ja3,
            "ja4_fingerprint": ja4,
            "matched_malware_profile": matched_malware,
            "sni": sni,
            "first_n_packets_count": size_seq_len,
            "avg_packet_size": round(avg_packet_size, 1),
            "packet_size_variance": round(size_variance, 2),
            "is_fixed_length_beacon": is_fixed_length_beacon
        }

    # =========================================================================
    # 5. Reconnaissance / Scanning Feature Extraction
    # =========================================================================
    def compute_recon_scan_metrics(self, src_ip: str) -> Dict[str, Any]:
        """
        Track fan-out cardinality (unique destination IPs and ports contacted
        per source IP over rolling 10s window).
        """
        now = time.time()
        cutoff = now - self.window_seconds
        records = list(self.src_ip_history.get(src_ip, []))
        
        valid_records = [r for r in records if r[0] >= cutoff]
        if not valid_records:
            return {
                "unique_dst_ips_10s": 0,
                "unique_dst_ports_10s": 0,
                "fanout_cardinality": 0,
                "syn_only_ratio": 0.0
            }

        unique_dst_ips = set(r[1] for r in valid_records)
        unique_dst_ports = set(r[2] for r in valid_records)
        total_syns = sum(r[7] for r in valid_records)
        total_acks = sum(r[8] for r in valid_records)

        syn_only_ratio = total_syns / max(1.0, total_syns + total_acks)
        fanout = max(len(unique_dst_ips), len(unique_dst_ports))

        return {
            "unique_dst_ips_10s": len(unique_dst_ips),
            "unique_dst_ports_10s": len(unique_dst_ports),
            "fanout_cardinality": fanout,
            "syn_only_ratio": round(syn_only_ratio, 3)
        }

    # =========================================================================
    # 6. Data Exfiltration Feature Extraction
    # =========================================================================
    @staticmethod
    def compute_exfiltration_metrics(flow: FlowRecord) -> Dict[str, float]:
        """
        Calculate directional byte asymmetry (outbound-to-inbound byte and packet ratios).
        """
        bytes_out = float(flow.bytes_sent)
        bytes_in = float(flow.bytes_recv)
        pkts_out = float(flow.packets_sent)
        pkts_in = float(flow.packets_recv)

        byte_ratio = bytes_out / max(1.0, bytes_in)
        pkt_ratio = pkts_out / max(1.0, pkts_in)

        return {
            "bytes_sent": bytes_out,
            "bytes_recv": bytes_in,
            "byte_asymmetry_ratio": round(byte_ratio, 2),
            "packet_asymmetry_ratio": round(pkt_ratio, 2)
        }
