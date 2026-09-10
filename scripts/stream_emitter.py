#!/usr/bin/env python3
"""
Passive Telemetry Stream Emitter (Unidirectional Data Diode Feed)
Replaces attacker.py. Replays synthetic or pre-captured flow/DNS/TLS metadata records
across all 6 threat vectors directly into the backend via simulated unidirectional diode channel.
Target sustained rate: 2,000 - 5,000 flows/sec with real-time throughput counter in flows/sec & Mbps.
"""

import os
import sys
import time
import random
import string
import asyncio
import argparse
import httpx
from datetime import datetime, timezone
from typing import List, Dict, Any

# Ensure project root is in sys.path
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

# ANSI formatting
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

MALICIOUS_JA3_HASHES = [
    ("e7d705a39f6c0a54e601275bfbb0a221", "AsyncRAT C2 Client"),
    ("72a589da586844d7f0818ce684948eea", "Cobalt Strike HTTPS Beacon"),
    ("a0e9f5d64349fb13191bc781f81f42e1", "Metasploit Meterpreter"),
    ("b32309a26951912be7dba376398abc3b", "TrickBot Banking Trojan")
]

SCAN_TARGET_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 1433, 1521, 3306, 3389, 5432, 8080, 8443, 9200, 27017]


def generate_random_ip() -> str:
    return f"{random.randint(11, 220)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"


def generate_dga_domain() -> str:
    length = random.randint(22, 36)
    chars = string.ascii_lowercase + string.digits
    label = "".join(random.choices(chars, k=length))
    tld = random.choice(["cc", "top", "xyz", "ru", "biz", "info"])
    return f"{label}.exfil-intel.{tld}"


def generate_flow_record(threat_type: str) -> Dict[str, Any]:
    """Generates a synthetic passive network flow metadata record."""
    timestamp = datetime.now(timezone.utc).isoformat()
    src_ip = generate_random_ip()
    src_port = random.randint(1024, 65530)
    dst_ip = generate_random_ip()
    dst_port = random.choice([80, 443, 53, 8080, 8443])
    proto = "TCP"
    
    bytes_sent = random.randint(300, 2500)
    bytes_recv = random.randint(1500, 15000)
    pkts_sent = random.randint(3, 15)
    pkts_recv = random.randint(5, 30)
    tcp_flags = {"SYN": 1, "ACK": 1, "FIN": 0, "RST": 0, "PSH": 1}
    
    is_tls = False
    tls_sni = None
    ja3_hash = None
    ja4_fingerprint = None
    packet_sizes = []
    packet_iat_deltas = []
    
    is_dns = False
    dns_query = None
    dns_query_type = None

    if threat_type == "NORMAL":
        # Standard HTTPS web / API browsing
        is_tls = True
        tls_sni = random.choice(["api.github.com", "cloudflare.com", "google.com", "aws.amazon.com", "datadoghq.com"])
        ja3_hash = "669181e23d9be9636fc064d23458f8d4"
        ja4_fingerprint = "t13d1516h2_8daaf6152771_b186095e22b6"
        packet_sizes = [random.randint(60, 1400) for _ in range(8)]
        packet_iat_deltas = [round(random.uniform(0.01, 0.4), 3) for _ in range(7)]

    elif threat_type == "VOLUMETRIC_DDOS":
        # SYN flood burst with spoofed source IPs
        dst_ip = "198.51.100.25"  # Targeted edge gateway VIP
        dst_port = 443
        bytes_sent = random.randint(40, 80)
        bytes_recv = 0
        pkts_sent = random.randint(10, 40)
        pkts_recv = 0
        tcp_flags = {"SYN": random.randint(10, 30), "ACK": 0, "FIN": 0, "RST": 0, "PSH": 0}

    elif threat_type == "BOTNET_C2":
        # Low variance periodic heartbeat to fixed C2 controller
        src_ip = "10.0.4.88"       # Compromised internal asset
        dst_ip = "198.51.100.199"   # External C2 node
        dst_port = 8443
        is_tls = True
        tls_sni = None             # Direct IP connection (no SNI)
        ja3_hash = "e7d705a39f6c0a54e601275bfbb0a221"
        ja4_fingerprint = "t13d1516h2_c2_botnet_pulse"
        bytes_sent = 240
        bytes_recv = 180
        # Fixed-length sequences
        packet_sizes = [240, -180, 64, -64]
        packet_iat_deltas = [0.002, 0.003, 0.001]

    elif threat_type == "DGA_DNS_TUNNEL":
        # Covert DNS channel with high entropy and TXT/NULL record queries
        src_ip = "10.0.2.14"
        dst_ip = "8.8.8.8"
        dst_port = 53
        proto = "UDP"
        is_dns = True
        dns_query = generate_dga_domain()
        dns_query_type = random.choice(["TXT", "NULL", "TXT", "A"])
        bytes_sent = random.randint(120, 450)
        bytes_recv = random.randint(400, 1200)

    elif threat_type == "ENCRYPTED_MALWARE":
        # Signature TLS ClientHello without payload decryption
        src_ip = "10.0.5.112"
        dst_ip = "203.0.113.77"
        dst_port = 443
        is_tls = True
        ja3_tuple = random.choice(MALICIOUS_JA3_HASHES)
        ja3_hash = ja3_tuple[0]
        tls_sni = random.choice(["sync-service.dynamic-dns.net", "update-edge.xyz", ""])
        packet_sizes = [517, -1420, -1420, 210, -85]
        packet_iat_deltas = [0.012, 0.004, 0.001, 0.050]

    elif threat_type == "RECON_SCAN":
        # Rapid port sweep from single source IP
        src_ip = "192.0.2.45"
        dst_ip = "10.0.1.10"
        dst_port = random.choice(SCAN_TARGET_PORTS)
        tcp_flags = {"SYN": 1, "ACK": 0, "FIN": 0, "RST": 0, "PSH": 0}
        bytes_sent = 60
        bytes_recv = 0
        pkts_sent = 1
        pkts_recv = 0

    elif threat_type == "DATA_EXFIL":
        # Heavy directional outbound byte asymmetry
        src_ip = "10.0.3.50"
        dst_ip = "198.51.100.99"
        dst_port = 443
        is_tls = True
        tls_sni = "storage-backup-sync.cloud"
        bytes_sent = random.randint(850_000, 3_500_000)  # Massive outbound payload
        bytes_recv = random.randint(1200, 8000)           # Tiny inbound ACK stream
        pkts_sent = random.randint(600, 2400)
        pkts_recv = random.randint(30, 120)

    return {
        "timestamp": timestamp,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": proto,
        "bytes_sent": bytes_sent,
        "bytes_recv": bytes_recv,
        "packets_sent": pkts_sent,
        "packets_recv": pkts_recv,
        "duration_ms": round(random.uniform(2.0, 180.0), 2),
        "tcp_flags": tcp_flags,
        "is_tls": is_tls,
        "tls_sni": tls_sni,
        "ja3_hash": ja3_hash,
        "ja4_fingerprint": ja4_fingerprint,
        "cipher_suite": "TLS_AES_256_GCM_SHA384" if is_tls else None,
        "packet_sizes": packet_sizes,
        "packet_iat_deltas": packet_iat_deltas,
        "is_dns": is_dns,
        "dns_query": dns_query,
        "dns_query_type": dns_query_type,
        "dns_response_code": "NOERROR" if is_dns else None
    }


async def stream_emitter_worker(
    backend_url: str,
    target_rate: int = 3000,
    batch_size: int = 150,
    duration_seconds: Optional[int] = None
):
    """
    High-throughput async emitter worker.
    Generates batches of flow records and streams them via HTTP POST to the backend ingest route.
    Tracks instantaneous flows/sec and Mbps.
    """
    ingest_endpoint = f"{backend_url.rstrip('/')}/api/v1/diode/ingest"
    
    threat_weights = [
        ("NORMAL", 0.60),
        ("VOLUMETRIC_DDOS", 0.10),
        ("BOTNET_C2", 0.08),
        ("DGA_DNS_TUNNEL", 0.08),
        ("ENCRYPTED_MALWARE", 0.05),
        ("RECON_SCAN", 0.05),
        ("DATA_EXFIL", 0.04)
    ]
    threat_types, weights = zip(*threat_weights)

    print(f"{CYAN}{BOLD}==================================================================={RESET}")
    print(f"{CYAN}{BOLD}⚡ STRATA PASSIVE TELEMETRY STREAM EMITTER (DATA DIODE REPLAY) v2.0{RESET}")
    print(f"Target Ingestion URL  : {backend_url}")
    print(f"Target Sustained Rate : {BOLD}{target_rate:,} flows/sec{RESET}")
    print(f"Batch Size            : {batch_size} flows/batch")
    print(f"Diode Constraint      : {GREEN}UNIDIRECTIONAL RX (ZERO RETURN PATH / READ-ONLY){RESET}")
    print(f"{CYAN}{BOLD}==================================================================={RESET}\n")

    total_emitted = 0
    total_bytes = 0
    start_time = time.time()
    last_hud_time = time.time()
    emitted_since_hud = 0
    bytes_since_hud = 0
    threat_counts = {t: 0 for t in threat_types}

    async with httpx.AsyncClient(timeout=httpx.Timeout(2.0, connect=1.0)) as client:
        try:
            while True:
                now = time.time()
                if duration_seconds and (now - start_time) >= duration_seconds:
                    break

                batch_start = time.perf_counter()
                
                # Generate batch
                batch_threats = random.choices(threat_types, weights=weights, k=batch_size)
                batch_records = []
                batch_bytes = 0

                for t in batch_threats:
                    rec = generate_flow_record(t)
                    batch_records.append(rec)
                    threat_counts[t] += 1
                    batch_bytes += (rec["bytes_sent"] + rec["bytes_recv"])

                # Post batch to backend
                try:
                    res = await client.post(ingest_endpoint, json=batch_records)
                    if res.status_code == 200:
                        total_emitted += len(batch_records)
                        total_bytes += batch_bytes
                        emitted_since_hud += len(batch_records)
                        bytes_since_hud += batch_bytes
                except Exception as e:
                    # Non-blocking passive stream continues
                    pass

                # Target rate pacing
                batch_duration = time.perf_counter() - batch_start
                target_batch_time = batch_size / float(target_rate)
                sleep_needed = target_batch_time - batch_duration
                if sleep_needed > 0.0005:
                    await asyncio.sleep(sleep_needed)

                # Update HUD every 0.8 seconds
                now = time.time()
                hud_delta = now - last_hud_time
                if hud_delta >= 0.8:
                    sustained_fps = emitted_since_hud / max(0.001, hud_delta)
                    sustained_mbps = (bytes_since_hud * 8.0) / (max(0.001, hud_delta) * 1_000_000.0)
                    overall_fps = total_emitted / max(0.001, now - start_time)

                    sys.stdout.write(
                        f"\r{BOLD}[PASSIVE DIODE TAP]{RESET} "
                        f"Current: {GREEN}{sustained_fps:6.0f} flows/s{RESET} | "
                        f"Throughput: {CYAN}{sustained_mbps:6.2f} Mbps{RESET} | "
                        f"Total Emitted: {YELLOW}{total_emitted:,}{RESET} | "
                        f"DDoS: {threat_counts['VOLUMETRIC_DDOS']} | "
                        f"C2: {threat_counts['BOTNET_C2']} | "
                        f"DGA: {threat_counts['DGA_DNS_TUNNEL']} | "
                        f"TLS: {threat_counts['ENCRYPTED_MALWARE']} | "
                        f"Scan: {threat_counts['RECON_SCAN']} | "
                        f"Exfil: {threat_counts['DATA_EXFIL']}"
                    )
                    sys.stdout.flush()

                    last_hud_time = now
                    emitted_since_hud = 0
                    bytes_since_hud = 0

        except asyncio.CancelledError:
            pass

    elapsed = time.time() - start_time
    avg_fps = total_emitted / max(0.001, elapsed)
    avg_mbps = (total_bytes * 8.0) / (max(0.001, elapsed) * 1_000_000.0)

    print(f"\n\n{GREEN}✔ Telemetry stream replay completed.{RESET}")
    print(f"Total Flows Replayed  : {BOLD}{total_emitted:,}{RESET}")
    print(f"Total Bytes Replayed  : {total_bytes / (1024 * 1024):.2f} MB")
    print(f"Elapsed Time          : {elapsed:.2f}s")
    print(f"Average Sustained Rate: {BOLD}{avg_fps:.1f} flows/sec{RESET} ({avg_mbps:.2f} Mbps)")


def main():
    parser = argparse.ArgumentParser(description="Passive Telemetry Stream Emitter (Data Diode Replay)")
    parser.add_argument("--url", default=os.getenv("BACKEND_URL", "http://127.0.0.1:8000"), help="Backend URL")
    parser.add_argument("--target-rate", type=int, default=3000, help="Target sustained rate in flows/sec (2000-5000)")
    parser.add_argument("--batch-size", type=int, default=150, help="Batch size per POST request")
    parser.add_argument("--duration", type=int, default=None, help="Duration in seconds (default: run until Ctrl+C)")
    args = parser.parse_args()

    try:
        asyncio.run(
            stream_emitter_worker(
                backend_url=args.url,
                target_rate=args.target_rate,
                batch_size=args.batch_size,
                duration_seconds=args.duration
            )
        )
    except KeyboardInterrupt:
        print(f"\n{YELLOW}🛑 Stream emitter stopped by user.{RESET}")


if __name__ == "__main__":
    main()
