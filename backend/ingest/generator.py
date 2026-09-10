import random
import string
import time
import asyncio
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from backend.ingest.models import FlowRecord
from backend.ingest.receiver import receiver_instance

logger = logging.getLogger("strata.generator")

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
    length = random.randint(22, 34)
    chars = string.ascii_lowercase + string.digits
    label = "".join(random.choices(chars, k=length))
    tld = random.choice(["cc", "top", "xyz", "ru", "biz", "info"])
    return f"{label}.exfil-intel.{tld}"


NORMAL_SRC_IPS = [f"10.0.{s}.{h}" for s in [1, 2] for h in range(1, 15)]
NORMAL_DST_IPS = ["198.51.100.10", "198.51.100.11", "203.0.113.20", "203.0.113.21", "8.8.8.8", "1.1.1.1", "142.250.190.46"]


def create_flow_record(threat_type: str) -> FlowRecord:
    """Generates a FlowRecord for a specific threat vector or normal baseline traffic."""
    now_iso = datetime.now(timezone.utc).isoformat()
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
        src_ip = random.choice(NORMAL_SRC_IPS)
        dst_ip = generate_random_ip()
        is_tls = True
        tls_sni = random.choice(["api.github.com", "cloudflare.com", "google.com", "aws.amazon.com", "datadoghq.com"])
        ja3_hash = "669181e23d9be9636fc064d23458f8d4"
        ja4_fingerprint = "t13d1516h2_8daaf6152771_b186095e22b6"
        packet_sizes = [random.randint(60, 1400) for _ in range(8)]
        packet_iat_deltas = [round(random.uniform(0.01, 0.4), 3) for _ in range(7)]

    elif threat_type == "VOLUMETRIC_DDOS":
        dst_ip = "198.51.100.25"
        dst_port = 443
        is_tls = False
        ja3_hash = None
        ja4_fingerprint = None
        bytes_sent = random.randint(40, 80)
        bytes_recv = 0
        pkts_sent = random.randint(15, 50)
        pkts_recv = 0
        tcp_flags = {"SYN": random.randint(15, 40), "ACK": 0, "FIN": 0, "RST": 0, "PSH": 0}

    elif threat_type == "BOTNET_C2":
        src_ip = "10.0.4.88"
        dst_ip = "198.51.100.199"
        dst_port = 8443
        is_tls = True
        tls_sni = None
        ja3_hash = "c2_heartbeat_pulse_session_ja3"
        ja4_fingerprint = "t13d1516h2_c2_botnet_pulse"
        bytes_sent = 240
        bytes_recv = 180
        packet_sizes = [240, -180, 64, -64, 240, -180]
        packet_iat_deltas = [2.50, 2.51, 2.49, 2.50, 2.50]

    elif threat_type == "DGA_DNS_TUNNEL":
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
        src_ip = "192.0.2.45"
        dst_ip = "10.0.1.10"
        dst_port = random.randint(20, 1024)
        tcp_flags = {"SYN": 1, "ACK": 0, "FIN": 0, "RST": 0, "PSH": 0}
        bytes_sent = 60
        bytes_recv = 0
        pkts_sent = 1
        pkts_recv = 0

    elif threat_type == "DATA_EXFIL":
        src_ip = "10.0.3.50"
        dst_ip = "198.51.100.99"
        dst_port = 443
        is_tls = True
        tls_sni = "storage-backup-sync.cloud"
        bytes_sent = random.randint(850_000, 3_500_000)
        bytes_recv = random.randint(1200, 8000)
        pkts_sent = random.randint(600, 2400)
        pkts_recv = random.randint(30, 120)

    return FlowRecord(
        timestamp=now_iso,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol=proto,
        bytes_sent=bytes_sent,
        bytes_recv=bytes_recv,
        packets_sent=pkts_sent,
        packets_recv=pkts_recv,
        duration_ms=round(random.uniform(2.0, 180.0), 2),
        tcp_flags=tcp_flags,
        is_tls=is_tls,
        tls_sni=tls_sni,
        ja3_hash=ja3_hash,
        ja4_fingerprint=ja4_fingerprint,
        cipher_suite="TLS_AES_256_GCM_SHA384" if is_tls else None,
        packet_sizes=packet_sizes,
        packet_iat_deltas=packet_iat_deltas,
        is_dns=is_dns,
        dns_query=dns_query,
        dns_query_type=dns_query_type,
        dns_response_code="NOERROR" if is_dns else None
    )


class AmbientTelemetryEmitter:
    """
    Continuous Ambient In-Process Telemetry Generator.
    Ensures the passive enclave receives a continuous, realistic stream of passive metadata
    (target rate: ~2,500 flows/sec) even when no external replay script is running.
    """

    def __init__(self, target_rate: int = 500):
        self.target_rate = target_rate
        self.is_running = False
        self._task: Optional[asyncio.Task] = None
        self.threat_weights = [
            ("NORMAL", 0.994),
            ("VOLUMETRIC_DDOS", 0.001),
            ("BOTNET_C2", 0.001),
            ("DGA_DNS_TUNNEL", 0.001),
            ("ENCRYPTED_MALWARE", 0.001),
            ("RECON_SCAN", 0.001),
            ("DATA_EXFIL", 0.001)
        ]

    async def start(self):
        if not self.is_running:
            self.is_running = True
            self._task = asyncio.create_task(self._generator_loop())
            logger.info(f"Continuous Ambient Telemetry Generator started (~{self.target_rate} flows/sec).")

    async def stop(self):
        self.is_running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
            logger.info("Continuous Ambient Telemetry Generator stopped.")

    async def _generator_loop(self):
        batch_size = 50
        threat_types, weights = zip(*self.threat_weights)
        
        while self.is_running:
            try:
                t0 = time.perf_counter()
                
                # Generate batch
                batch_types = random.choices(threat_types, weights=weights, k=batch_size)
                records = [create_flow_record(t) for t in batch_types]
                
                # Push directly into receiver queue
                await receiver_instance.ingest_batch(records)

                # Rate pacing
                elapsed = time.perf_counter() - t0
                target_batch_time = batch_size / float(self.target_rate)
                sleep_time = target_batch_time - elapsed
                if sleep_time > 0.001:
                    await asyncio.sleep(sleep_time)
                else:
                    await asyncio.sleep(0.005)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in ambient telemetry loop: {e}")
                await asyncio.sleep(0.1)


# Singleton ambient generator instance
ambient_emitter = AmbientTelemetryEmitter(target_rate=500)
