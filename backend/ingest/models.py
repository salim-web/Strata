from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class FlowRecord(BaseModel):
    """
    Passive network flow metadata record (derived from NetFlow/IPFIX, PCAP/pcap-ng metadata,
    or streaming JSON flow records). Strictly unidirectional and passive: no payload is decrypted.
    """
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str = "TCP"  # TCP, UDP, ICMP, etc.
    
    # Volume & Timing metrics
    bytes_sent: int = 0      # Outbound bytes (client to server)
    bytes_recv: int = 0      # Inbound bytes (server to client)
    packets_sent: int = 0    # Outbound packets
    packets_recv: int = 0    # Inbound packets
    duration_ms: float = 0.0
    
    # TCP Flags & Protocol Metadata
    tcp_flags: Dict[str, int] = Field(default_factory=lambda: {"SYN": 0, "ACK": 0, "FIN": 0, "RST": 0, "PSH": 0})
    
    # TLS / Encrypted Metadata (Payload Decryption strictly forbidden)
    is_tls: bool = False
    tls_sni: Optional[str] = None
    ja3_hash: Optional[str] = None
    ja4_fingerprint: Optional[str] = None
    cipher_suite: Optional[str] = None
    # First N packet sizes (positive: outbound, negative: inbound) & inter-arrival time deltas (seconds)
    packet_sizes: List[int] = Field(default_factory=list)
    packet_iat_deltas: List[float] = Field(default_factory=list)
    
    # DNS Metadata (if protocol is DNS / port 53)
    is_dns: bool = False
    dns_query: Optional[str] = None
    dns_query_type: Optional[str] = None  # A, AAAA, TXT, NULL, ANY, CNAME
    dns_response_code: Optional[str] = None

    @property
    def flow_id(self) -> str:
        return f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}:{self.protocol}"


class ThreatEvidence(BaseModel):
    """
    Standardized threat evidence key-value structure with metrics and baseline thresholds.
    """
    evidence: Dict[str, str] = Field(default_factory=dict)


class StandardizedAlert(BaseModel):
    """
    Standardized Threat Detection Alert Schema:
    {
      "timestamp": "ISO8601",
      "flow_id": "src_ip:src_port->dst_ip:dst_port:proto",
      "threat_class": "VOLUMETRIC_DDOS | BOTNET_C2 | DGA_DNS_TUNNEL | ENCRYPTED_MALWARE | RECON_SCAN | DATA_EXFIL",
      "confidence_score": 0.00 - 1.00,
      "severity": "LOW | MEDIUM | HIGH | CRITICAL",
      "evidence": {
        "metric_name": "value",
        "baseline_threshold": "value"
      }
    }
    """
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    flow_id: str
    threat_class: str  # VOLUMETRIC_DDOS | BOTNET_C2 | DGA_DNS_TUNNEL | ENCRYPTED_MALWARE | RECON_SCAN | DATA_EXFIL
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    severity: str = "LOW"  # LOW | MEDIUM | HIGH | CRITICAL
    evidence: Dict[str, str] = Field(default_factory=dict)


class EnclaveKPIs(BaseModel):
    """
    Real-time KPIs for the Data Diode Passive Network Threat Intelligence Enclave.
    """
    sustained_flows_per_sec: float = 0.0
    sustained_mbps: float = 0.0
    ingested_packets_total: int = 0
    ingested_flows_total: int = 0
    active_anomalies_count: int = 0
    pipeline_latency_ms: float = 0.0
    diode_status: str = "READ_ONLY_ENCLAVE_ACTIVE"
    return_path_active: bool = False  # Strictly False: Zero return path
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
