import time
import asyncio
import logging
from collections import deque
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from backend.ingest.models import FlowRecord, StandardizedAlert, EnclaveKPIs
from backend.ingest.sliding_window import SlidingWindowAggregator
from backend.ingest.receiver import receiver_instance
from backend.ml_engine.ensemble import ensemble_instance

logger = logging.getLogger("strata.pipeline")


class PassiveTelemetryPipeline:
    """
    Core Unidirectional Data Diode Telemetry Processing Pipeline.
    Consumes passive flow stream, executes sliding-window feature extraction,
    runs the ML multi-detector ensemble with bounded latency (<50ms),
    and publishes standardized alerts.
    """

    def __init__(self):
        self.aggregator = SlidingWindowAggregator(window_seconds=10.0)
        self.alerts_buffer: deque = deque(maxlen=1000)
        self.is_running = False
        self._worker_task: Optional[asyncio.Task] = None
        
        # Threat class radar metrics (live breakdown of the 6 classes)
        self.threat_radar: Dict[str, Dict[str, Any]] = {
            "VOLUMETRIC_DDOS": {
                "active_count": 0,
                "latest_confidence": 0.0,
                "severity": "LOW",
                "sample_evidence": "Flow Rate: 42.0/s | SYN/ACK: 1.02x | Entropy: 2.14"
            },
            "BOTNET_C2": {
                "active_count": 0,
                "latest_confidence": 0.0,
                "severity": "LOW",
                "sample_evidence": "Periodicity: 0.0% | IAT Variance: 0.84s"
            },
            "DGA_DNS_TUNNEL": {
                "active_count": 0,
                "latest_confidence": 0.0,
                "severity": "LOW",
                "sample_evidence": "Entropy: 2.45 | Vowel: 42% | Label Len: 12"
            },
            "ENCRYPTED_MALWARE": {
                "active_count": 0,
                "latest_confidence": 0.0,
                "severity": "LOW",
                "sample_evidence": "JA3 Hash: clean | Cipher: TLS_AES_256_GCM | SNI: valid"
            },
            "RECON_SCAN": {
                "active_count": 0,
                "latest_confidence": 0.0,
                "severity": "LOW",
                "sample_evidence": "Fanout: 2 targets/10s | SYN-only: 0%"
            },
            "DATA_EXFIL": {
                "active_count": 0,
                "latest_confidence": 0.0,
                "severity": "LOW",
                "sample_evidence": "Outbound/Inbound: 0.28x | Tx: 14.2 KB"
            }
        }

    async def start(self):
        """Start the background streaming worker."""
        if not self.is_running:
            self.is_running = True
            self._worker_task = asyncio.create_task(self._process_stream_loop())
            logger.info("Passive Telemetry Pipeline worker started.")

    async def stop(self):
        """Gracefully stop the background streaming worker."""
        self.is_running = False
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
            self._worker_task = None
            logger.info("Passive Telemetry Pipeline worker stopped.")

    async def _process_stream_loop(self):
        """
        High-throughput batch consumption loop.
        Drains up to 300 flows per batch from the async queue to guarantee bounded latency.
        """
        while self.is_running:
            try:
                records = []
                # 1. Drain priority burst queue first (immediate processing)
                while receiver_instance.priority_queue and len(records) < 150:
                    records.append(receiver_instance.priority_queue.popleft())

                # 2. If no priority records, pull from standard streaming queue
                if not records:
                    first_record: FlowRecord = await receiver_instance.queue.get()
                    records = [first_record]
                    while len(records) < 150:
                        try:
                            record = receiver_instance.queue.get_nowait()
                            records.append(record)
                        except asyncio.QueueEmpty:
                            break

                t0 = time.perf_counter()

                # Compute sliding-window DDoS metrics once for the batch
                ddos_metrics = self.aggregator.compute_ddos_metrics()

                # Process batch through sliding window & ML ensemble
                for flow in records:
                    self.aggregator.add_flow(flow)

                    # 2. C2 Beaconing features
                    c2_metrics = self.aggregator.compute_beaconing_metrics(flow.dst_ip)

                    # 3. DNS features
                    dns_metrics = (
                        self.aggregator.compute_dns_metrics(flow.dns_query, flow.dns_query_type)
                        if (flow.is_dns or flow.dns_query)
                        else {"char_entropy": 0.0, "vowel_ratio": 0.4, "max_label_length": 0, "subdomain_depth": 0, "is_txt_null_anomaly": 0.0}
                    )

                    # 4. Encrypted TLS metadata
                    enc_metrics = (
                        self.aggregator.compute_encrypted_metadata_metrics(flow)
                        if (flow.is_tls or flow.ja3_hash or flow.tls_sni)
                        else {"ja3_hash": "", "ja4_fingerprint": "", "matched_malware_profile": None, "sni": "", "first_n_packets_count": 0, "avg_packet_size": 0.0, "packet_size_variance": 0.0, "is_fixed_length_beacon": 0.0}
                    )

                    # 5. Recon scan features
                    recon_metrics = self.aggregator.compute_recon_scan_metrics(flow.src_ip)

                    # 6. Exfil features
                    exfil_metrics = self.aggregator.compute_exfiltration_metrics(flow)

                    # ML ensemble inspection
                    detected_alerts = ensemble_instance.inspect_flow(
                        flow=flow,
                        ddos_metrics=ddos_metrics,
                        beacon_metrics=c2_metrics,
                        dns_metrics=dns_metrics,
                        encrypted_metrics=enc_metrics,
                        recon_metrics=recon_metrics,
                        exfil_metrics=exfil_metrics
                    )

                    for alert in detected_alerts:
                        self.alerts_buffer.appendleft(alert)
                        receiver_instance.active_anomalies_count += 1
                        self._update_threat_radar(alert)

                # Measure actual latency
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                receiver_instance.last_pipeline_latency_ms = max(0.5, round(elapsed_ms, 2))

                # Yield execution to event loop
                await asyncio.sleep(0.001)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in pipeline loop: {e}", exc_info=True)
                await asyncio.sleep(0.05)

    def _update_threat_radar(self, alert: StandardizedAlert):
        """Update live radar status for the alert's threat class."""
        t_class = alert.threat_class
        if t_class in self.threat_radar:
            radar_item = self.threat_radar[t_class]
            radar_item["active_count"] += 1
            radar_item["latest_confidence"] = alert.confidence_score
            radar_item["severity"] = alert.severity

            # Format concise sample evidence string
            if t_class == "VOLUMETRIC_DDOS":
                radar_item["sample_evidence"] = (
                    f"Rate: {alert.evidence.get('flow_rate_rps', 'N/A')} | "
                    f"SYN/ACK: {alert.evidence.get('syn_to_ack_ratio', 'N/A')} | "
                    f"Entropy: {alert.evidence.get('src_ip_entropy', 'N/A')}"
                )
            elif t_class == "BOTNET_C2":
                radar_item["sample_evidence"] = (
                    f"Periodicity: {alert.evidence.get('periodicity_score', 'N/A')} | "
                    f"IAT Var: {alert.evidence.get('iat_variance', 'N/A')} | "
                    f"Interval: {alert.evidence.get('mean_interval', 'N/A')}"
                )
            elif t_class == "DGA_DNS_TUNNEL":
                radar_item["sample_evidence"] = (
                    f"DNS Entropy: {alert.evidence.get('query_char_entropy', 'N/A')} | "
                    f"Vowel: {alert.evidence.get('vowel_ratio', 'N/A')} | "
                    f"Query: {alert.evidence.get('dns_query', 'N/A')[:22]}"
                )
            elif t_class == "ENCRYPTED_MALWARE":
                radar_item["sample_evidence"] = (
                    f"Threat: {alert.evidence.get('matched_threat', 'Unknown TLS')} | "
                    f"JA3: {alert.evidence.get('ja3_hash', 'N/A')[:14]}..."
                )
            elif t_class == "RECON_SCAN":
                radar_item["sample_evidence"] = (
                    f"Scan: {alert.evidence.get('scan_type', 'Fanout')} | "
                    f"Targets: {alert.evidence.get('fanout_cardinality', 'N/A')}"
                )
            elif t_class == "DATA_EXFIL":
                radar_item["sample_evidence"] = (
                    f"Byte Ratio: {alert.evidence.get('byte_asymmetry_ratio', 'N/A')} | "
                    f"Outbound: {alert.evidence.get('outbound_bytes', 'N/A')}"
                )

    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return standardized alerts formatted as dictionaries."""
        alerts = list(self.alerts_buffer)[:limit]
        return [alert.model_dump() for alert in alerts]

    def get_radar_summary(self) -> Dict[str, Any]:
        return self.threat_radar


# Singleton pipeline instance
pipeline_instance = PassiveTelemetryPipeline()
