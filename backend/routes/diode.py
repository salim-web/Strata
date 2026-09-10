import logging
from typing import List, Dict, Any, Union
from datetime import datetime, timezone
from fastapi import APIRouter, Request, Body, Query, HTTPException, status
from pydantic import BaseModel

from backend.ingest.models import FlowRecord, StandardizedAlert, EnclaveKPIs
from backend.ingest.receiver import receiver_instance
from backend.pipeline import pipeline_instance
from backend.services.gemini_analyst import generate_threat_intelligence_assessment

logger = logging.getLogger("strata.diode_routes")

router = APIRouter(prefix="/api/v1", tags=["Data Diode Enclave Telemetry"])


class IngestBatchPayload(BaseModel):
    flows: List[FlowRecord]


class AssessmentRequest(BaseModel):
    alert: Dict[str, Any]


@router.post("/diode/ingest")
async def ingest_telemetry_stream(
    payload: Union[FlowRecord, IngestBatchPayload, List[FlowRecord]] = Body(...)
):
    """
    Unidirectional streaming ingest endpoint.
    Consumes passive NetFlow/IPFIX, PCAP metadata, or synthetic streaming records.
    Strictly read-only: No inline blocking, no TCP reset, no return-path action.
    """
    if isinstance(payload, FlowRecord):
        await receiver_instance.ingest_record(payload)
        return {"status": "ingested", "count": 1}
    elif isinstance(payload, IngestBatchPayload):
        count = await receiver_instance.ingest_batch(payload.flows)
        return {"status": "ingested", "count": count}
    elif isinstance(payload, list):
        count = await receiver_instance.ingest_batch(payload)
        return {"status": "ingested", "count": count}
class ThreatBurstPayload(BaseModel):
    threat_class: str = "DGA_DNS_TUNNEL"
    count: int = 50


@router.post("/diode/emitter/burst")
async def trigger_threat_burst(payload: ThreatBurstPayload = Body(...)):
    """
    Triggers an immediate burst of synthetic passive telemetry across any of the 6 threat vectors.
    """
    import time
    from backend.ingest.generator import create_flow_record
    t_class = payload.threat_class.upper()
    burst_count = max(1, min(250, payload.count))
    now = time.time()
    flows = []

    if t_class == "BOTNET_C2":
        # Prime the sliding window with periodic heartbeat intervals so all burst flows score immediately
        ts_deque = pipeline_instance.aggregator.dst_ip_timestamps["198.51.100.199"]
        ts_deque.clear()
        for k in range(4, 0, -1):
            ts_deque.append(now - ((burst_count + k) * 0.10))
    elif t_class == "RECON_SCAN":
        # Ensure fanout baseline is primed so every burst flow immediately alerts
        history = pipeline_instance.aggregator.src_ip_history["192.0.2.45"]
        history.clear()
        for p in [21, 22, 23, 25, 80, 110, 143, 443, 8080]:
            history.append((now - 1.0, "10.0.1.10", p, 60, 0, 1, 1, 1, 0))

    for i in range(burst_count):
        flow = create_flow_record(t_class)
        if t_class == "BOTNET_C2":
            # Space out beaconing timestamps across the window to represent periodic heartbeats
            offset = (burst_count - 1 - i) * 0.10
            flow_ts = datetime.fromtimestamp(now - offset, timezone.utc).isoformat()
            flow.timestamp = flow_ts
        flows.append(flow)

    count = await receiver_instance.ingest_burst(flows)
    return {"status": "burst_injected", "threat_class": t_class, "count": count}



@router.get("/diode/stats")
async def get_diode_telemetry_stats():
    """
    Returns real-time KPIs and 6-vector Threat Radar summaries for the Data Diode Enclave.
    """
    kpis = receiver_instance.get_kpis()
    radar = pipeline_instance.get_radar_summary()
    return {
        "kpis": kpis.model_dump(),
        "threat_radar": radar,
        "recent_alerts_count": len(pipeline_instance.alerts_buffer)
    }


@router.get("/diode/alerts")
async def get_standardized_alerts(limit: int = Query(50, ge=1, le=200)):
    """
    Returns recent standardized alerts matching the schema:
    {
      "timestamp": "ISO8601",
      "flow_id": "src_ip:src_port->dst_ip:dst_port:proto",
      "threat_class": "VOLUMETRIC_DDOS | BOTNET_C2 | DGA_DNS_TUNNEL | ENCRYPTED_MALWARE | RECON_SCAN | DATA_EXFIL",
      "confidence_score": 0.00 - 1.00,
      "severity": "LOW | MEDIUM | HIGH | CRITICAL",
      "evidence": { "metric_name": "value", "baseline_threshold": "value" }
    }
    """
    alerts = pipeline_instance.get_recent_alerts(limit=limit)
    return {
        "alerts_count": len(alerts),
        "alerts": alerts
    }


@router.post("/analyst/assess")
async def request_analyst_assessment(payload: AssessmentRequest = Body(...)):
    """
    Generates human-readable threat assessment using Google Gemini (via google-genai)
    based strictly on passive evidence attributes.
    """
    assessment = await generate_threat_intelligence_assessment(payload.alert)
    return assessment


# =============================================================================
# Backward Compatibility Endpoints for Frontend Dashboard
# =============================================================================

@router.get("/threat-metrics")
async def get_legacy_threat_metrics():
    """
    Adapter endpoint providing backwards-compatible metrics structure
    adhering strictly to passive data diode state (0 blocked IPs, read-only mode).
    """
    kpis = receiver_instance.get_kpis()
    alerts = pipeline_instance.get_recent_alerts(limit=25)
    
    # Map standardized alerts to legacy alert format if needed
    legacy_alerts = []
    for a in alerts:
        legacy_alerts.append({
            "id": f"ALT-{a.get('flow_id', '')[:16]}",
            "timestamp": a.get("timestamp", ""),
            "severity": a.get("severity", "HIGH"),
            "message": f"[{a.get('threat_class')}] {a.get('flow_id')} (Confidence: {int(a.get('confidence_score', 0.8) * 100)}%) - " +
                       ", ".join(f"{k}: {v}" for k, v in a.get("evidence", {}).items() if k != "baseline_threshold")
        })

    return {
        "total_requests": kpis.ingested_flows_total,
        "blocked_ips_count": 0,  # Strictly zero in read-only passive diode mode
        "blocked_ips_list": [],
        "recent_alerts": legacy_alerts,
        "sampling_rate": 1.0,
        "sampling_rate_pct": 100,
        "sampled_requests_count": kpis.ingested_flows_total,
        "bypassed_requests_count": 0,
        "compute_saved_pct": 0,
        "current_anomaly_score": round(min(1.0, kpis.active_anomalies_count / max(1, kpis.ingested_flows_total or 1) * 20.0), 2),
        "ml_latency_ms": kpis.pipeline_latency_ms,
        "diode_kpis": kpis.model_dump()
    }
