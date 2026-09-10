import logging
from typing import Dict, Any, List
from fastapi import APIRouter, Request
from backend.pipeline import pipeline_instance
from backend.ingest.receiver import receiver_instance

logger = logging.getLogger("strata.threats")

router = APIRouter(prefix="/api/v1/threats", tags=["Data Diode Passive Threat Observability"])


@router.get("/feed")
async def get_threat_feed(request: Request):
    """
    Returns latest security threat events from the passive data diode pipeline.
    Zero active blocking: read-only telemetry.
    """
    alerts = pipeline_instance.get_recent_alerts(limit=50)
    events = []
    for a in alerts:
        events.append({
            "id": f"evt_{a.get('flow_id', '')[:16]}",
            "timestamp": a.get("timestamp"),
            "flow_id": a.get("flow_id"),
            "threat_type": a.get("threat_class"),
            "severity": a.get("severity"),
            "score": a.get("confidence_score"),
            "action": "PASSIVE_FLAGGED",
            "message": f"[{a.get('threat_class')}] {a.get('flow_id')} | " +
                       ", ".join(f"{k}: {v}" for k, v in a.get("evidence", {}).items() if k != "baseline_threshold")
        })
    return {"events_count": len(events), "events": events}


@router.get("/stats")
async def get_threat_stats(request: Request):
    """
    Aggregates high-level threat statistics for the passive Data Diode Enclave.
    """
    kpis = receiver_instance.get_kpis()
    radar = pipeline_instance.get_radar_summary()

    threat_distribution = {
        "DDoS": radar.get("VOLUMETRIC_DDOS", {}).get("active_count", 0),
        "BotnetC2": radar.get("BOTNET_C2", {}).get("active_count", 0),
        "DNSTunnel": radar.get("DGA_DNS_TUNNEL", {}).get("active_count", 0),
        "EncryptedMalware": radar.get("ENCRYPTED_MALWARE", {}).get("active_count", 0),
        "ReconScan": radar.get("RECON_SCAN", {}).get("active_count", 0),
        "DataExfil": radar.get("DATA_EXFIL", {}).get("active_count", 0),
    }

    return {
        "total_requests_analyzed": kpis.ingested_flows_total,
        "total_blocked_ips": 0,  # Zero return-path / zero blocking
        "threat_distribution": threat_distribution,
        "realtime_rps": kpis.sustained_flows_per_sec,
        "system_status": "DATA_DIODE_READ_ONLY"
    }


@router.get("/blocked-ips")
async def get_blocked_ips(request: Request):
    """
    Data Diode Enclave operates purely in read-only mode: NO IPs are ever blocked.
    """
    return {
        "total_blocked_ips": 0,
        "blocked_ips": [],
        "diode_mode": "ZERO_RETURN_PATH_READ_ONLY"
    }
