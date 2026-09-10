import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

# Setup sys.path for backend and project root
root_dir = Path(__file__).resolve().parent.parent.parent
backend_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from backend.main import app

client = TestClient(app)


def test_health_endpoint():
    """Test /health endpoint returns 200 OK and diode status dictionary."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data.get("status") == "healthy"
    assert data.get("diode_mode") == "READ_ONLY"
    assert "sustained_flows_per_sec" in data


def test_root_endpoint():
    """Test root endpoint / returns passive enclave diode metadata."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data.get("mode") == "READ_ONLY"
    assert data.get("return_path_active") is False
    assert "STRATA" in data.get("enclave", "")


def test_diode_stats_and_radar_endpoints():
    """Test /api/v1/diode/stats returns KPIs and 6-vector threat radar."""
    response = client.get("/api/v1/diode/stats")
    assert response.status_code == 200
    data = response.json()
    assert "kpis" in data
    assert "threat_radar" in data
    assert "VOLUMETRIC_DDOS" in data["threat_radar"]
    assert "BOTNET_C2" in data["threat_radar"]
    assert "DGA_DNS_TUNNEL" in data["threat_radar"]
    assert "ENCRYPTED_MALWARE" in data["threat_radar"]
    assert "RECON_SCAN" in data["threat_radar"]
    assert "DATA_EXFIL" in data["threat_radar"]


def test_diode_standardized_alerts_endpoint():
    """Test /api/v1/diode/alerts returns standardized alerts schema."""
    response = client.get("/api/v1/diode/alerts?limit=10")
    assert response.status_code == 200
    data = response.json()
    assert "alerts" in data
    assert "alerts_count" in data
    assert isinstance(data["alerts"], list)


def test_threat_observability_endpoints():
    """Test dashboard observability endpoints /feed and /stats."""
    # Test Feed
    feed_res = client.get("/api/v1/threats/feed")
    assert feed_res.status_code == 200
    feed_data = feed_res.json()
    assert "events" in feed_data
    assert isinstance(feed_data["events"], list)

    # Test Stats
    stats_res = client.get("/api/v1/threats/stats")
    assert stats_res.status_code == 200
    stats_data = stats_res.json()
    assert "total_requests_analyzed" in stats_data
    assert "total_blocked_ips" in stats_data
    assert "threat_distribution" in stats_data
    assert "realtime_rps" in stats_data


def test_zero_blocking_enforcement():
    """Verify that diode strictly enforces zero return path (0 blocked IPs)."""
    response = client.get("/api/v1/threats/blocked-ips")
    assert response.status_code == 200
    data = response.json()
    assert data.get("total_blocked_ips") == 0
    assert len(data.get("blocked_ips", [])) == 0
    assert "READ_ONLY" in data.get("diode_mode", "")
