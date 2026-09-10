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

from main import app

client = TestClient(app)


def test_health_endpoint():
    """Test /health endpoint returns 200 OK and status dictionary."""
    headers = {"X-Forwarded-For": "10.10.0.1"}
    response = client.get("/health", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data.get("status") == "healthy"
    assert "redis" in data


def test_root_endpoint():
    """Test root endpoint / returns gateway metadata."""
    headers = {"X-Forwarded-For": "10.10.0.2"}
    response = client.get("/", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data.get("system") == "STRATA API Gateway"


def test_rate_limiting_middleware():
    """Test rate limiting middleware enforces limits and triggers 429 or 403 status."""
    headers = {"X-Forwarded-For": "10.10.0.3"}
    responses = [client.get("/api/v1/public/ping", headers=headers) for _ in range(30)]

    status_codes = [r.status_code for r in responses]
    assert (429 in status_codes) or (403 in status_codes)


def test_honeypot_trap():
    """Test honeypot endpoints trigger 403 Forbidden and block IP."""
    headers = {"X-Forwarded-For": "10.10.0.4"}
    response = client.get("/.env", headers=headers)
    assert response.status_code == 403
    data = response.json()
    assert "error" in data
    assert "Honeypot trap triggered" in data["error"]


def test_threat_observability_endpoints():
    """Test dashboard observability endpoints /feed and /stats."""
    headers = {"X-Forwarded-For": "10.10.0.5"}

    # Test Feed
    feed_res = client.get("/api/v1/threats/feed", headers=headers)
    assert feed_res.status_code == 200
    feed_data = feed_res.json()
    assert "events" in feed_data
    assert isinstance(feed_data["events"], list)

    # Test Stats
    stats_res = client.get("/api/v1/threats/stats", headers=headers)
    assert stats_res.status_code == 200
    stats_data = stats_res.json()
    assert "total_requests_analyzed" in stats_data
    assert "total_blocked_ips" in stats_data
    assert "threat_distribution" in stats_data
    assert "realtime_rps" in stats_data


def test_mock_jwt_token_generation():
    """Test /api/v1/auth/token endpoint generates valid JWT tokens."""
    headers = {"X-Forwarded-For": "10.10.0.6"}
    payload = {
        "user_id": "test_user_99",
        "role": "admin",
        "scopes": ["read", "write"],
        "expires_minutes": 10
    }
    response = client.post("/api/v1/auth/token", json=payload, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
