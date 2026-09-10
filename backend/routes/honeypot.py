import json
import inspect
import logging
from datetime import datetime, timezone
from typing import Dict, Any
from fastapi import APIRouter, Request, status
from fastapi.responses import JSONResponse

try:
    from backend.middleware.rate_limiter import get_client_ip, block_ip
    from backend.middleware.redis_rate_limit import tracker_instance
except ImportError:
    from middleware.rate_limiter import get_client_ip, block_ip
    from middleware.redis_rate_limit import tracker_instance

logger = logging.getLogger("strata.honeypot")

router = APIRouter(tags=["Active Security Honeypots"])


async def trigger_honeypot(request: Request, trap_name: str) -> JSONResponse:
    """
    Common handler for honeypot triggers:
    1. Immediately bans attacker IP for 24 hours (86400 seconds).
    2. Pushes high-severity threat event to Redis stream:threats list.
    3. Records security alert in ThreatTracker.
    4. Returns HTTP 403 Forbidden payload.
    """
    client_ip = get_client_ip(request)
    path = request.url.path
    timestamp = datetime.now(timezone.utc).isoformat()
    redis_client = getattr(request.app.state, "redis", None) or tracker_instance.redis

    # 1. Ban attacker for 24 hours (86400s)
    await block_ip(redis_client, client_ip, duration_seconds=86400)

    # 2. Push security event to Redis stream:threats
    threat_event = {
        "event": "HONEYPOT_TRIGGERED",
        "trap": trap_name,
        "ip": client_ip,
        "path": path,
        "timestamp": timestamp
    }
    if redis_client:
        try:
            event_json = json.dumps(threat_event)
            if inspect.iscoroutinefunction(getattr(redis_client, "lpush", None)):
                await redis_client.lpush("stream:threats", event_json)
                await redis_client.ltrim("stream:threats", 0, 999)
            elif hasattr(redis_client, "lpush"):
                redis_client.lpush("stream:threats", event_json)
                redis_client.ltrim("stream:threats", 0, 999)
        except Exception as e:
            logger.warning(f"Error pushing threat event to Redis stream: {e}")

    # 3. Log high-severity alert
    tracker_instance.add_alert(
        severity="HIGH",
        message=f"Honeypot trap '{trap_name}' triggered at path '{path}' by IP {client_ip}. Banned for 24 hours."
    )

    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={
            "error": "Access Denied: Honeypot trap triggered by STRATA Threat Gateway",
            "trap": trap_name,
            "ip": client_ip,
            "path": path
        }
    )


@router.get("/wp-admin")
async def honeypot_wp_admin(request: Request):
    """Honeypot trap for automated WordPress admin scanners."""
    return await trigger_honeypot(request, "WordPress Admin Probe")


@router.post("/wp-login.php")
async def honeypot_wp_login(request: Request):
    """Honeypot trap for automated WordPress login brute-forcers."""
    return await trigger_honeypot(request, "WordPress Login Probe")


@router.get("/.env")
async def honeypot_dot_env(request: Request):
    """Honeypot trap for environment file harvesting probes."""
    return await trigger_honeypot(request, "Environment File Probe (.env)")


@router.get("/.git/config")
async def honeypot_git_config(request: Request):
    """Honeypot trap for Git configuration file harvesting probes."""
    return await trigger_honeypot(request, "Git Config Probe (.git/config)")


@router.get("/api/v1/debug/secrets")
async def honeypot_debug_secrets(request: Request):
    """Honeypot trap for internal API debug endpoint exposure probes."""
    return await trigger_honeypot(request, "Internal API Secrets Probe")
