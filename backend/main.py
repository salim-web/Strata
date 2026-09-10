import os
import sys
import logging
import asyncio
from datetime import timedelta
from typing import Optional, Dict, Any
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status, Body, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import redis.asyncio as aioredis

# Add project root and backend directory to sys.path
root_dir = Path(__file__).resolve().parent.parent
backend_dir = Path(__file__).resolve().parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

try:
    from backend.config import settings
except ImportError:
    from config import settings

try:
    from backend.middleware.rate_limiter import RateLimitMiddleware
    from backend.middleware.telemetry import TelemetryMiddleware
    from backend.middleware.auth import create_access_token, verify_jwt_token
    from backend.middleware.redis_rate_limit import tracker_instance
    from backend.routes.dummy_api import router as dummy_router
    from backend.routes.honeypot import router as honeypot_router
    from backend.routes.targets import router as targets_router
    from backend.routes.threats import router as threats_router
except ImportError:
    from middleware.rate_limiter import RateLimitMiddleware
    from middleware.telemetry import TelemetryMiddleware
    from middleware.auth import create_access_token, verify_jwt_token
    from middleware.redis_rate_limit import tracker_instance
    from routes.dummy_api import router as dummy_router
    from routes.honeypot import router as honeypot_router
    from routes.targets import router as targets_router
    from routes.threats import router as threats_router

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("strata.main")


class TokenRequestPayload(BaseModel):
    user_id: str = Field("user_123", json_schema_extra={"example": "user_123"})
    role: str = Field("admin", json_schema_extra={"example": "admin"})
    scopes: list[str] = Field(["read", "write"], json_schema_extra={"example": ["read", "write"]})
    expires_minutes: int = Field(15, json_schema_extra={"example": 15})


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Async lifespan context manager to initialize and gracefully close
    the Redis connection pool on startup and shutdown.
    """
    logger.info("Initializing Redis async connection pool...")
    host = "127.0.0.1" if settings.REDIS_HOST == "localhost" else settings.REDIS_HOST
    redis_client = aioredis.Redis(
        host=host,
        port=settings.REDIS_PORT,
        db=settings.REDIS_DB,
        decode_responses=True,
        socket_connect_timeout=0.3,
        socket_timeout=0.3,
        protocol=2
    )
    app.state.redis = redis_client

    try:
        await asyncio.wait_for(redis_client.ping(), timeout=0.3)
        logger.info("Successfully connected to Redis instance.")
    except Exception as e:
        logger.warning(f"Redis unreachable during startup ({e}). Running in resilient in-memory mode.")
        app.state.redis = None

    yield

    logger.info("Closing Redis connection pool...")
    try:
        await redis_client.aclose()
        logger.info("Redis connection pool gracefully closed.")
    except Exception as e:
        logger.warning(f"Error closing Redis connection: {e}")


app = FastAPI(
    title="STRATA API Gateway",
    description="Real-time FastAPI & Redis threat detection and rate limiting engine.",
    version="1.0.0",
    lifespan=lifespan
)

# Register Telemetry & Rate Limiting Middlewares globally
app.add_middleware(RateLimitMiddleware)
app.add_middleware(TelemetryMiddleware)

# Configure CORS middleware dynamically using settings (Must be OUTERMOST)
origins = settings.ALLOWED_ORIGINS if settings.ALLOWED_ORIGINS else ["http://localhost:3000"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(dummy_router)
app.include_router(honeypot_router)
app.include_router(targets_router)
app.include_router(threats_router)


@app.post("/api/auth/token")
@app.post("/api/v1/auth/token")
async def generate_mock_token(payload: TokenRequestPayload = Body(...)):
    """
    Utility route for generating signed mock JWT test tokens during development and testing.
    """
    token_data = {
        "sub": payload.user_id,
        "user_id": payload.user_id,
        "role": payload.role,
        "scopes": payload.scopes
    }
    access_token = create_access_token(
        data=token_data,
        expires_delta=timedelta(minutes=payload.expires_minutes)
    )
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in_minutes": payload.expires_minutes
    }


@app.get("/api/threat-metrics")
@app.get("/api/v1/threat-metrics")
async def get_threat_metrics(request: Request):
    """
    Frontend Interface Contract endpoint returning total requests, blocked IPs count,
    blocked IP list, and recent security alerts.
    """
    snapshot = tracker_instance.get_metrics_snapshot()
    redis_client = getattr(request.app.state, "redis", None)
    if redis_client:
        try:
            total = await asyncio.wait_for(redis_client.get("total_requests"), timeout=1.0)
            snapshot["total_requests"] = int(total) if total else 0
        except Exception:
            pass
    return snapshot


class ManualUnblockPayload(BaseModel):
    ip: str = Field(..., json_schema_extra={"example": "192.168.1.105"})


class SamplingConfigRequest(BaseModel):
    sample_rate: float = Field(..., json_schema_extra={"example": 0.5})


@app.post("/api/config/sampling")
@app.post("/api/v1/config/sampling")
async def update_sampling_config(request: Request, payload: SamplingConfigRequest = Body(...)):
    """
    Dynamically update API traffic sampling rate for local ML threat detection engine.
    """
    rate = max(0.05, min(1.0, float(payload.sample_rate)))
    redis_client = getattr(request.app.state, "redis", None)
    if redis_client:
        try:
            await redis_client.set("config:sampling_rate", str(rate))
        except Exception as e:
            logger.warning(f"Failed to update Redis sampling rate: {e}")

    tracker_instance.set_sampling_rate(rate)
    rate_pct = int(round(rate * 100))
    saved_pct = int(round((1.0 - rate) * 100))

    tracker_instance.add_alert(
        severity="LOW",
        message=f"API Sampling Rate adjusted to {rate_pct}% ({saved_pct}% compute overhead saved)."
    )

    return {
        "status": "success",
        "sampling_rate": rate,
        "sampling_rate_pct": rate_pct,
        "compute_saved_pct": saved_pct
    }


@app.post("/api/unblock-ip")
@app.post("/api/v1/unblock-ip")
async def manual_unblock_ip(request: Request, payload: ManualUnblockPayload = Body(...)):
    """
    Manually unblocks a blacklisted IP address from Redis and ThreatTracker.
    """
    redis_client = getattr(request.app.state, "redis", None) or tracker_instance.redis
    
    try:
        from backend.middleware.rate_limiter import unblock_ip
    except ImportError:
        from middleware.rate_limiter import unblock_ip
        
    await unblock_ip(redis_client, payload.ip.strip())
    
    tracker_instance.add_alert(
        severity="MEDIUM",
        message=f"IP {payload.ip.strip()} was manually unblocked."
    )
    
    return {
        "status": "success",
        "message": f"IP {payload.ip.strip()} unblocked successfully.",
        "ip": payload.ip.strip()
    }



@app.get("/")
async def root():
    return {
        "system": "STRATA API Gateway",
        "status": "active",
        "docs": "/docs"
    }


@app.get("/health")
async def health_check(request: Request):
    """
    Health check endpoint verifying application status and Redis ping connection.
    Returns: {"status": "healthy", "redis": "connected" | "disconnected"}
    """
    redis_status = "disconnected"
    redis_client = getattr(request.app.state, "redis", None)

    if redis_client:
        try:
            is_alive = await asyncio.wait_for(redis_client.ping(), timeout=0.3)
            if is_alive:
                redis_status = "connected"
        except Exception:
            redis_status = "disconnected"

    return {
        "status": "healthy",
        "redis": redis_status
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("backend.main:app", host="0.0.0.0", port=port, reload=True)
