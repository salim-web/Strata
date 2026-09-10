import os
import sys
import logging
import asyncio
from typing import Optional, Dict, Any
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
import redis.asyncio as aioredis

# Add project root and backend directory to sys.path
root_dir = Path(__file__).resolve().parent.parent
backend_dir = Path(__file__).resolve().parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from dotenv import load_dotenv
load_dotenv()

try:
    from backend.config import settings
except ImportError:
    from config import settings

from backend.pipeline import pipeline_instance
from backend.ingest.receiver import receiver_instance
from backend.ingest.generator import ambient_emitter
from backend.routes.diode import router as diode_router, get_legacy_threat_metrics
from backend.routes.threats import router as threats_router

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("strata.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Async lifespan context manager:
    1. Starts the passive telemetry streaming pipeline worker.
    2. Starts the continuous ambient telemetry emitter (~2,500 flows/sec).
    3. Gracefully stops workers on shutdown.
    """
    logger.info("Starting Passive Network Threat Intelligence Enclave...")
    
    # 1. Start Passive Telemetry Ingest & Feature Extraction Pipeline
    await pipeline_instance.start()
    
    # 2. Start Continuous Ambient Telemetry Emitter (2,500 flows/sec baseline)
    await ambient_emitter.start()
    
    # 3. Redis connection (optional, for persistent metric snapshots)
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
        logger.info("Connected to Redis instance.")
    except Exception as e:
        logger.info("Running in resilient in-memory data diode mode.")
        app.state.redis = None

    yield

    logger.info("Shutting down Passive Network Threat Intelligence Enclave...")
    await ambient_emitter.stop()
    await pipeline_instance.stop()
    try:
        if app.state.redis:
            await app.state.redis.aclose()
    except Exception as e:
        logger.warning(f"Error closing Redis: {e}")


app = FastAPI(
    title="STRATA Passive Network Threat Intelligence Enclave",
    description="Autonomous, read-only threat detection engine adhering to unidirectional data diode constraints.",
    version="2.0.0",
    lifespan=lifespan
)

# STRICTLY REMOVED: RateLimitMiddleware and all inline blocking logic!
# Configure CORS middleware
origins = settings.ALLOWED_ORIGINS if settings.ALLOWED_ORIGINS else ["http://localhost:3000", "http://127.0.0.1:3000"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers (Diode & Passive Threat Observability)
app.include_router(diode_router)
app.include_router(threats_router)


@app.get("/api/threat-metrics")
@app.get("/api/v1/threat-metrics")
async def get_threat_metrics():
    """
    Backward-compatible telemetry endpoint for frontend dashboard polling.
    Adheres strictly to unidirectional diode constraints: 0 blocked IPs, read-only mode.
    """
    return await get_legacy_threat_metrics()


@app.get("/")
async def root():
    return {
        "enclave": "STRATA Passive Network Threat Intelligence Enclave",
        "architecture": "Unidirectional Data Diode / Passive Mirroring",
        "mode": "READ_ONLY",
        "return_path_active": False,
        "docs": "/docs"
    }


@app.get("/health")
async def health_check():
    kpis = receiver_instance.get_kpis()
    return {
        "status": "healthy",
        "diode_mode": "READ_ONLY",
        "sustained_flows_per_sec": kpis.sustained_flows_per_sec,
        "active_anomalies": kpis.active_anomalies_count,
        "pipeline_latency_ms": kpis.pipeline_latency_ms
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("backend.main:app", host="0.0.0.0", port=port, reload=True)
