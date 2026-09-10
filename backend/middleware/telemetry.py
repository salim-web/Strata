import time
import math
import json
import inspect
import asyncio
import logging
from typing import Dict, Any, Optional
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

try:
    from backend.middleware.rate_limiter import get_client_ip
except ImportError:
    from middleware.rate_limiter import get_client_ip

try:
    from backend.middleware.redis_rate_limit import tracker_instance
except ImportError:
    from middleware.redis_rate_limit import tracker_instance

try:
    from backend.services.ml_client import evaluate_request_anomaly
except ImportError:
    try:
        from services.ml_client import evaluate_request_anomaly
    except ImportError:
        evaluate_request_anomaly = None

logger = logging.getLogger("strata.telemetry")


def calculate_shannon_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of a string to identify automated bot scrapers & anomalous payloads.
    """
    if not text:
        return 0.0
    length = len(text)
    char_counts: Dict[str, int] = {}
    for char in text:
        char_counts[char] = char_counts.get(char, 0) + 1

    entropy = 0.0
    for count in char_counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 4)


class TelemetryMiddleware(BaseHTTPMiddleware):
    """
    Middleware extracting security telemetry features from incoming HTTP requests
    and streaming events to Redis for ML anomaly detection.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint):
        current_time_sec = time.time()
        timestamp_ms = int(current_time_sec * 1000)

        client_ip = get_client_ip(request)
        endpoint = request.url.path
        method = request.method

        # Payload size from Content-Length header
        try:
            payload_size = int(request.headers.get("content-length", 0))
        except (ValueError, TypeError):
            payload_size = 0

        # Calculate Shannon entropy over User-Agent + header representation
        user_agent = request.headers.get("user-agent", "")
        headers_str = f"{user_agent}|{'|'.join(request.headers.keys())}"
        header_entropy = calculate_shannon_entropy(headers_str)

        # Request velocity: count of requests from this IP in the last 10 seconds
        redis_client = getattr(request.app.state, "redis", None) or tracker_instance.redis
        request_velocity = 1

        if redis_client:
            try:
                zset_key = f"rate_limit:{client_ip}"
                zcount_fn = getattr(redis_client, "zcount", None)
                if zcount_fn:
                    vel = zcount_fn(zset_key, current_time_sec - 10, "+inf")
                    if inspect.isawaitable(vel):
                        vel = await vel
                    request_velocity = max(1, vel)
            except Exception as e:
                logger.debug(f"Error reading velocity from Redis: {e}")

        query_str = str(request.url.query) if request.url.query else ""
        from ml_engine.inference import has_sqli_syntax
        telemetry_data = {
            "client_ip": client_ip,
            "endpoint": endpoint,
            "method": method,
            "timestamp": timestamp_ms,
            "payload_size": payload_size,
            "header_entropy": header_entropy,
            "request_velocity": request_velocity,
            "raw_payload": f"{endpoint}?{query_str}" if query_str else endpoint,
            "is_potential_sqli": has_sqli_syntax(query_str),
            "is_potential_xss": any(p in query_str.lower() for p in ["<script>", "</script>", "javascript:", "onerror="])
        }

        # Attach telemetry to request.state for downstream route handlers / ML inspection
        request.state.telemetry = telemetry_data

        # Async non-blocking push of telemetry to stream:telemetry
        if redis_client:
            try:
                telemetry_json = json.dumps(telemetry_data)
                lpush_res = getattr(redis_client, "lpush", lambda *args: None)("stream:telemetry", telemetry_json)
                if inspect.isawaitable(lpush_res):
                    await lpush_res
                ltrim_res = getattr(redis_client, "ltrim", lambda *args: None)("stream:telemetry", 0, 999)
                if inspect.isawaitable(ltrim_res):
                    await ltrim_res
            except Exception as e:
                logger.debug(f"Failed streaming telemetry to Redis: {e}")

        response = await call_next(request)

        # Async ML Anomaly Evaluation for active traffic respecting active sampling rate
        excluded_ml_paths = [
            "/health", "/docs", "/openapi.json", "/redoc", "/",
            "/api/threat-metrics", "/api/v1/threat-metrics",
            "/api/v1/threats/feed", "/api/v1/threats/stats", "/api/v1/threats/blocked-ips",
            "/.env", "/wp-admin", "/wp-login.php", "/.git/config", "/api/v1/debug/secrets"
        ]
        if evaluate_request_anomaly and endpoint not in excluded_ml_paths:
            import random
            sampling_rate = tracker_instance.get_sampling_rate()
            is_critical = telemetry_data.get("is_potential_sqli") or telemetry_data.get("is_potential_xss") or request_velocity > 30

            if is_critical or (random.random() < sampling_rate):
                tracker_instance.increment_sampled_requests()
                try:
                    asyncio.create_task(evaluate_request_anomaly(telemetry_data, redis_client))
                except Exception as e:
                    logger.debug(f"Async ML anomaly check error: {e}")
            else:
                tracker_instance.increment_bypassed_requests()

        return response
