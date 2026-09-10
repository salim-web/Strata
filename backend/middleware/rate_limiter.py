import os
import sys
import time
import uuid
import inspect
import logging
from typing import Optional, Dict, List, Set, Tuple, Any
from fastapi import Request, status
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse

try:
    from backend.config import settings
except ImportError:
    from config import settings

try:
    from backend.middleware.redis_rate_limit import tracker_instance
except ImportError:
    from middleware.redis_rate_limit import tracker_instance

logger = logging.getLogger("strata.rate_limiter")


def get_client_ip(request: Request) -> str:
    """
    Safely extract real client IP address handling X-Forwarded-For header
    and falling back to request.client.host.
    """
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        # X-Forwarded-For can be a comma-separated list of IPs; first one is client IP
        client_ip = forwarded_for.split(",")[0].strip()
        if client_ip:
            return client_ip

    if request.client and request.client.host:
        return request.client.host

    return "127.0.0.1"


async def _safe_await(val):
    if inspect.isawaitable(val):
        return await val
    return val


async def block_ip(redis_client, ip: str, duration_seconds: int = 3600) -> None:
    """
    Programmatically blacklists an IP address in Redis and in-memory fallback.
    """
    if ip in ["127.0.0.1", "localhost", "::1"]:
        return

    blacklist_key = f"blacklist:{ip}"
    if redis_client:
        try:
            await _safe_await(redis_client.set(blacklist_key, "1", ex=duration_seconds))
            await _safe_await(redis_client.sadd("blocked_ips_set", ip))
        except Exception as e:
            logger.warning(f"Redis error during block_ip for {ip}: {e}")

    tracker_instance.block_ip(ip, reason=f"Programmatically blacklisted for {duration_seconds}s")


async def unblock_ip(redis_client, ip: str) -> None:
    """
    Removes an IP address from the Redis and in-memory blacklist.
    """
    blacklist_key = f"blacklist:{ip}"
    violations_key = f"violations:{ip}"
    if redis_client:
        try:
            await _safe_await(redis_client.delete(blacklist_key))
            await _safe_await(redis_client.delete(violations_key))
            await _safe_await(redis_client.srem("blocked_ips_set", ip))
        except Exception as e:
            logger.warning(f"Redis error during unblock_ip for {ip}: {e}")

    if ip in tracker_instance.in_memory_metrics["blocked_ips"]:
        tracker_instance.in_memory_metrics["blocked_ips"].remove(ip)
    logger.info(f"IP {ip} has been unblocked.")


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Async Redis-based sliding-window rate limiting and dynamic IP blocking middleware.
    """

    def __init__(self, app):
        super().__init__(app)
        # In-memory fallbacks when Redis is offline
        self.memory_timestamps: Dict[str, List[float]] = {}
        self.memory_violations: Dict[str, int] = {}
        self.memory_blacklist: Dict[str, float] = {}  # ip -> expiry timestamp

    async def is_blacklisted(self, redis_client, ip: str) -> bool:
        """Check if client IP is blacklisted in Redis or in-memory fallback."""
        if ip in ["127.0.0.1", "localhost", "::1"]:
            return False
        current_time = time.time()

        # Check in-memory expiry
        if ip in self.memory_blacklist:
            if current_time < self.memory_blacklist[ip]:
                return True
            else:
                del self.memory_blacklist[ip]

        if tracker_instance.is_ip_blocked(ip):
            return True

        if redis_client:
            try:
                blacklist_key = f"blacklist:{ip}"
                val = await _safe_await(redis_client.get(blacklist_key))
                if val is not None:
                    return True
            except Exception as e:
                logger.warning(f"Redis error checking blacklist for {ip}: {e}")

        return False

    async def check_rate_limit(self, redis_client, ip: str) -> Tuple[bool, int, int]:
        """
        Sliding-window ZSET algorithm using Redis or in-memory fallback.
        Returns: (is_allowed: bool, request_count: int, violation_count: int)
        """
        current_time = time.time()
        rate_limit_requests = settings.RATE_LIMIT_REQUESTS
        window_seconds = settings.RATE_LIMIT_WINDOW_SECONDS
        zset_key = f"rate_limit:{ip}"
        violations_key = f"violations:{ip}"

        request_count = 0
        violation_count = 0

        if redis_client:
            try:
                pipe = redis_client.pipeline()
                pipe.zremrangebyscore(zset_key, 0, current_time - window_seconds)
                pipe.zadd(zset_key, {f"{current_time}:{uuid.uuid4().hex[:6]}": current_time})
                pipe.zcard(zset_key)
                pipe.expire(zset_key, window_seconds)
                results = await _safe_await(pipe.execute())
                request_count = results[2]

                if request_count > rate_limit_requests:
                    violation_count = await _safe_await(redis_client.incr(violations_key))
                    await _safe_await(redis_client.expire(violations_key, window_seconds * 10))

                return request_count <= rate_limit_requests, request_count, violation_count
            except Exception as e:
                logger.warning(f"Redis error during rate limit check for {ip}: {e}")

        # In-memory fallback
        timestamps = self.memory_timestamps.get(ip, [])
        valid_ts = [ts for ts in timestamps if ts > current_time - window_seconds]
        valid_ts.append(current_time)
        self.memory_timestamps[ip] = valid_ts
        request_count = len(valid_ts)

        if request_count > rate_limit_requests:
            self.memory_violations[ip] = self.memory_violations.get(ip, 0) + 1
            violation_count = self.memory_violations[ip]

        return request_count <= rate_limit_requests, request_count, violation_count

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint):
        path = request.url.path

        # Excluded paths: health, docs, root, dashboard metrics/threat observability, honeypot traps
        DASHBOARD_PATHS = [
            "/health", "/docs", "/openapi.json", "/redoc", "/",
            "/api/threat-metrics", "/api/v1/threat-metrics",
            "/api/v1/threats/feed", "/api/v1/threats/stats",
            "/api/v1/threats/blocked-ips", "/api/v1/threats/unblock"
        ]
        HONEYPOT_PATHS = ["/.env", "/wp-admin", "/wp-login.php", "/.git/config", "/api/v1/debug/secrets"]
        if path in DASHBOARD_PATHS or path in HONEYPOT_PATHS:
            return await call_next(request)

        client_ip = get_client_ip(request)
        redis_client = getattr(request.app.state, "redis", None) or tracker_instance.redis

        # Track total global requests
        tracker_instance.increment_total_requests()

        # 1. Dynamic IP Blacklist Verification
        if await self.is_blacklisted(redis_client, client_ip):
            tracker_instance.increment_blocked_requests()
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"error": "Access Denied: IP blocked by STRATA Threat Gateway"}
            )

        # 2. Sliding-Window Rate Check
        allowed, count, violations = await self.check_rate_limit(redis_client, client_ip)

        rate_limit_requests = settings.RATE_LIMIT_REQUESTS
        window_seconds = settings.RATE_LIMIT_WINDOW_SECONDS

        if not allowed:
            tracker_instance.increment_blocked_requests()
            if count % 10 == 0 or violations == 1:
                tracker_instance.add_alert(
                    severity="HIGH",
                    message=f"Distributed Token-Bucket Exhaustion (DDoS Spike) detected from IP {client_ip} - {count} req/min"
                )

            headers = {
                "X-RateLimit-Limit": str(rate_limit_requests),
                "X-RateLimit-Remaining": "0",
                "Retry-After": str(window_seconds)
            }
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "detail": "Rate limit exceeded. Too many requests.",
                    "ip": client_ip
                },
                headers=headers
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(rate_limit_requests)
        response.headers["X-RateLimit-Remaining"] = str(max(0, rate_limit_requests - count))
        return response
