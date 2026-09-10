import os
import time
import json
import uuid
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any, Tuple
from fastapi import Request, status
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse

logger = logging.getLogger("strata.rate_limit")

# --- ML Interface Contract Import Wrapper ---
try:
    from ml_engine.inference import detect_anomaly
except Exception:
    def detect_anomaly(payload: str, request_rate: int) -> bool:
        """Fallback ML anomaly detector mock."""
        return request_rate > 100 or len(payload) > 5000

try:
    from ml_engine.ai_reporter import generate_threat_report
except Exception:
    def generate_threat_report(ip: str, attack_type: str, raw_payload: str) -> str:
        """Fallback ML threat report generator mock."""
        return f"[CISO Incident Summary] Anomaly flagged from {ip} with vector {attack_type}."


class ThreatTracker:
    """
    Threat metrics, IP rate limiting, and blocking tracker backed by Redis
    with an automatic in-memory fallback.
    """

    def __init__(self, rate_limit: int = 50, window_seconds: int = 60):
        self.rate_limit = rate_limit
        self.window_seconds = window_seconds

        # Redis client setup (optional)
        redis_host = os.getenv("REDIS_HOST", "127.0.0.1")
        if redis_host == "localhost":
            redis_host = "127.0.0.1"
        redis_port = int(os.getenv("REDIS_PORT", 6379))
        try:
            import redis
            client = redis.Redis(host=redis_host, port=redis_port, db=0, decode_responses=True, socket_connect_timeout=0.3, socket_timeout=0.3, protocol=2)
            client.ping()
            self.redis = client
            logger.info("Connected to Redis successfully for ThreatTracker.")
        except Exception as e:
            logger.warning(f"Redis unavailable ({e}). Using in-memory fallback store.")
            self.redis = None

        # In-memory storage fallback
        self.memory_store: Dict[str, List[float]] = {}
        self.in_memory_incidents: List[Dict[str, Any]] = []
        self.in_memory_metrics = {
            "total_requests": 0,
            "blocked_ips": set(),
            "sampling_rate": 1.0,
            "sampled_requests_count": 0,
            "bypassed_requests_count": 0,
            "alerts": [
                {
                    "id": "alert_init_1",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "severity": "LOW",
                    "message": "STRATA Threat Defense Gateway started successfully."
                }
            ]
        }
        self.current_anomaly_score = 0.12
        try:
            from backend.services.ml_client import benchmark_ml_latency
            self.last_ml_latency_ms = benchmark_ml_latency()
        except Exception:
            try:
                from services.ml_client import benchmark_ml_latency
                self.last_ml_latency_ms = benchmark_ml_latency()
            except Exception:
                self.last_ml_latency_ms = 8.2

    def set_sampling_rate(self, rate: float) -> None:
        """Set active API sampling rate (0.05 to 1.0)."""
        rate = max(0.05, min(1.0, float(rate)))
        self.in_memory_metrics["sampling_rate"] = rate
        if self.redis:
            try:
                self.redis.set("config:sampling_rate", str(rate))
            except Exception as e:
                logger.warning(f"Redis set config:sampling_rate error: {e}")

    def get_sampling_rate(self) -> float:
        """Retrieve current sampling rate."""
        if self.redis:
            try:
                val = self.redis.get("config:sampling_rate")
                if val is not None:
                    return float(val)
            except Exception:
                pass
        return self.in_memory_metrics.get("sampling_rate", 1.0)

    def increment_sampled_requests(self) -> int:
        """Increment count of requests processed by ML inspection."""
        self.in_memory_metrics["sampled_requests_count"] += 1
        if self.redis:
            try:
                val = self.redis.incr("sampled_requests_count")
                return int(val)
            except Exception:
                pass
        return self.in_memory_metrics["sampled_requests_count"]

    def increment_bypassed_requests(self) -> int:
        """Increment count of requests that bypassed ML inspection to save compute."""
        self.in_memory_metrics["bypassed_requests_count"] += 1
        if self.redis:
            try:
                val = self.redis.incr("bypassed_requests_count")
                return int(val)
            except Exception:
                pass
        return self.in_memory_metrics["bypassed_requests_count"]

    def get_sampled_requests_count(self) -> int:
        if self.redis:
            try:
                val = self.redis.get("sampled_requests_count")
                if val is not None:
                    return int(val)
            except Exception:
                pass
        return self.in_memory_metrics.get("sampled_requests_count", 0)

    def get_bypassed_requests_count(self) -> int:
        if self.redis:
            try:
                val = self.redis.get("bypassed_requests_count")
                if val is not None:
                    return int(val)
            except Exception:
                pass
        return self.in_memory_metrics.get("bypassed_requests_count", 0)

    def increment_total_requests(self) -> int:
        """Increment cumulative total requests count."""
        if self.redis:
            try:
                return int(self.redis.incr("total_requests"))
            except Exception as e:
                logger.warning(f"Redis incr error: {e}")
        self.in_memory_metrics["total_requests"] += 1
        return self.in_memory_metrics["total_requests"]

    def get_total_requests(self) -> int:
        if self.redis:
            try:
                val = self.redis.get("total_requests")
                return int(val) if val else 0
            except Exception as e:
                logger.error(f"get_total_requests error: {e}")
        return self.in_memory_metrics["total_requests"]

    def is_ip_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked."""
        if self.redis:
            try:
                return bool(self.redis.sismember("blocked_ips_set", ip))
            except Exception as e:
                logger.warning(f"Redis sismember error: {e}")
        return ip in self.in_memory_metrics["blocked_ips"]

    def block_ip(self, ip: str, reason: str = "Exceeded request rate limit") -> None:
        """Block an IP address and record alert metric."""
        if self.redis:
            try:
                self.redis.sadd("blocked_ips_set", ip)
            except Exception as e:
                logger.warning(f"Redis sadd error: {e}")
        
        self.in_memory_metrics["blocked_ips"].add(ip)
        logger.warning(f"IP {ip} blocked. Reason: {reason}")

        # Record alert
        alert_msg = f"IP {ip} blocked: {reason}"
        self.add_alert(severity="HIGH", message=alert_msg)

    def get_blocked_ips(self) -> List[str]:
        if self.redis:
            try:
                ips = list(self.redis.smembers("blocked_ips_set"))
                return ips
            except Exception:
                pass
        return list(self.in_memory_metrics["blocked_ips"])

    def add_alert(self, severity: str, message: str) -> None:
        """Add a recent threat alert."""
        alert = {
            "id": f"alert_{uuid.uuid4().hex[:8]}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": severity,
            "message": message
        }
        if self.redis:
            try:
                self.redis.lpush("recent_alerts_list", json.dumps(alert))
                self.redis.ltrim("recent_alerts_list", 0, 99)
            except Exception as e:
                logger.warning(f"Redis lpush error: {e}")

        # In-memory storage
        self.in_memory_metrics["alerts"].insert(0, alert)
        self.in_memory_metrics["alerts"] = self.in_memory_metrics["alerts"][:100]

    def get_recent_alerts(self, limit: int = 20) -> List[Dict[str, Any]]:
        if self.redis:
            try:
                raw_list = self.redis.lrange("recent_alerts_list", 0, limit - 1)
                if raw_list:
                    return [json.loads(item) for item in raw_list]
            except Exception as e:
                logger.warning(f"Redis lrange error: {e}")
        return self.in_memory_metrics["alerts"][:limit]

    def add_incident(self, incident: Dict[str, Any]) -> None:
        """Add an evaluated incident record to Redis and in-memory storage."""
        if self.redis:
            try:
                self.redis.lpush("list:incidents", json.dumps(incident))
                self.redis.ltrim("list:incidents", 0, 99)
            except Exception as e:
                logger.warning(f"Redis lpush error for list:incidents: {e}")
        
        self.in_memory_incidents.insert(0, incident)
        self.in_memory_incidents = self.in_memory_incidents[:100]

    def get_incidents(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve latest incidents from Redis or in-memory fallback."""
        if self.redis:
            try:
                raw_list = self.redis.lrange("list:incidents", 0, limit - 1)
                if raw_list:
                    return [json.loads(item) for item in raw_list]
            except Exception as e:
                logger.warning(f"Redis lrange error for list:incidents: {e}")
        return self.in_memory_incidents[:limit]

    def check_rate_limit(self, ip: str) -> Tuple[bool, int]:
        """
        Check if request count for IP in sliding window exceeds rate_limit.
        Returns: (is_allowed: bool, current_request_count: int)
        """
        current_time = time.time()

        if self.redis:
            try:
                key = f"rate_limit:{ip}"
                pipeline = self.redis.pipeline()
                pipeline.zremrangebyscore(key, 0, current_time - self.window_seconds)
                pipeline.zadd(key, {f"{current_time}:{uuid.uuid4().hex[:6]}": current_time})
                pipeline.zcard(key)
                pipeline.expire(key, self.window_seconds)
                results = pipeline.execute()
                request_count = results[2]
                return request_count <= self.rate_limit, request_count
            except Exception as e:
                logger.warning(f"Redis zset error: {e}")

        # In-memory fallback algorithm
        timestamps = self.memory_store.get(ip, [])
        valid_timestamps = [ts for ts in timestamps if ts > current_time - self.window_seconds]
        valid_timestamps.append(current_time)
        self.memory_store[ip] = valid_timestamps

        count = len(valid_timestamps)
        return count <= self.rate_limit, count

    def increment_blocked_requests(self):
        if "blocked_requests_count" not in self.in_memory_metrics:
            self.in_memory_metrics["blocked_requests_count"] = 0
        self.in_memory_metrics["blocked_requests_count"] += 1

    def get_blocked_requests_count(self) -> int:
        return self.in_memory_metrics.get("blocked_requests_count", 0)

    def get_metrics_snapshot(self) -> Dict[str, Any]:
        """
        Returns exact JSON structure required by Frontend contract:
        {
          "total_requests": int,
          "blocked_ips_count": int,
          "blocked_requests_count": int,
          "blocked_ips_list": list[str],
          "recent_alerts": [
            {
              "id": str,
              "timestamp": str,
              "severity": "HIGH" | "MEDIUM" | "LOW",
              "message": str
            }
          ]
        }
        """
        blocked_list = self.get_blocked_ips()
        rate = self.get_sampling_rate()
        
        # Apply exponential decay to anomaly score so it doesn't get stuck after a spike
        current_score = getattr(self, "current_anomaly_score", 0.12)
        if current_score > 0.12:
            decayed = 0.12 + (current_score - 0.12) * 0.85
            if decayed < 0.13:
                decayed = 0.12
            self.current_anomaly_score = decayed
            current_score = decayed

        return {
            "total_requests": self.get_total_requests(),
            "blocked_ips_count": len(blocked_list),
            "blocked_requests_count": self.get_blocked_requests_count(),
            "blocked_ips_list": blocked_list,
            "sampling_rate": rate,
            "sampling_rate_pct": int(round(rate * 100)),
            "sampled_requests_count": self.get_sampled_requests_count(),
            "bypassed_requests_count": self.get_bypassed_requests_count(),
            "compute_saved_pct": int(round((1.0 - rate) * 100)),
            "current_anomaly_score": round(current_score, 4),
            "ml_latency_ms": round(float(getattr(self, "last_ml_latency_ms", 9.3)), 2),
            "recent_alerts": self.get_recent_alerts(limit=25)
        }


# Global Singleton Tracker Instance
tracker_instance = ThreatTracker(rate_limit=50, window_seconds=60)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Middleware intercepting incoming requests for threat monitoring,
    rate limiting, IP blocking, and ML anomaly detection.
    """

    def __init__(self, app, tracker: Optional[ThreatTracker] = None):
        super().__init__(app)
        self.tracker = tracker or tracker_instance

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint):
        client_ip = request.client.host if request.client else "127.0.0.1"

        # Bypass rate limit check for health & root docs endpoints
        path = request.url.path
        if path in ["/health", "/docs", "/openapi.json", "/"]:
            return await call_next(request)

        # 1. Track total request count
        self.tracker.increment_total_requests()

        # 2. Check if IP is already blocked
        if self.tracker.is_ip_blocked(client_ip):
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "Too Many Requests",
                    "detail": "Too Many Requests. IP address has been blocked.",
                    "ip": client_ip
                }
            )

        # 3. Check rate limiting threshold (50 req / 60 sec)
        allowed, count = self.tracker.check_rate_limit(client_ip)
        if not allowed:
            self.tracker.increment_blocked_requests()
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "Too Many Requests",
                    "detail": "Rate limit exceeded. Too many requests.",
                    "ip": client_ip,
                    "request_count": count
                }
            )

        # 4. Optional ML Anomaly Detection Integration
        try:
            header_entropy = len(set(str(request.headers))) / max(1, len(str(request.headers))) * 10
            is_anomaly = detect_anomaly(
                req_frequency=float(count),
                payload_size=float(request.headers.get("content-length", 0)),
                header_entropy=header_entropy,
                error_rate=0.0
            )

            if is_anomaly:
                report = generate_threat_report({
                    "ip": client_ip,
                    "threat_type": "ANOMALOUS_BEHAVIOR",
                    "anomaly_score": 0.95
                })
                self.tracker.add_alert(severity="HIGH", message=f"ML Anomaly Flagged for {client_ip}: {report}")
        except Exception as e:
            logger.debug(f"ML check skipped: {e}")

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(self.tracker.rate_limit)
        response.headers["X-RateLimit-Remaining"] = str(max(0, self.tracker.rate_limit - count))
        return response
