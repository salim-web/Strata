export interface ThreatAlert {
  id: string;
  timestamp: string;
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  message: string;
}

export interface ThreatMetrics {
  total_requests: number;
  blocked_ips_count: number;
  blocked_requests_count?: number;
  blocked_ips_list: string[];
  recent_alerts: ThreatAlert[];
  sampling_rate?: number;
  sampling_rate_pct?: number;
  sampled_requests_count?: number;
  bypassed_requests_count?: number;
  compute_saved_pct?: number;
  current_anomaly_score?: number;
  ml_latency_ms?: number;
}

export interface TrafficDataPoint {
  time: string;
  requests: number;
  blocked: number;
  anomalyScore: number;
}

export interface ApiResponseMeta {
  isFallback: boolean;
  timestamp: string;
  source: string;
  latencyMs: number;
}

export const INITIAL_MOCK_ALERTS: ThreatAlert[] = [
  {
    id: "ALT-9082",
    timestamp: "2026-08-28T18:45:00.000Z",
    severity: "HIGH",
    message: "SQL Injection payload detected in POST /api/v1/auth/login from 185.220.101.5 (' OR '1'='1)",
  },
  {
    id: "ALT-9081",
    timestamp: "2026-08-28T18:44:30.000Z",
    severity: "HIGH",
    message: "Distributed Token-Bucket Exhaustion (DDoS Spike) detected from IP cluster 45.154.255.88 - 340 req/sec",
  },
  {
    id: "ALT-9080",
    timestamp: "2026-08-28T18:43:40.000Z",
    severity: "MEDIUM",
    message: "Invalid PyJWT signature and expired claim token presented on /api/v1/user/profile from 194.26.29.112",
  },
  {
    id: "ALT-9079",
    timestamp: "2026-08-28T18:42:15.000Z",
    severity: "HIGH",
    message: "Honeypot trap triggered: unauthorized probe on /admin/debug/credentials by 91.240.118.244",
  },
  {
    id: "ALT-9078",
    timestamp: "2026-08-28T18:41:00.000Z",
    severity: "MEDIUM",
    message: "High-entropy JSON payload flagged by IsolationForest ML anomaly detector (Anomaly Index: 0.96) on /api/v1/payment/transfer",
  },
  {
    id: "ALT-9077",
    timestamp: "2026-08-28T18:39:10.000Z",
    severity: "LOW",
    message: "Repeated 404 scanning behavior observed from crawler 198.51.100.42 across 28 API routes",
  },
];

export const INITIAL_BLOCKED_IPS = [
  "185.220.101.5",
  "45.154.255.88",
  "91.240.118.244",
  "194.26.29.112",
  "103.251.167.20",
  "185.220.101.7",
];

export const initialMockData: ThreatMetrics = {
  total_requests: 142850,
  blocked_ips_count: INITIAL_BLOCKED_IPS.length,
  blocked_ips_list: INITIAL_BLOCKED_IPS,
  sampling_rate: 1.0,
  sampling_rate_pct: 100,
  sampled_requests_count: 142850,
  bypassed_requests_count: 0,
  compute_saved_pct: 0.0,
  recent_alerts: INITIAL_MOCK_ALERTS,
};

export function generateInitialTrafficHistory(count = 15): TrafficDataPoint[] {
  const points: TrafficDataPoint[] = [];
  const now = new Date();
  for (let i = count - 1; i >= 0; i--) {
    const t = new Date(now.getTime() - i * 2000);
    const timeStr = t.toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
    const requests = Math.floor(20 + Math.random() * 25);
    const blocked = Math.random() > 0.6 ? Math.floor(Math.random() * 4) + 1 : 0;
    points.push({
      time: timeStr,
      requests,
      blocked,
      anomalyScore: parseFloat((0.15 + blocked * 0.12).toFixed(2)),
    });
  }
  return points;
}
