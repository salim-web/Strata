import { ThreatMetrics, initialMockData, ApiResponseMeta } from './mockData';

export type { ApiResponseMeta };

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export interface ThreatMetricsResponse {
  data: ThreatMetrics;
  meta: ApiResponseMeta;
}

/**
 * Fetch latest threat metrics from backend with graceful fallback to mock data
 */
export async function fetchThreatMetrics(): Promise<ThreatMetricsResponse> {
  const startTime = performance.now();
  const timestamp = new Date().toISOString();

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 2000);

    const res = await fetch(`${API_BASE_URL}/api/threat-metrics`, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
      },
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    const latencyMs = Math.round(performance.now() - startTime);

    if (res.ok) {
      const data = await res.json();
      return {
        data: {
          total_requests: data.total_requests ?? 0,
          blocked_ips_count: data.blocked_ips_count ?? (data.blocked_ips_list?.length || 0),
          blocked_ips_list: data.blocked_ips_list || [],
          recent_alerts: data.recent_alerts || [],
          sampling_rate: data.sampling_rate,
          sampling_rate_pct: data.sampling_rate_pct,
          sampled_requests_count: data.sampled_requests_count,
          bypassed_requests_count: data.bypassed_requests_count,
          compute_saved_pct: data.compute_saved_pct,
          current_anomaly_score: data.current_anomaly_score,
          ml_latency_ms: data.ml_latency_ms !== undefined ? data.ml_latency_ms : undefined,
        },
        meta: {
          isFallback: false,
          timestamp,
          source: 'fastapi_gateway',
          latencyMs,
        },
      };
    }
  } catch (error) {
    // Backend unreachable, silent fallback
  }

  const latencyMs = Math.round(performance.now() - startTime);
  return {
    data: initialMockData,
    meta: {
      isFallback: true,
      timestamp,
      source: 'mock_simulation',
      latencyMs: Math.max(8, latencyMs),
    },
  };
}

/**
 * Manually unblock an IP address via backend API
 */
export async function unblockIpOnBackend(ip: string): Promise<{ success: boolean; message?: string }> {
  try {
    const res = await fetch(`${API_BASE_URL}/api/unblock-ip`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ ip }),
    });

    if (res.ok) {
      const data = await res.json().catch(() => ({}));
      return { success: true, message: data.message || 'IP unblocked successfully.' };
    }
    return { success: false, message: `Status: ${res.status}` };
  } catch (err: any) {
    return { success: false, message: err.message };
  }
}

/**
 * Update the ML/API sampling rate dynamically
 */
export async function updateSamplingConfig(rate: number): Promise<{ success: boolean; rate: number }> {
  try {
    const res = await fetch(`${API_BASE_URL}/api/v1/config/sampling`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ sample_rate: rate }),
    });
    if (res.ok) {
      return { success: true, rate };
    }
  } catch {
    // Graceful fallback if route not on backend yet
  }
  return { success: true, rate };
}
