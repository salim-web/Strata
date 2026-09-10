import {
  EnclaveKPIs,
  ThreatRadarItem,
  StandardizedAlert,
  GeminiAssessment,
  DiodeStatsResponse,
  initialKPIs,
  initialThreatRadar,
  initialStandardizedAlerts,
} from './mockData';

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';

export interface ApiResponseMeta {
  isFallback: boolean;
  timestamp: string;
  source: 'passive_diode_gateway' | 'airgap_local_cache';
  latencyMs: number;
}

/**
 * Fetches real-time Diode KPIs and 6-vector Threat Radar summaries.
 */
export async function fetchDiodeStats(): Promise<{
  data: DiodeStatsResponse;
  meta: ApiResponseMeta;
}> {
  const startTime = performance.now();
  const timestamp = new Date().toISOString();

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 1500);

    const res = await fetch(`${API_BASE_URL}/api/v1/diode/stats`, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    const latencyMs = Math.round(performance.now() - startTime);

    if (res.ok) {
      const json = await res.json();
      return {
        data: {
          kpis: json.kpis || initialKPIs,
          threat_radar: json.threat_radar || initialThreatRadar,
          recent_alerts_count: json.recent_alerts_count || 0,
        },
        meta: {
          isFallback: false,
          timestamp,
          source: 'passive_diode_gateway',
          latencyMs,
        },
      };
    }
  } catch (error) {
    // Graceful offline air-gapped fallback
  }

  const latencyMs = Math.max(2, Math.round(performance.now() - startTime));
  return {
    data: {
      kpis: initialKPIs,
      threat_radar: initialThreatRadar,
      recent_alerts_count: initialStandardizedAlerts.length,
    },
    meta: {
      isFallback: true,
      timestamp,
      source: 'airgap_local_cache',
      latencyMs,
    },
  };
}

/**
 * Fetches the live stream of standardized alerts from the passive enclave.
 */
export async function fetchStandardizedAlerts(limit: number = 50): Promise<StandardizedAlert[]> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 1500);

    const res = await fetch(`${API_BASE_URL}/api/v1/diode/alerts?limit=${limit}`, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (res.ok) {
      const json = await res.json();
      if (Array.isArray(json.alerts) && json.alerts.length > 0) {
        return json.alerts;
      }
    }
  } catch {
    // Offline fallback
  }
  return initialStandardizedAlerts;
}

/**
 * Requests an AI Threat Intelligence assessment from Google Gemini
 * based strictly on passive evidence attributes.
 */
export async function requestGeminiAssessment(alert: StandardizedAlert): Promise<GeminiAssessment> {
  try {
    const res = await fetch(`${API_BASE_URL}/api/v1/analyst/assess`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ alert }),
    });

    if (res.ok) {
      const json = await res.json();
      return json;
    }
  } catch (err) {
    console.warn('Gemini analyst request failed, using client fallback:', err);
  }

  // High-fidelity client-side fallback if backend unreachable
  return {
    model_used: 'Air-Gapped Client Enclave Engine',
    threat_classification: alert.threat_class,
    flow_id: alert.flow_id,
    severity: alert.severity,
    confidence_score: alert.confidence_score,
    mitre_attack_mapping: {
      tactic: alert.threat_class === 'VOLUMETRIC_DDOS' ? 'Impact' :
              alert.threat_class === 'BOTNET_C2' ? 'Command and Control' :
              alert.threat_class === 'DGA_DNS_TUNNEL' ? 'Exfiltration' :
              alert.threat_class === 'ENCRYPTED_MALWARE' ? 'Defense Evasion' :
              alert.threat_class === 'RECON_SCAN' ? 'Reconnaissance' : 'Exfiltration',
      technique_id: alert.threat_class === 'VOLUMETRIC_DDOS' ? 'T1498.001' :
                    alert.threat_class === 'BOTNET_C2' ? 'T1071.001' :
                    alert.threat_class === 'DGA_DNS_TUNNEL' ? 'T1071.004' :
                    alert.threat_class === 'ENCRYPTED_MALWARE' ? 'T1573.002' :
                    alert.threat_class === 'RECON_SCAN' ? 'T1595.001' : 'T1048.003',
      technique_name: `${alert.threat_class} Vector Protocol Analysis`,
      primary_vector: 'Passive metadata deviation across sliding-window vectors',
    },
    threat_hypothesis: `Passive optical tap observed high-confidence ${alert.threat_class} indicators on flow ${alert.flow_id}. Evidence strictly derived without payload decryption.`,
    passive_evidence_analysis: Object.entries(alert.evidence)
      .map(([k, v]) => `${k} = ${v}`)
      .join(' | '),
    observation_summary: `Enclave flagged ${alert.severity} priority anomaly with ${Math.round(alert.confidence_score * 100)}% confidence score. Zero return-path packets were emitted.`,
    passive_monitoring_recommendations: [
      'Observe upstream NetFlow/IPFIX records for cross-subnet correlation.',
      'Correlate host telemetry out-of-band via central SIEM.',
      'Maintain strict diode read-only monitoring without inline blocking.',
    ],
  };
}

/**
 * Triggers an immediate synthetic passive threat burst for demonstration.
 */
export async function triggerThreatBurst(threatClass: string = 'DGA_DNS_TUNNEL', count: number = 60): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE_URL}/api/v1/diode/emitter/burst`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ threat_class: threatClass, count }),
    });
    return res.ok;
  } catch {
    return false;
  }
}

