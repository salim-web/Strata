export interface StandardizedAlert {
  timestamp: string;
  flow_id: string;
  threat_class: 'VOLUMETRIC_DDOS' | 'BOTNET_C2' | 'DGA_DNS_TUNNEL' | 'ENCRYPTED_MALWARE' | 'RECON_SCAN' | 'DATA_EXFIL';
  confidence_score: number;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  evidence: Record<string, string>;
}

export interface ThreatRadarItem {
  active_count: number;
  latest_confidence: number;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  sample_evidence: string;
}

export interface EnclaveKPIs {
  sustained_flows_per_sec: number;
  sustained_mbps: number;
  ingested_packets_total: number;
  ingested_flows_total: number;
  active_anomalies_count: number;
  pipeline_latency_ms: number;
  diode_status: string;
  return_path_active: boolean;
  timestamp: string;
}

export interface DiodeStatsResponse {
  kpis: EnclaveKPIs;
  threat_radar: Record<string, ThreatRadarItem>;
  recent_alerts_count: number;
}

export interface GeminiAssessment {
  model_used: string;
  threat_classification: string;
  flow_id?: string;
  severity?: string;
  confidence_score?: number;
  mitre_attack_mapping: {
    tactic: string;
    technique_id: string;
    technique_name: string;
    primary_vector?: string;
  };
  threat_hypothesis: string;
  passive_evidence_analysis: string;
  observation_summary: string;
  passive_monitoring_recommendations: string[];
}

export const initialKPIs: EnclaveKPIs = {
  sustained_flows_per_sec: 3420.5,
  sustained_mbps: 48.6,
  ingested_packets_total: 1845290,
  ingested_flows_total: 412580,
  active_anomalies_count: 38,
  pipeline_latency_ms: 3.8,
  diode_status: 'READ_ONLY_ENCLAVE_ACTIVE',
  return_path_active: false,
  timestamp: new Date().toISOString(),
};

export const initialThreatRadar: Record<string, ThreatRadarItem> = {
  VOLUMETRIC_DDOS: {
    active_count: 14,
    latest_confidence: 0.94,
    severity: 'CRITICAL',
    sample_evidence: 'Rate: 4820.0/s | SYN/ACK: 18.5x | Entropy: 7.92',
  },
  BOTNET_C2: {
    active_count: 6,
    latest_confidence: 0.91,
    severity: 'HIGH',
    sample_evidence: 'Periodicity: 98.4% | IAT Var: 0.0028s | Interval: 5.00s',
  },
  DGA_DNS_TUNNEL: {
    active_count: 8,
    latest_confidence: 0.96,
    severity: 'CRITICAL',
    sample_evidence: 'DNS Entropy: 4.82 | Vowel: 12.5% | Label: 34 chars (TXT)',
  },
  ENCRYPTED_MALWARE: {
    active_count: 5,
    latest_confidence: 0.95,
    severity: 'CRITICAL',
    sample_evidence: 'JA3: e7d705a39f6c0... (AsyncRAT) | No SNI',
  },
  RECON_SCAN: {
    active_count: 3,
    latest_confidence: 0.88,
    severity: 'HIGH',
    sample_evidence: 'Fan-out: 142 targets/10s | SYN-only: 98%',
  },
  DATA_EXFIL: {
    active_count: 2,
    latest_confidence: 0.92,
    severity: 'HIGH',
    sample_evidence: 'Outbound/Inbound: 14.2x | Tx Volume: 2.8 MB',
  },
};

export const initialStandardizedAlerts: StandardizedAlert[] = [
  {
    timestamp: new Date(Date.now() - 2000).toISOString(),
    flow_id: '10.0.2.14:5312->8.8.8.8:53:UDP',
    threat_class: 'DGA_DNS_TUNNEL',
    confidence_score: 0.96,
    severity: 'CRITICAL',
    evidence: {
      dns_query: 'x92v7m4b1q8z3k5w.exfil-intel.cc',
      query_char_entropy: '4.82',
      vowel_ratio: '12.5%',
      max_label_length: '32',
      record_type: 'TXT',
      baseline_threshold: 'Entropy > 3.80 OR (TXT/NULL AND Length > 20)',
    },
  },
  {
    timestamp: new Date(Date.now() - 5000).toISOString(),
    flow_id: '10.0.5.112:54200->203.0.113.77:443:TCP',
    threat_class: 'ENCRYPTED_MALWARE',
    confidence_score: 0.95,
    severity: 'CRITICAL',
    evidence: {
      matched_threat: 'AsyncRAT C2 Client',
      ja3_hash: 'e7d705a39f6c0a54e601275bfbb0a221',
      ja4_fingerprint: 't13d1516h2_c2_botnet_pulse',
      sni_target: 'raw_ip_or_hidden',
      baseline_threshold: 'Matches Threat Intel Signature DB (JA3/JA4)',
    },
  },
  {
    timestamp: new Date(Date.now() - 11000).toISOString(),
    flow_id: '10.0.3.50:55555->198.51.100.99:443:TCP',
    threat_class: 'DATA_EXFIL',
    confidence_score: 0.92,
    severity: 'HIGH',
    evidence: {
      outbound_bytes: '2840.5 KB',
      byte_asymmetry_ratio: '14.2x',
      packet_asymmetry_ratio: '18.0x',
      baseline_threshold: 'Byte Ratio > 8.0x AND Outbound Volume > 250 KB',
    },
  },
  {
    timestamp: new Date(Date.now() - 18000).toISOString(),
    flow_id: '10.0.4.88:49152->198.51.100.199:8443:TCP',
    threat_class: 'BOTNET_C2',
    confidence_score: 0.91,
    severity: 'HIGH',
    evidence: {
      periodicity_score: '98.4%',
      iat_variance: '0.00280s',
      mean_interval: '5.00s',
      sample_count: '12',
      baseline_threshold: 'Periodicity > 65% AND IAT Variance < 0.05s',
    },
  },
  {
    timestamp: new Date(Date.now() - 25000).toISOString(),
    flow_id: '192.0.2.45:44444->10.0.1.10:22:TCP',
    threat_class: 'RECON_SCAN',
    confidence_score: 0.88,
    severity: 'HIGH',
    evidence: {
      scan_type: 'Vertical Port Scan',
      fanout_cardinality: '142 targets / 10s',
      unique_dst_ports: '28',
      syn_only_ratio: '98.0%',
      baseline_threshold: 'Fan-out > 15 IPs OR > 20 Ports per 10s window',
    },
  },
  {
    timestamp: new Date(Date.now() - 32000).toISOString(),
    flow_id: '185.220.101.5:12400->198.51.100.25:443:TCP',
    threat_class: 'VOLUMETRIC_DDOS',
    confidence_score: 0.94,
    severity: 'CRITICAL',
    evidence: {
      flow_rate_rps: '4820.0 flows/sec',
      syn_to_ack_ratio: '18.50x',
      src_ip_entropy: '7.920',
      baseline_threshold: 'Flow Rate > 1500/s OR SYN/ACK > 4.5x OR Entropy > 6.0',
    },
  },
];
