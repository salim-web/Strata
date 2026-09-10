"use client";

import React, { useState } from 'react';
import Link from 'next/link';
import { MultiThreatRadar } from '../../components/MultiThreatRadar';
import { useEnclave } from '../../context/EnclaveContext';
import {
  Radar,
  Activity,
  ArrowRight,
  ShieldAlert,
  Sliders,
  Filter,
  X,
  Radio,
} from 'lucide-react';

export default function RadarPage() {
  const { threatRadar, bursting, triggerBurst } = useEnclave();
  const [selectedThreat, setSelectedThreat] = useState<string | null>(null);

  const VECTOR_DETAILS = [
    {
      key: 'VOLUMETRIC_DDOS',
      name: 'Volumetric / Protocol DDoS',
      metric: 'Rolling flow velocity, SYN-to-ACK ratio, Shannon IP entropy',
      baseline: 'Flow rate < 500/s, SYN/ACK ~1.0, Entropy 2.0–4.0',
      threshold: 'Flow rate > 1,500/s, SYN/ACK > 4.5x, Entropy > 6.0',
      sla: '< 15ms SLA',
    },
    {
      key: 'BOTNET_C2',
      name: 'Botnet C2 Beaconing',
      metric: 'Inter-arrival time (IAT) variance, autocorrelation / FFT periodicity',
      baseline: 'IAT variance > 1.0s, Random natural jitter',
      threshold: 'IAT variance < 0.05s, Periodicity score > 65%',
      sla: '< 20ms SLA',
    },
    {
      key: 'DGA_DNS_TUNNEL',
      name: 'DNS Tunnelling & DGA',
      metric: 'Query character Shannon entropy, bigram frequency, TXT/NULL cascades',
      baseline: 'Entropy < 3.2, Vowel ratio 35–45%, Label < 20 chars',
      threshold: 'Entropy > 3.8, Vowels < 18%, TXT query length > 24',
      sla: '< 10ms SLA',
    },
    {
      key: 'ENCRYPTED_MALWARE',
      name: 'Encrypted Traffic (Zero Decryption)',
      metric: 'JA3/JA4 ClientHello/ServerHello hashes, SNI heuristics, first-N packet lengths',
      baseline: 'Known OS/browser TLS signatures, Valid SNI matching IP',
      threshold: 'Threat intelligence DB match (AsyncRAT, Cobalt Strike), Direct-IP TLS',
      sla: '< 25ms SLA',
    },
    {
      key: 'RECON_SCAN',
      name: 'Reconnaissance / Scanning',
      metric: '10s rolling fan-out cardinality (unique destination IPs & destination ports)',
      baseline: 'Fan-out < 5 targets / 10 seconds',
      threshold: 'Fan-out > 15 destination IPs or > 20 ports in 10s',
      sla: '< 15ms SLA',
    },
    {
      key: 'DATA_EXFIL',
      name: 'Data Exfiltration',
      metric: 'Directional byte asymmetry ratio (B_out / (B_in + 1)), packet ratio',
      baseline: 'Outbound/Inbound ratio < 1.0 (Downloads > Uploads)',
      threshold: 'Outbound/Inbound ratio > 8.0x with > 250 KB uploaded',
      sla: '< 20ms SLA',
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 rounded-3xl border border-[#E5E5F0] dark:border-white/5 bg-white dark:bg-[#26282E] p-6 shadow-saas-light dark:shadow-saas-dark">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="flex h-7 w-7 items-center justify-center rounded-full bg-indigo-50 dark:bg-indigo-500/15 text-indigo-600 dark:text-indigo-400">
              <Radar className="h-4 w-4" />
            </span>
            <h2 className="text-lg sm:text-xl font-extrabold tracking-tight text-[#1E1E2D] dark:text-white">
              6-Vector Multi-Threat Radar Deep Dive
            </h2>
          </div>
          <p className="text-xs font-medium text-[#8A8FA3] dark:text-[#9CA3AF]">
            Continuous feature extraction across 6 calibrated threat vectors without decrypting TLS payloads or inline packet blocking.
          </p>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={() => triggerBurst(selectedThreat || 'VOLUMETRIC_DDOS', 100)}
            disabled={bursting}
            className="inline-flex items-center gap-2 rounded-full bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 text-xs font-semibold shadow-sm transition-all disabled:opacity-50 cursor-pointer"
          >
            <Radio className={`h-3.5 w-3.5 ${bursting ? 'animate-spin' : ''}`} />
            <span>{bursting ? 'Simulating Burst...' : 'Simulate Threat Burst'}</span>
          </button>
        </div>
      </div>

      {/* Interactive 6-Vector Radar Cards */}
      <MultiThreatRadar
        radar={threatRadar}
        selectedThreatClass={selectedThreat}
        onSelectThreatClass={(threatKey) => {
          setSelectedThreat((prev) => (prev === threatKey ? null : threatKey));
        }}
      />

      {/* Selected Threat Active Banner */}
      {selectedThreat && (
        <div className="flex items-center justify-between rounded-full border border-indigo-200 dark:border-indigo-500/20 bg-indigo-50 dark:bg-indigo-950/30 px-4 py-2 text-xs font-semibold text-indigo-700 dark:text-indigo-300 shadow-sm animate-fade-in">
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-indigo-500 animate-pulse" />
            <span>
              Currently Focused Vector: <strong>{selectedThreat}</strong>
            </span>
          </div>
          <div className="flex items-center gap-3">
            <Link
              href="/incidents"
              className="inline-flex items-center gap-1 rounded-full bg-indigo-600 text-white px-3 py-1 text-[11px] font-bold shadow-sm hover:bg-indigo-700 transition-colors"
            >
              <span>View in Incidents Feed</span>
              <ArrowRight className="h-3 w-3" />
            </Link>
            <button
              onClick={() => setSelectedThreat(null)}
              className="inline-flex items-center gap-1 rounded-full bg-white dark:bg-[#26282E] px-2 py-0.5 text-[11px] font-bold text-[#8A8FA3] dark:text-[#9CA3AF] border border-[#E5E5F0] dark:border-white/10 hover:text-[#1E1E2D] dark:hover:text-white cursor-pointer"
            >
              <X className="h-3 w-3" />
              <span>Reset</span>
            </button>
          </div>
        </div>
      )}

      {/* Feature Mathematics & Anomaly Threshold Matrix */}
      <div className="rounded-3xl border border-[#E5E5F0] dark:border-white/5 bg-white dark:bg-[#26282E] p-6 shadow-saas-light dark:shadow-saas-dark space-y-4">
        <div className="flex items-center justify-between border-b border-[#E5E5F0] dark:border-white/5 pb-4">
          <div className="flex items-center gap-2.5">
            <div className="flex h-9 w-9 items-center justify-center rounded-full bg-indigo-50 dark:bg-indigo-500/15 text-indigo-600 dark:text-indigo-400">
              <Sliders className="h-4 w-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold tracking-tight text-[#1E1E2D] dark:text-white">
                Sliding-Window Feature Mathematics & Anomaly Thresholds
              </h3>
              <p className="text-[11px] font-medium text-[#8A8FA3] dark:text-[#9CA3AF]">
                Enclave calibration baselines versus empirical threat detection limits
              </p>
            </div>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-[#E5E5F0] dark:border-white/5 text-[#8A8FA3] dark:text-[#9CA3AF] uppercase text-[10px] font-bold tracking-wider">
                <th className="pb-3 pr-4">Threat Vector</th>
                <th className="pb-3 px-4">Passive Metadata Analyzed</th>
                <th className="pb-3 px-4">Baseline Normal</th>
                <th className="pb-3 px-4">Anomaly Trigger Threshold</th>
                <th className="pb-3 pl-4">Latency SLA</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E5E5F0] dark:divide-white/5 font-medium">
              {VECTOR_DETAILS.map((vec) => (
                <tr
                  key={vec.key}
                  className={`hover:bg-[#F8F8FC] dark:hover:bg-[#1E1F24] transition-colors ${
                    selectedThreat === vec.key ? 'bg-indigo-50/40 dark:bg-indigo-950/20' : ''
                  }`}
                >
                  <td className="py-3.5 pr-4 font-bold text-[#1E1E2D] dark:text-white">
                    {vec.name}
                  </td>
                  <td className="py-3.5 px-4 text-[#8A8FA3] dark:text-[#9CA3AF] max-w-xs">
                    {vec.metric}
                  </td>
                  <td className="py-3.5 px-4 font-mono text-[#1E1E2D] dark:text-slate-200">
                    {vec.baseline}
                  </td>
                  <td className="py-3.5 px-4 font-mono font-bold text-amber-600 dark:text-amber-400">
                    {vec.threshold}
                  </td>
                  <td className="py-3.5 pl-4 font-mono text-emerald-600 dark:text-emerald-400">
                    {vec.sla}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
