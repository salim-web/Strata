"use client";

import React, { useState } from 'react';
import { useEnclave } from '../../context/EnclaveContext';
import {
  Sliders,
  Shield,
  ShieldCheck,
  Radio,
  Lock,
  Cpu,
  Zap,
  Activity,
  Server,
  AlertTriangle,
  Clock,
} from 'lucide-react';

export default function EnclavePage() {
  const { kpis, bursting, triggerBurst } = useEnclave();
  const [burstThreat, setBurstThreat] = useState<string>('DGA_DNS_TUNNEL');
  const [burstCount, setBurstCount] = useState<number>(80);
  const [burstSuccessMsg, setBurstSuccessMsg] = useState<string | null>(null);

  const handleInject = async () => {
    await triggerBurst(burstThreat, burstCount);
    setBurstSuccessMsg(`Successfully injected burst of ${burstCount} synthetic ${burstThreat} flows.`);
    setTimeout(() => setBurstSuccessMsg(null), 4000);
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 rounded-3xl border border-[#E5E5F0] dark:border-white/5 bg-white dark:bg-[#26282E] p-6 shadow-saas-light dark:shadow-saas-dark">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="flex h-7 w-7 items-center justify-center rounded-full bg-emerald-50 dark:bg-emerald-500/15 text-emerald-600 dark:text-emerald-400">
              <Sliders className="h-4 w-4" />
            </span>
            <h2 className="text-lg sm:text-xl font-extrabold tracking-tight text-[#1E1E2D] dark:text-white">
              Enclave Health & Diode Controls
            </h2>
          </div>
          <p className="text-xs font-medium text-[#8A8FA3] dark:text-[#9CA3AF]">
            Hardware RX-only optical tap validation, zero return-path guarantees, and on-demand threat emitter controls.
          </p>
        </div>

        <div className="inline-flex items-center gap-2 rounded-full border border-emerald-200 dark:border-emerald-500/20 bg-emerald-50 dark:bg-emerald-500/10 px-4 py-1.5 text-xs font-bold text-emerald-700 dark:text-emerald-400 shadow-sm shrink-0">
          <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse" />
          <span>DIODE HARDWARE AIR-GAP VERIFIED</span>
        </div>
      </div>

      {/* Grid: Diode Integrity (6 cols) + Threat Burst Generator (6 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* 1. Hardware Diode Integrity Guarantees */}
        <div className="rounded-3xl border border-[#E5E5F0] dark:border-white/5 bg-white dark:bg-[#26282E] p-6 shadow-saas-light dark:shadow-saas-dark space-y-4">
          <div className="flex items-center gap-2.5 border-b border-[#E5E5F0] dark:border-white/5 pb-4">
            <div className="flex h-9 w-9 items-center justify-center rounded-full bg-indigo-50 dark:bg-indigo-500/15 text-indigo-600 dark:text-indigo-400">
              <ShieldCheck className="h-5 w-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold tracking-tight text-[#1E1E2D] dark:text-white">
                Diode Architectural Constraints
              </h3>
              <p className="text-[11px] font-medium text-[#8A8FA3] dark:text-[#9CA3AF]">
                Enforced by physical transmit-fiber severing & kernel isolation
              </p>
            </div>
          </div>

          <div className="space-y-3 text-xs">
            <div className="flex items-start gap-3 rounded-2xl border border-[#E5E5F0] dark:border-white/5 bg-[#F8F8FC] dark:bg-[#1E1F24] p-3.5">
              <div className="flex h-7 w-7 items-center justify-center rounded-full bg-emerald-50 dark:bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 shrink-0 mt-0.5">
                <CheckIcon />
              </div>
              <div>
                <span className="font-bold text-[#1E1E2D] dark:text-white block">
                  Zero Return Path (Physical Transmit Cut)
                </span>
                <p className="text-[11px] text-[#8A8FA3] dark:text-[#9CA3AF] mt-0.5">
                  The enclave network interface card is operated in receive-only mode. Monitored backbones are unreachable for TCP resets or return packets.
                </p>
              </div>
            </div>

            <div className="flex items-start gap-3 rounded-2xl border border-[#E5E5F0] dark:border-white/5 bg-[#F8F8FC] dark:bg-[#1E1F24] p-3.5">
              <div className="flex h-7 w-7 items-center justify-center rounded-full bg-emerald-50 dark:bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 shrink-0 mt-0.5">
                <CheckIcon />
              </div>
              <div>
                <span className="font-bold text-[#1E1E2D] dark:text-white block">
                  Zero Inline Blocking & Pushbacks
                </span>
                <p className="text-[11px] text-[#8A8FA3] dark:text-[#9CA3AF] mt-0.5">
                  No active iptables, nftables, or firewall rule pushes. The system strictly observes network telemetry without modifying traffic state.
                </p>
              </div>
            </div>

            <div className="flex items-start gap-3 rounded-2xl border border-[#E5E5F0] dark:border-white/5 bg-[#F8F8FC] dark:bg-[#1E1F24] p-3.5">
              <div className="flex h-7 w-7 items-center justify-center rounded-full bg-emerald-50 dark:bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 shrink-0 mt-0.5">
                <CheckIcon />
              </div>
              <div>
                <span className="font-bold text-[#1E1E2D] dark:text-white block">
                  Strict Payload Privacy (No Decryption)
                </span>
                <p className="text-[11px] text-[#8A8FA3] dark:text-[#9CA3AF] mt-0.5">
                  TLS and QUIC payloads remain fully encrypted. Threat analysis is executed exclusively on handshake headers and timing sequences.
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* 2. On-Demand Synthetic Threat Burst Generator */}
        <div className="rounded-3xl border border-[#E5E5F0] dark:border-white/5 bg-white dark:bg-[#26282E] p-6 shadow-saas-light dark:shadow-saas-dark space-y-4">
          <div className="flex items-center gap-2.5 border-b border-[#E5E5F0] dark:border-white/5 pb-4">
            <div className="flex h-9 w-9 items-center justify-center rounded-full bg-amber-50 dark:bg-amber-500/15 text-amber-600 dark:text-amber-400">
              <Radio className="h-5 w-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold tracking-tight text-[#1E1E2D] dark:text-white">
                Telemetry Stream Burst Generator
              </h3>
              <p className="text-[11px] font-medium text-[#8A8FA3] dark:text-[#9CA3AF]">
                Inject calibrated anomaly bursts into the high-priority sliding window queue
              </p>
            </div>
          </div>

          <div className="space-y-4 text-xs">
            <div>
              <label className="text-[11px] font-bold uppercase tracking-wider text-[#8A8FA3] dark:text-[#9CA3AF] block mb-1.5">
                Select Threat Vector
              </label>
              <select
                value={burstThreat}
                onChange={(e) => setBurstThreat(e.target.value)}
                className="w-full rounded-2xl border border-[#E5E5F0] dark:border-white/10 bg-[#F8F8FC] dark:bg-[#1E1F24] p-3 text-xs font-semibold text-[#1E1E2D] dark:text-white focus:outline-none cursor-pointer"
              >
                <option value="DGA_DNS_TUNNEL">DGA / DNS Tunnelling (High Entropy Cascade)</option>
                <option value="ENCRYPTED_MALWARE">Encrypted Malware (Malicious JA3 / Direct-IP TLS)</option>
                <option value="VOLUMETRIC_DDOS">Volumetric / SYN Flood DDoS (R_flow &gt; 1,500 fps)</option>
                <option value="BOTNET_C2">Botnet C2 Beaconing (Low IAT Variance &lt; 0.05s)</option>
                <option value="RECON_SCAN">Reconnaissance / Port Scan (Fan-out &gt; 20 ports)</option>
                <option value="DATA_EXFIL">Data Exfiltration (Directional Byte Asymmetry &gt; 8x)</option>
              </select>
            </div>

            <div>
              <div className="flex items-center justify-between text-[11px] font-bold uppercase tracking-wider text-[#8A8FA3] dark:text-[#9CA3AF] mb-1.5">
                <span>Burst Volume</span>
                <span className="text-indigo-600 dark:text-indigo-400">{burstCount} Flow Records</span>
              </div>
              <input
                type="range"
                min="20"
                max="250"
                step="10"
                value={burstCount}
                onChange={(e) => setBurstCount(Number(e.target.value))}
                className="w-full accent-indigo-600 cursor-pointer"
              />
              <div className="flex justify-between text-[10px] text-[#8A8FA3] dark:text-[#9CA3AF] mt-1">
                <span>20 flows (Micro-Burst)</span>
                <span>250 flows (Stress Saturation)</span>
              </div>
            </div>

            <button
              onClick={handleInject}
              disabled={bursting}
              className="w-full flex items-center justify-center gap-2 rounded-2xl bg-indigo-600 hover:bg-indigo-700 text-white py-3 text-xs font-bold shadow-md shadow-indigo-500/25 transition-all disabled:opacity-50 cursor-pointer"
            >
              <Radio className={`h-4 w-4 ${bursting ? 'animate-spin' : ''}`} />
              <span>{bursting ? 'Injecting Telemetry Burst...' : 'Inject Calibrated Threat Burst'}</span>
            </button>

            {burstSuccessMsg && (
              <div className="rounded-xl border border-emerald-200 dark:border-emerald-500/20 bg-emerald-50 dark:bg-emerald-500/10 p-3 text-xs font-semibold text-emerald-700 dark:text-emerald-400">
                {burstSuccessMsg}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Ingest Engine & Machine Learning Status Row */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 sm:gap-6">
        <div className="rounded-3xl border border-[#E5E5F0] dark:border-white/5 bg-white dark:bg-[#26282E] p-5 shadow-saas-light dark:shadow-saas-dark">
          <div className="flex items-center gap-2.5 mb-2">
            <Cpu className="h-4 w-4 text-indigo-600 dark:text-indigo-400" />
            <h4 className="text-xs font-bold text-[#1E1E2D] dark:text-white uppercase">
              ML Ensemble Weights
            </h4>
          </div>
          <span className="text-xl font-extrabold text-[#1E1E2D] dark:text-white block">
            threat_model.joblib
          </span>
          <span className="text-xs font-medium text-emerald-600 dark:text-emerald-400 mt-1 block">
            Loaded & Online (6 Detectors Active)
          </span>
        </div>

        <div className="rounded-3xl border border-[#E5E5F0] dark:border-white/5 bg-white dark:bg-[#26282E] p-5 shadow-saas-light dark:shadow-saas-dark">
          <div className="flex items-center gap-2.5 mb-2">
            <Zap className="h-4 w-4 text-amber-600 dark:text-amber-400" />
            <h4 className="text-xs font-bold text-[#1E1E2D] dark:text-white uppercase">
              Inference Latency SLA
            </h4>
          </div>
          <span className="text-xl font-extrabold text-[#1E1E2D] dark:text-white block">
            {kpis.pipeline_latency_ms.toFixed(1)} ms
          </span>
          <span className="text-xs font-medium text-emerald-600 dark:text-emerald-400 mt-1 block">
            Bounded Latency &lt; 50.0ms Target
          </span>
        </div>

        <div className="rounded-3xl border border-[#E5E5F0] dark:border-white/5 bg-white dark:bg-[#26282E] p-5 shadow-saas-light dark:shadow-saas-dark">
          <div className="flex items-center gap-2.5 mb-2">
            <Clock className="h-4 w-4 text-sky-600 dark:text-sky-400" />
            <h4 className="text-xs font-bold text-[#1E1E2D] dark:text-white uppercase">
              Sliding Window Horizon
            </h4>
          </div>
          <span className="text-xl font-extrabold text-[#1E1E2D] dark:text-white block">
            10.0 Seconds
          </span>
          <span className="text-xs font-medium text-[#8A8FA3] dark:text-[#9CA3AF] mt-1 block">
            Rolling FIFO Window Aggregate
          </span>
        </div>
      </div>
    </div>
  );
}

function CheckIcon() {
  return (
    <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M5 13l4 4L19 7" />
    </svg>
  );
}
