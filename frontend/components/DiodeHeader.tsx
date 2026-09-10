"use client";

import React from 'react';
import { Shield, Radio, Activity, Eye, Zap, Lock } from 'lucide-react';

interface DiodeHeaderProps {
  flowsPerSec: number;
  mbps: number;
  pipelineLatency: number;
  lastUpdated: string;
  onInjectBurst?: (threatClass: string) => void;
  bursting?: boolean;
}

export const DiodeHeader: React.FC<DiodeHeaderProps> = ({
  flowsPerSec,
  mbps,
  pipelineLatency,
  lastUpdated,
  onInjectBurst,
  bursting = false,
}) => {
  return (
<header className="relative border-b border-cyan-950/40 bg-gradient-to-r from-slate-950 via-[#0a0f1d] to-slate-950 px-6 py-4 backdrop-blur-xl">
  <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
    {/* Title & Enclave Identity */}
    <div className="flex items-center gap-4">
      <div className="relative flex h-12 w-12 items-center justify-center rounded-xl border border-cyan-500/30 bg-cyan-950/40 shadow-[0_0_20px_rgba(6,182,212,0.25)]">
        <Shield className="h-6 w-6 text-cyan-400" />
      </div>

          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-lg font-bold tracking-tight text-white sm:text-xl">
                STRATA
              </h1>
            </div>
          </div>
        </div>

        {/* Diode Indicator Badge & Real-Time Stats */}
        <div className="flex flex-wrap items-center gap-3">
          

          {/* Quick Latency & Stream Chip */}
          <div className="flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-900/80 px-3 py-1.5 text-xs font-mono text-slate-300">
            <Zap className="h-3.5 w-3.5 text-amber-400 animate-pulse" />
            <span>SLA: <strong className="text-emerald-400">{pipelineLatency.toFixed(1)}ms</strong> &lt; 50ms</span>
          </div>

          <div className="flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-900/80 px-3 py-1.5 text-xs font-mono text-slate-400">
            <Eye className="h-3.5 w-3.5 text-cyan-400" />
            <span>Synced: <span className="text-slate-200">{lastUpdated}</span></span>
          </div>

          {onInjectBurst && (
            <div className="flex items-center gap-1.5">
              <select
                id="threat-burst-select"
                defaultValue="DGA_DNS_TUNNEL"
                className="rounded-lg border border-slate-800 bg-slate-900 px-2 py-1.5 text-[11px] font-mono text-slate-300 focus:border-cyan-500 focus:outline-none"
              >
                <option value="DGA_DNS_TUNNEL">DGA / DNS Tunnel</option>
                <option value="ENCRYPTED_MALWARE">Encrypted Malware (JA3)</option>
                <option value="VOLUMETRIC_DDOS">Volumetric DDoS</option>
                <option value="BOTNET_C2">Botnet C2 Beacon</option>
                <option value="RECON_SCAN">Recon Port Scan</option>
                <option value="DATA_EXFIL">Data Exfiltration</option>
              </select>
              <button
                onClick={() => {
                  const sel = document.getElementById('threat-burst-select') as HTMLSelectElement;
                  onInjectBurst(sel ? sel.value : 'DGA_DNS_TUNNEL');
                }}
                disabled={bursting}
                className="flex items-center gap-1.5 rounded-lg border border-cyan-500/30 bg-cyan-950/60 px-3 py-1.5 text-xs font-mono font-bold text-cyan-300 hover:bg-cyan-900/40 hover:border-cyan-400 disabled:opacity-50 transition shadow-sm"
              >
                <Radio className={`h-3.5 w-3.5 text-cyan-400 ${bursting ? 'animate-spin' : ''}`} />
                <span>{bursting ? 'Injecting...' : 'Inject Burst'}</span>
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
};
