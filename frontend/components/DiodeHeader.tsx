"use client";

import React from 'react';
import { Shield, Radio, Eye, Zap, Sun, Moon, Lock } from 'lucide-react';

interface DiodeHeaderProps {
  flowsPerSec: number;
  mbps: number;
  pipelineLatency: number;
  lastUpdated: string;
  onInjectBurst?: (threatClass: string) => void;
  bursting?: boolean;
  theme?: 'light' | 'dark';
  onToggleTheme?: () => void;
}

export const DiodeHeader: React.FC<DiodeHeaderProps> = ({
  flowsPerSec,
  mbps,
  pipelineLatency,
  lastUpdated,
  onInjectBurst,
  bursting = false,
  theme = 'dark',
  onToggleTheme,
}) => {
  const isDark = theme === 'dark';

  return (
    <header className="sticky top-0 z-30 w-full border-b border-[#E2E2EC] dark:border-white/5 bg-white/85 dark:bg-[#1C1D21]/90 backdrop-blur-xl transition-colors duration-250">
      <div className="mx-auto flex max-w-[1700px] flex-col gap-4 px-4 py-3.5 sm:px-6 lg:flex-row lg:items-center lg:justify-between">
        {/* Left: Brand Identity & Data Diode Badge */}
        <div className="flex flex-wrap items-center gap-3 sm:gap-4">
          {/* Logo & Shield Icon */}
          <div className="flex items-center gap-3">
            <div className="relative flex h-11 w-11 items-center justify-center rounded-2xl bg-gradient-to-tr from-indigo-600 via-indigo-500 to-violet-500 text-white shadow-md shadow-indigo-500/20">
              <Shield className="h-5 w-5" />
            </div>

            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-lg font-extrabold tracking-tight text-[#1E1E2D] dark:text-white sm:text-xl">
                  STRATA
                </h1>
                <span className="hidden sm:inline-block text-xs font-semibold text-[#8A8FA3] dark:text-[#9CA3AF]">
                  // Enclave v2.0
                </span>
              </div>
              <p className="text-[11px] font-medium text-[#8A8FA3] dark:text-[#9CA3AF]">
                Passive Network Threat Intelligence &bull; RX-Only Optical Tap
              </p>
            </div>
          </div>

          {/* Diode Zero Return Path Status Badge */}
          <div className="inline-flex items-center gap-1.5 rounded-full border border-emerald-200 dark:border-emerald-500/20 bg-emerald-50 dark:bg-emerald-500/10 px-3 py-1 text-xs font-semibold text-emerald-700 dark:text-emerald-400 shadow-sm">
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500" />
            </span>
            <span className="tracking-wide">DIODE READ-ONLY: ZERO RETURN PATH</span>
          </div>
        </div>

        {/* Right: Floating Pill Indicators, Threat Burst Trigger & Theme Toggle */}
        <div className="flex flex-wrap items-center gap-2.5 sm:gap-3">
          {/* SLA Latency Chip */}
          <div className="inline-flex items-center gap-1.5 rounded-full border border-[#E5E5F0] dark:border-white/10 bg-[#F8F8FC] dark:bg-[#26282E] px-3.5 py-1.5 text-xs font-medium text-[#1E1E2D] dark:text-[#F3F4F6] shadow-sm">
            <Zap className="h-3.5 w-3.5 text-amber-500 dark:text-amber-400" />
            <span>
              SLA: <strong className="font-semibold text-emerald-600 dark:text-emerald-400">{pipelineLatency.toFixed(1)}ms</strong> <span className="text-[#8A8FA3] dark:text-[#9CA3AF]">&lt; 50ms</span>
            </span>
          </div>

          {/* Real-time Synced Time Chip */}
          <div className="hidden sm:inline-flex items-center gap-1.5 rounded-full border border-[#E5E5F0] dark:border-white/10 bg-[#F8F8FC] dark:bg-[#26282E] px-3.5 py-1.5 text-xs font-medium text-[#8A8FA3] dark:text-[#9CA3AF] shadow-sm">
            <Eye className="h-3.5 w-3.5 text-indigo-500 dark:text-indigo-400" />
            <span>
              Synced: <strong className="text-[#1E1E2D] dark:text-[#F3F4F6]">{lastUpdated}</strong>
            </span>
          </div>

          {/* On-Demand Threat Burst Injector */}
          {onInjectBurst && (
            <div className="flex items-center gap-1.5 rounded-full border border-[#E5E5F0] dark:border-white/10 bg-[#F8F8FC] dark:bg-[#26282E] p-1 shadow-sm">
              <select
                id="threat-burst-select"
                defaultValue="DGA_DNS_TUNNEL"
                className="rounded-full bg-transparent pl-3 pr-2 py-1 text-xs font-medium text-[#1E1E2D] dark:text-[#F3F4F6] focus:outline-none cursor-pointer"
              >
                <option value="DGA_DNS_TUNNEL" className="bg-white dark:bg-[#26282E]">DGA / DNS Tunnel</option>
                <option value="ENCRYPTED_MALWARE" className="bg-white dark:bg-[#26282E]">Encrypted Malware (JA3)</option>
                <option value="VOLUMETRIC_DDOS" className="bg-white dark:bg-[#26282E]">Volumetric DDoS</option>
                <option value="BOTNET_C2" className="bg-white dark:bg-[#26282E]">Botnet C2 Beacon</option>
                <option value="RECON_SCAN" className="bg-white dark:bg-[#26282E]">Recon Port Scan</option>
                <option value="DATA_EXFIL" className="bg-white dark:bg-[#26282E]">Data Exfiltration</option>
              </select>

              <button
                onClick={() => {
                  const sel = document.getElementById('threat-burst-select') as HTMLSelectElement;
                  onInjectBurst(sel ? sel.value : 'DGA_DNS_TUNNEL');
                }}
                disabled={bursting}
                className="inline-flex items-center gap-1.5 rounded-full bg-indigo-600 dark:bg-indigo-500 px-3.5 py-1 text-xs font-semibold text-white shadow-sm hover:bg-indigo-700 dark:hover:bg-indigo-600 disabled:opacity-50 transition-all cursor-pointer"
              >
                <Radio className={`h-3 w-3 ${bursting ? 'animate-spin' : ''}`} />
                <span>{bursting ? 'Injecting...' : 'Inject Burst'}</span>
              </button>
            </div>
          )}

          {/* Light / Dark Mode Toggle Pill Switch */}
          {onToggleTheme && (
            <button
              onClick={onToggleTheme}
              aria-label="Toggle Light / Dark theme"
              className="relative inline-flex h-9 w-16 items-center rounded-full border border-[#E5E5F0] dark:border-white/10 bg-[#F8F8FC] dark:bg-[#26282E] p-1 shadow-sm transition-colors duration-200 cursor-pointer"
            >
              <div
                className={`flex h-7 w-7 items-center justify-center rounded-full bg-white dark:bg-[#1C1D21] text-[#1E1E2D] dark:text-[#F3F4F6] shadow-sm transform transition-transform duration-200 ${
                  isDark ? 'translate-x-7 text-indigo-400' : 'translate-x-0 text-amber-500'
                }`}
              >
                {isDark ? <Moon className="h-3.5 w-3.5" /> : <Sun className="h-3.5 w-3.5" />}
              </div>
            </button>
          )}
        </div>
      </div>
    </header>
  );
};
