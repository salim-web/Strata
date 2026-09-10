"use client";

import React from 'react';
import {
  Flame,
  Radio,
  Globe2,
  Lock,
  Radar,
  ArrowUpRight,
  ChevronRight,
} from 'lucide-react';
import { ThreatRadarItem } from '../lib/mockData';

interface MultiThreatRadarProps {
  radar: Record<string, ThreatRadarItem>;
  onSelectThreatClass?: (threatClass: string) => void;
  selectedThreatClass?: string | null;
}

interface ThreatMeta {
  key: string;
  name: string;
  category: string;
  icon: React.ReactNode;
  iconBg: string;
  iconColor: string;
  progressGradient: string;
  accentText: string;
  description: string;
}

const THREAT_CONFIGS: ThreatMeta[] = [
  {
    key: 'VOLUMETRIC_DDOS',
    name: 'Volumetric / Protocol DDoS',
    category: 'State Exhaustion',
    icon: <Flame className="h-4 w-4" />,
    iconBg: 'bg-rose-50 dark:bg-rose-500/15',
    iconColor: 'text-rose-600 dark:text-rose-400',
    progressGradient: 'from-rose-500 to-pink-500',
    accentText: 'text-rose-600 dark:text-rose-400',
    description: 'Sliding flow-rate bursts, SYN/ACK imbalance & source IP Shannon entropy spikes.',
  },
  {
    key: 'BOTNET_C2',
    name: 'Botnet C2 Beaconing',
    category: 'Persistence Heartbeat',
    icon: <Radio className="h-4 w-4" />,
    iconBg: 'bg-amber-50 dark:bg-amber-500/15',
    iconColor: 'text-amber-600 dark:text-amber-400',
    progressGradient: 'from-amber-500 to-orange-400',
    accentText: 'text-amber-600 dark:text-amber-400',
    description: 'Low-variance periodic intervals & autocorrelation/FFT peaks to destination IPs.',
  },
  {
    key: 'DGA_DNS_TUNNEL',
    name: 'DNS Tunnelling & DGA',
    category: 'Covert Channel',
    icon: <Globe2 className="h-4 w-4" />,
    iconBg: 'bg-cyan-50 dark:bg-cyan-500/15',
    iconColor: 'text-cyan-600 dark:text-cyan-400',
    progressGradient: 'from-cyan-500 to-sky-400',
    accentText: 'text-cyan-600 dark:text-cyan-400',
    description: 'Character Shannon entropy, n-gram bigram anomalies & TXT/NULL query cascades.',
  },
  {
    key: 'ENCRYPTED_MALWARE',
    name: 'Encrypted Traffic Metadata',
    category: 'Zero Decryption TLS',
    icon: <Lock className="h-4 w-4" />,
    iconBg: 'bg-violet-50 dark:bg-violet-500/15',
    iconColor: 'text-violet-600 dark:text-violet-400',
    progressGradient: 'from-indigo-500 to-violet-500',
    accentText: 'text-violet-600 dark:text-violet-400',
    description: 'JA3/JA4 ClientHello hashes, SNI inspection & first-N packet size sequences.',
  },
  {
    key: 'RECON_SCAN',
    name: 'Reconnaissance / Scanning',
    category: 'Network Discovery',
    icon: <Radar className="h-4 w-4" />,
    iconBg: 'bg-blue-50 dark:bg-blue-500/15',
    iconColor: 'text-blue-600 dark:text-blue-400',
    progressGradient: 'from-blue-500 to-indigo-400',
    accentText: 'text-blue-600 dark:text-blue-400',
    description: '10s rolling fan-out cardinality (unique destination IPs & ports contacted per host).',
  },
  {
    key: 'DATA_EXFIL',
    name: 'Data Exfiltration',
    category: 'Unauthorized Transfer',
    icon: <ArrowUpRight className="h-4 w-4" />,
    iconBg: 'bg-orange-50 dark:bg-orange-500/15',
    iconColor: 'text-orange-600 dark:text-orange-400',
    progressGradient: 'from-orange-500 to-amber-500',
    accentText: 'text-orange-600 dark:text-orange-400',
    description: 'Directional byte asymmetry ratios (outbound-to-inbound volume >8x) & large uploads.',
  },
];

export const MultiThreatRadar: React.FC<MultiThreatRadarProps> = ({
  radar,
  onSelectThreatClass,
  selectedThreatClass,
}) => {
  const getSeverityPill = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-rose-50 text-rose-700 border-rose-200 dark:bg-rose-500/15 dark:text-rose-400 dark:border-rose-500/20';
      case 'HIGH':
        return 'bg-orange-50 text-orange-700 border-orange-200 dark:bg-orange-500/15 dark:text-orange-400 dark:border-orange-500/20';
      case 'MEDIUM':
        return 'bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-500/15 dark:text-amber-400 dark:border-amber-500/20';
      case 'LOW':
      default:
        return 'bg-[#F0EFF8] text-[#8A8FA3] border-[#E5E5F0] dark:bg-white/5 dark:text-[#9CA3AF] dark:border-white/10';
    }
  };

  return (
    <div className="space-y-4">
      {/* Section Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <div className="flex h-8 w-8 items-center justify-center rounded-full bg-indigo-50 dark:bg-indigo-500/15 text-indigo-600 dark:text-indigo-400">
            <Radar className="h-4 w-4 animate-spin" style={{ animationDuration: '8s' }} />
          </div>
          <div>
            <h2 className="text-sm font-bold tracking-tight text-[#1E1E2D] dark:text-white uppercase">
              Passive Multi-Threat Radar
            </h2>
            <p className="text-[11px] font-medium text-[#8A8FA3] dark:text-[#9CA3AF]">
              Continuous Sliding-Window Feature Extraction &bull; 6-Vector ML Inference
            </p>
          </div>
        </div>

        <span className="hidden sm:inline-flex items-center rounded-full border border-[#E5E5F0] dark:border-white/10 bg-white dark:bg-[#26282E] px-3 py-1 text-xs font-semibold text-[#8A8FA3] dark:text-[#9CA3AF] shadow-sm">
          Select vector to filter feed
        </span>
      </div>

      {/* 6-Vector Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {THREAT_CONFIGS.map((threat) => {
          const radarItem = radar[threat.key] || {
            active_count: 0,
            latest_confidence: 0.0,
            severity: 'LOW',
            sample_evidence: 'Monitoring passive flow windows...',
          };

          const isSelected = selectedThreatClass === threat.key;
          const confidencePct = Math.round((radarItem.latest_confidence || 0) * 100);

          return (
            <div
              key={threat.key}
              onClick={() => onSelectThreatClass && onSelectThreatClass(threat.key)}
              className={`group relative cursor-pointer overflow-hidden rounded-2xl border p-4 sm:p-5 transition-all duration-200 ${
                isSelected
                  ? 'border-indigo-500 dark:border-indigo-400 bg-white dark:bg-[#26282E] ring-2 ring-indigo-500/20 shadow-glow-violet'
                  : 'border-[#E5E5F0] dark:border-white/5 bg-white dark:bg-[#26282E] hover:border-indigo-300 dark:hover:border-white/15 shadow-saas-light dark:shadow-saas-dark hover:-translate-y-0.5'
              }`}
            >
              {/* Card Header: Icon, Titles & Severity Pill */}
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-center gap-3">
                  <div className={`flex h-9 w-9 items-center justify-center rounded-full ${threat.iconBg} ${threat.iconColor}`}>
                    {threat.icon}
                  </div>
                  <div>
                    <h3 className="text-xs font-bold text-[#1E1E2D] dark:text-white group-hover:text-indigo-600 dark:group-hover:text-indigo-400 transition-colors">
                      {threat.name}
                    </h3>
                    <span className="text-[11px] font-medium text-[#8A8FA3] dark:text-[#9CA3AF]">
                      {threat.category}
                    </span>
                  </div>
                </div>

                <span
                  className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-[10px] font-bold tracking-wider ${getSeverityPill(
                    radarItem.severity
                  )}`}
                >
                  {radarItem.severity}
                </span>
              </div>

              {/* Confidence & Active Flow Count */}
              <div className="mt-4 flex items-center justify-between border-t border-[#F0EFF8] dark:border-white/5 pt-3 text-xs">
                <div>
                  <span className="text-[10px] font-medium text-[#8A8FA3] dark:text-[#9CA3AF] block mb-0.5">
                    Detection Confidence
                  </span>
                  <span className={`text-sm font-extrabold ${threat.accentText}`}>
                    {confidencePct > 0 ? `${confidencePct}%` : '0%'}
                  </span>
                </div>

                <div className="text-right">
                  <span className="text-[10px] font-medium text-[#8A8FA3] dark:text-[#9CA3AF] block mb-0.5">
                    Active In-Window
                  </span>
                  <span className="text-sm font-extrabold text-[#1E1E2D] dark:text-white">
                    {radarItem.active_count}
                  </span>
                </div>
              </div>

              {/* Category-Matched Rounded Progress Bar */}
              <div className="mt-2.5 h-1.5 w-full overflow-hidden rounded-full bg-[#ECEBF5] dark:bg-white/10">
                <div
                  className={`h-full rounded-full bg-gradient-to-r ${threat.progressGradient} transition-all duration-300`}
                  style={{ width: `${Math.max(5, confidencePct)}%` }}
                />
              </div>

              {/* Passive Evidence Drawer Row */}
              <div className="mt-3.5 rounded-xl border border-[#E5E5F0] dark:border-white/5 bg-[#F8F8FC] dark:bg-[#1E1F24] p-2.5 text-xs transition-colors group-hover:border-indigo-200 dark:group-hover:border-white/10">
                <div className="flex items-center justify-between text-[10px] font-bold uppercase tracking-wider text-[#8A8FA3] dark:text-[#9CA3AF] mb-1">
                  <span>Passive Evidence</span>
                  <ChevronRight className="h-3 w-3 text-[#8A8FA3] dark:text-[#9CA3AF] group-hover:translate-x-0.5 transition-transform" />
                </div>
                <div className="truncate text-[11px] font-mono font-medium text-[#1E1E2D] dark:text-[#F3F4F6]">
                  {radarItem.sample_evidence}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
