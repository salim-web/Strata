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
  AlertTriangle,
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
  borderHoverColor: string;
  accentColor: string;
  badgeBg: string;
  description: string;
}

const THREAT_CONFIGS: ThreatMeta[] = [
  {
    key: 'VOLUMETRIC_DDOS',
    name: 'Volumetric / Protocol DDoS',
    category: 'State Exhaustion',
    icon: <Flame className="h-4 w-4" />,
    borderHoverColor: 'hover:border-rose-500/50',
    accentColor: 'text-rose-400',
    badgeBg: 'bg-rose-500/10 text-rose-400 border-rose-500/20',
    description: 'Sliding flow-rate bursts, SYN/ACK imbalance & source IP Shannon entropy spikes.',
  },
  {
    key: 'BOTNET_C2',
    name: 'Botnet C2 Beaconing',
    category: 'Persistence Heartbeat',
    icon: <Radio className="h-4 w-4" />,
    borderHoverColor: 'hover:border-amber-500/50',
    accentColor: 'text-amber-400',
    badgeBg: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
    description: 'Low-variance periodic intervals & autocorrelation/FFT peaks to destination IPs.',
  },
  {
    key: 'DGA_DNS_TUNNEL',
    name: 'DNS Tunnelling & DGA',
    category: 'Covert Channel',
    icon: <Globe2 className="h-4 w-4" />,
    borderHoverColor: 'hover:border-cyan-500/50',
    accentColor: 'text-cyan-400',
    badgeBg: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20',
    description: 'Character Shannon entropy, n-gram bigram anomalies & TXT/NULL query cascades.',
  },
  {
    key: 'ENCRYPTED_MALWARE',
    name: 'Encrypted Traffic Metadata',
    category: 'Zero Decryption TLS',
    icon: <Lock className="h-4 w-4" />,
    borderHoverColor: 'hover:border-purple-500/50',
    accentColor: 'text-purple-400',
    badgeBg: 'bg-purple-500/10 text-purple-400 border-purple-500/20',
    description: 'JA3/JA4 ClientHello hashes, SNI inspection & first-N packet size sequences.',
  },
  {
    key: 'RECON_SCAN',
    name: 'Reconnaissance / Scanning',
    category: 'Network Discovery',
    icon: <Radar className="h-4 w-4" />,
    borderHoverColor: 'hover:border-blue-500/50',
    accentColor: 'text-blue-400',
    badgeBg: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
    description: '10s rolling fan-out cardinality (unique destination IPs & ports contacted per host).',
  },
  {
    key: 'DATA_EXFIL',
    name: 'Data Exfiltration',
    category: 'Unauthorized Transfer',
    icon: <ArrowUpRight className="h-4 w-4" />,
    borderHoverColor: 'hover:border-orange-500/50',
    accentColor: 'text-orange-400',
    badgeBg: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
    description: 'Directional byte asymmetry ratios (outbound-to-inbound volume >8x) & large uploads.',
  },
];

export const MultiThreatRadar: React.FC<MultiThreatRadarProps> = ({
  radar,
  onSelectThreatClass,
  selectedThreatClass,
}) => {
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="flex h-6 w-6 items-center justify-center rounded-md bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
            <Radar className="h-3.5 w-3.5 animate-spin" style={{ animationDuration: '6s' }} />
          </div>
          <h2 className="text-sm font-mono font-bold tracking-wider text-slate-200 uppercase">
            Passive Multi-Threat Radar // 6-Vector Metadata Ensemble
          </h2>
        </div>
        <span className="text-[11px] font-mono text-slate-400">
          Continuous Sliding-Window Feature Extraction
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
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
              className={`group relative cursor-pointer overflow-hidden rounded-xl border p-4 transition-all duration-200 backdrop-blur-md ${
                isSelected
                  ? 'border-cyan-500 bg-slate-900/90 shadow-[0_0_25px_rgba(6,182,212,0.25)]'
                  : `border-slate-800/80 bg-slate-900/50 hover:bg-slate-900/80 ${threat.borderHoverColor}`
              }`}
            >
              {/* Header */}
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-center gap-2.5">
                  <div className={`p-1.5 rounded-lg border bg-slate-950 ${threat.accentColor} border-slate-800`}>
                    {threat.icon}
                  </div>
                  <div>
                    <h3 className="text-xs font-bold font-mono text-white group-hover:text-cyan-300 transition-colors">
                      {threat.name}
                    </h3>
                    <span className="text-[10px] font-mono text-slate-400">
                      {threat.category}
                    </span>
                  </div>
                </div>

                <span
                  className={`inline-flex items-center rounded px-2 py-0.5 text-[10px] font-mono font-bold border ${threat.badgeBg}`}
                >
                  {radarItem.severity}
                </span>
              </div>

              {/* Confidence & Active Count */}
              <div className="mt-3 flex items-center justify-between border-t border-slate-800/60 pt-2 text-xs font-mono">
                <div>
                  <span className="text-[10px] text-slate-400 block">Confidence</span>
                  <span className={`text-sm font-bold ${threat.accentColor}`}>
                    {confidencePct > 0 ? `${confidencePct}%` : '0%'}
                  </span>
                </div>

                <div className="text-right">
                  <span className="text-[10px] text-slate-400 block">Active In-Window</span>
                  <span className="text-sm font-bold text-white">
                    {radarItem.active_count}
                  </span>
                </div>
              </div>

              {/* Confidence Progress Bar */}
              <div className="mt-2 h-1 w-full overflow-hidden rounded-full bg-slate-800">
                <div
                  className="h-full bg-gradient-to-r from-cyan-500 to-emerald-400 transition-all duration-300"
                  style={{ width: `${Math.max(4, confidencePct)}%` }}
                />
              </div>

              {/* Live Evidence Breakdown */}
              <div className="mt-3 rounded-lg bg-slate-950/70 border border-slate-800/60 p-2 text-[11px] font-mono text-slate-300">
                <div className="text-[10px] uppercase font-bold text-slate-400 mb-0.5 flex items-center justify-between">
                  <span>Passive Evidence</span>
                  <ChevronRight className="h-3 w-3 text-slate-400 group-hover:translate-x-0.5 transition-transform" />
                </div>
                <div className="truncate text-slate-300 font-medium">
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
