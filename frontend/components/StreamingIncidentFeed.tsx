"use client";

import React, { useState } from 'react';
import {
  AlertCircle,
  ChevronDown,
  ChevronUp,
  Cpu,
  Clock,
  Filter,
  Search,
  Check,
  Copy,
  ExternalLink,
} from 'lucide-react';
import { StandardizedAlert } from '../lib/mockData';

interface StreamingIncidentFeedProps {
  alerts: StandardizedAlert[];
  onSelectAlertForAnalysis: (alert: StandardizedAlert) => void;
  selectedAlertFlowId?: string | null;
}

export const StreamingIncidentFeed: React.FC<StreamingIncidentFeedProps> = ({
  alerts = [],
  onSelectAlertForAnalysis,
  selectedAlertFlowId,
}) => {
  const [filterSeverity, setFilterSeverity] = useState<string>('ALL');
  const [filterClass, setFilterClass] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [expandedFlowId, setExpandedFlowId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const filteredAlerts = alerts.filter((alert) => {
    const matchesSev = filterSeverity === 'ALL' || alert.severity === filterSeverity;
    const matchesClass = filterClass === 'ALL' || alert.threat_class === filterClass;
    const matchesSearch =
      searchQuery === '' ||
      alert.flow_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      alert.threat_class.toLowerCase().includes(searchQuery.toLowerCase()) ||
      JSON.stringify(alert.evidence).toLowerCase().includes(searchQuery.toLowerCase());
    return matchesSev && matchesClass && matchesSearch;
  });

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1500);
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-rose-500/10 text-rose-400 border-rose-500/30';
      case 'HIGH':
        return 'bg-orange-500/10 text-orange-400 border-orange-500/30';
      case 'MEDIUM':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      case 'LOW':
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  return (
    <div className="flex flex-col h-[600px] rounded-xl border border-slate-800/80 bg-slate-900/60 shadow-xl backdrop-blur-md overflow-hidden">
      {/* Header */}
      <div className="border-b border-slate-800 p-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-cyan-950/60 text-cyan-400 border border-cyan-500/20">
              <AlertCircle className="h-4 w-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold font-mono text-white tracking-wide">
                Streaming Incident Feed // Standardized Alert Schema
              </h3>
              <p className="text-[11px] font-mono text-slate-400">
                Live passive telemetry events &bull; Bounded Latency &bull; Non-reloading stream
              </p>
            </div>
          </div>

          {/* Severity Badges Filter */}
          <div className="flex items-center gap-1 bg-slate-950/60 p-1 rounded-lg border border-slate-800 text-[11px] font-mono">
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map((sev) => (
              <button
                key={sev}
                onClick={() => setFilterSeverity(sev)}
                className={`px-2.5 py-1 rounded transition-colors ${
                  filterSeverity === sev
                    ? 'bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/30'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>

        {/* Search & Threat Class Filter Bar */}
        <div className="mt-3 flex flex-col sm:flex-row gap-2">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-500" />
            <input
              type="text"
              placeholder="Search by flow ID, evidence metric, or threat vector..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full rounded-lg border border-slate-800 bg-slate-950/70 pl-9 pr-3 py-1.5 text-xs font-mono text-slate-200 placeholder-slate-500 focus:border-cyan-500/50 focus:outline-none"
            />
          </div>

          <select
            value={filterClass}
            onChange={(e) => setFilterClass(e.target.value)}
            className="rounded-lg border border-slate-800 bg-slate-950/70 px-3 py-1.5 text-xs font-mono text-slate-300 focus:border-cyan-500/50 focus:outline-none"
          >
            <option value="ALL">All Threat Vectors</option>
            <option value="VOLUMETRIC_DDOS">VOLUMETRIC_DDOS</option>
            <option value="BOTNET_C2">BOTNET_C2</option>
            <option value="DGA_DNS_TUNNEL">DGA_DNS_TUNNEL</option>
            <option value="ENCRYPTED_MALWARE">ENCRYPTED_MALWARE</option>
            <option value="RECON_SCAN">RECON_SCAN</option>
            <option value="DATA_EXFIL">DATA_EXFIL</option>
          </select>
        </div>
      </div>

      {/* Alerts Stream List */}
      <div className="flex-1 overflow-y-auto p-3 space-y-2.5 custom-scrollbar">
        {filteredAlerts.length === 0 ? (
          <div className="flex h-full items-center justify-center text-xs font-mono text-slate-500">
            No threat incidents match the current filters.
          </div>
        ) : (
          filteredAlerts.map((alert, idx) => {
            const isExpanded = expandedFlowId === `${alert.flow_id}-${idx}`;
            const isSelected = selectedAlertFlowId === alert.flow_id;
            const timeStr = new Date(alert.timestamp).toLocaleTimeString([], {
              hour: '2-digit',
              minute: '2-digit',
              second: '2-digit',
            });

            return (
              <div
                key={`${alert.flow_id}-${idx}`}
                className={`rounded-xl border p-3 transition-all ${
                  isSelected
                    ? 'border-cyan-500 bg-cyan-950/20 shadow-[0_0_15px_rgba(6,182,212,0.15)]'
                    : 'border-slate-800/80 bg-slate-950/50 hover:border-slate-700 hover:bg-slate-950/80'
                }`}
              >
                {/* Top Row: Threat Class, Severity, Confidence, Time */}
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${getSeverityBadge(
                        alert.severity
                      )}`}
                    >
                      {alert.severity}
                    </span>
                    <span className="font-mono text-xs font-bold text-white tracking-wide">
                      {alert.threat_class}
                    </span>
                    <span className="text-slate-500 font-mono text-xs">&bull;</span>
                    <span className="font-mono text-xs text-cyan-400 font-semibold">
                      Score: {alert.confidence_score.toFixed(2)}
                    </span>
                  </div>

                  <div className="flex items-center gap-3 text-[11px] font-mono text-slate-400">
                    <div className="flex items-center gap-1">
                      <Clock className="h-3 w-3 text-slate-400" />
                      <span>{timeStr}</span>
                    </div>

                    <button
                      onClick={() => handleCopy(JSON.stringify(alert, null, 2), `${alert.flow_id}-${idx}`)}
                      className="text-slate-400 hover:text-cyan-400 p-0.5 rounded"
                      title="Copy standardized alert JSON"
                    >
                      {copiedId === `${alert.flow_id}-${idx}` ? (
                        <Check className="h-3.5 w-3.5 text-emerald-400" />
                      ) : (
                        <Copy className="h-3.5 w-3.5" />
                      )}
                    </button>
                  </div>
                </div>

                {/* Middle Row: Flow ID */}
                <div className="mt-2 flex flex-wrap items-center justify-between gap-2">
                  <div className="font-mono text-xs text-slate-300 bg-slate-900/80 border border-slate-800 rounded px-2 py-1 select-all">
                    {alert.flow_id}
                  </div>

                  {/* Actions: Gemini Assessment & Expand Drawer */}
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => onSelectAlertForAnalysis(alert)}
                      className="flex items-center gap-1.5 rounded bg-cyan-950/60 border border-cyan-500/30 px-2.5 py-1 text-[11px] font-mono font-bold text-cyan-300 hover:bg-cyan-900/40 hover:border-cyan-400 transition-colors shadow-sm"
                    >
                      <Cpu className="h-3 w-3 text-cyan-400" />
                      <span>Analyze with Gemini</span>
                    </button>

                    <button
                      onClick={() =>
                        setExpandedFlowId(isExpanded ? null : `${alert.flow_id}-${idx}`)
                      }
                      className="p-1 rounded text-slate-400 hover:text-slate-200"
                      title="Toggle evidence drawer"
                    >
                      {isExpanded ? (
                        <ChevronUp className="h-4 w-4" />
                      ) : (
                        <ChevronDown className="h-4 w-4" />
                      )}
                    </button>
                  </div>
                </div>

                {/* Evidence Drawer */}
                {isExpanded && (
                  <div className="mt-3 border-t border-slate-800/80 pt-2.5">
                    <div className="text-[10px] uppercase font-mono font-bold text-slate-400 mb-1.5">
                      Passive Evidence Key-Values:
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5 text-xs font-mono">
                      {Object.entries(alert.evidence).map(([key, val]) => (
                        <div
                          key={key}
                          className="rounded bg-slate-900/80 border border-slate-800/70 p-1.5 flex justify-between gap-2"
                        >
                          <span className="text-slate-400">{key}:</span>
                          <span className="text-cyan-300 font-medium truncate">{val}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
