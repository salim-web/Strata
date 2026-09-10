"use client";

import React, { useState } from 'react';
import {
  AlertCircle,
  ChevronDown,
  ChevronUp,
  Cpu,
  Clock,
  Search,
  Check,
  Copy,
  Sparkles,
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
    <div className="flex flex-col h-[640px] rounded-2xl border border-[#E5E5F0] dark:border-white/5 bg-white dark:bg-[#26282E] shadow-saas-light dark:shadow-saas-dark overflow-hidden transition-colors">
      {/* Header Container */}
      <div className="border-b border-[#E5E5F0] dark:border-white/5 p-4 sm:p-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-full bg-indigo-50 dark:bg-indigo-500/15 text-indigo-600 dark:text-indigo-400">
              <AlertCircle className="h-5 w-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold tracking-tight text-[#1E1E2D] dark:text-white">
                Streaming Incident Feed
              </h3>
              <p className="text-[11px] font-medium text-[#8A8FA3] dark:text-[#9CA3AF]">
                Live passive telemetry events &bull; Bounded Latency &bull; Non-reloading stream
              </p>
            </div>
          </div>

          {/* Severity Badges Pill Filter */}
          <div className="flex items-center gap-1 rounded-full border border-[#E5E5F0] dark:border-white/10 bg-[#F8F8FC] dark:bg-[#1E1F24] p-1 text-xs">
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map((sev) => {
              const active = filterSeverity === sev;
              return (
                <button
                  key={sev}
                  onClick={() => setFilterSeverity(sev)}
                  className={`rounded-full px-3 py-1 text-xs font-semibold transition-all cursor-pointer ${
                    active
                      ? 'bg-indigo-600 text-white shadow-sm'
                      : 'text-[#8A8FA3] dark:text-[#9CA3AF] hover:text-[#1E1E2D] dark:hover:text-white'
                  }`}
                >
                  {sev}
                </button>
              );
            })}
          </div>
        </div>

        {/* Search & Threat Class Filter Pill Bar */}
        <div className="mt-3.5 flex flex-col sm:flex-row gap-2.5">
          <div className="relative flex-1">
            <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-[#8A8FA3] dark:text-[#9CA3AF]" />
            <input
              type="text"
              placeholder="Search by flow ID, evidence metric, or threat vector..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full rounded-full border border-[#E5E5F0] dark:border-white/10 bg-[#F8F8FC] dark:bg-[#1E1F24] pl-9 pr-4 py-2 text-xs font-medium text-[#1E1E2D] dark:text-[#F3F4F6] placeholder-[#8A8FA3] dark:placeholder-[#9CA3AF] focus:border-indigo-500 focus:outline-none transition-colors"
            />
          </div>

          <select
            value={filterClass}
            onChange={(e) => setFilterClass(e.target.value)}
            className="rounded-full border border-[#E5E5F0] dark:border-white/10 bg-[#F8F8FC] dark:bg-[#1E1F24] px-4 py-2 text-xs font-medium text-[#1E1E2D] dark:text-[#F3F4F6] focus:border-indigo-500 focus:outline-none transition-colors cursor-pointer"
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
      <div className="flex-1 overflow-y-auto p-4 space-y-2.5 custom-scrollbar">
        {filteredAlerts.length === 0 ? (
          <div className="flex h-full flex-col items-center justify-center text-center p-6">
            <div className="flex h-12 w-12 items-center justify-center rounded-full bg-[#F8F8FC] dark:bg-[#1E1F24] text-[#8A8FA3] dark:text-[#9CA3AF] mb-2">
              <Search className="h-5 w-5" />
            </div>
            <p className="text-xs font-medium text-[#8A8FA3] dark:text-[#9CA3AF]">
              No threat incidents match the current filters.
            </p>
          </div>
        ) : (
          filteredAlerts.map((alert, idx) => {
            const isExpanded = expandedFlowId === `${alert.flow_id}-${idx}`;
            const isSelectedForAnalyst = selectedAlertFlowId === alert.flow_id;
            const confidencePct = Math.round(alert.confidence_score * 100);

            return (
              <div
                key={`${alert.flow_id}-${idx}`}
                className={`group rounded-xl border p-3.5 transition-all duration-200 ${
                  isSelectedForAnalyst
                    ? 'border-indigo-500 bg-indigo-50/40 dark:bg-indigo-950/20 ring-1 ring-indigo-500/30'
                    : 'border-[#E5E5F0] dark:border-white/5 bg-[#F8F8FC] dark:bg-[#1E1F24] hover:border-indigo-200 dark:hover:border-white/15'
                }`}
              >
                {/* Main Alert Summary Row */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-[10px] font-bold tracking-wider ${getSeverityPill(
                        alert.severity
                      )}`}
                    >
                      {alert.severity}
                    </span>

                    <span className="text-xs font-bold font-mono text-[#1E1E2D] dark:text-white">
                      {alert.threat_class}
                    </span>

                    <span className="rounded-full bg-white dark:bg-[#26282E] border border-[#E5E5F0] dark:border-white/10 px-2 py-0.5 text-[10px] font-bold text-indigo-600 dark:text-indigo-400">
                      {confidencePct}% conf
                    </span>
                  </div>

                  {/* Flow ID & Actions */}
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleCopy(alert.flow_id, `${alert.flow_id}-${idx}`)}
                      title="Copy Flow ID"
                      className="inline-flex items-center gap-1 rounded-full border border-[#E5E5F0] dark:border-white/10 bg-white dark:bg-[#26282E] px-2.5 py-1 text-[10px] font-mono text-[#8A8FA3] dark:text-[#9CA3AF] hover:text-[#1E1E2D] dark:hover:text-white cursor-pointer transition-colors"
                    >
                      {copiedId === `${alert.flow_id}-${idx}` ? (
                        <Check className="h-3 w-3 text-emerald-500" />
                      ) : (
                        <Copy className="h-3 w-3" />
                      )}
                      <span className="truncate max-w-[160px]">{alert.flow_id}</span>
                    </button>

                    <button
                      onClick={() => onSelectAlertForAnalysis(alert)}
                      className="inline-flex items-center gap-1 rounded-full bg-indigo-600 dark:bg-indigo-500 hover:bg-indigo-700 px-3 py-1 text-[11px] font-semibold text-white shadow-sm transition-all cursor-pointer"
                    >
                      <Sparkles className="h-3 w-3" />
                      <span>Assess</span>
                    </button>

                    <button
                      onClick={() =>
                        setExpandedFlowId(isExpanded ? null : `${alert.flow_id}-${idx}`)
                      }
                      className="flex h-6 w-6 items-center justify-center rounded-full border border-[#E5E5F0] dark:border-white/10 bg-white dark:bg-[#26282E] text-[#8A8FA3] dark:text-[#9CA3AF] hover:text-[#1E1E2D] dark:hover:text-white cursor-pointer transition-colors"
                    >
                      {isExpanded ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
                    </button>
                  </div>
                </div>

                {/* Timestamp & Meta */}
                <div className="mt-2 flex items-center gap-3 text-[10px] font-medium text-[#8A8FA3] dark:text-[#9CA3AF]">
                  <span className="flex items-center gap-1">
                    <Clock className="h-3 w-3" />
                    {new Date(alert.timestamp).toLocaleTimeString()}
                  </span>
                  <span>&bull;</span>
                  <span>Diode Non-Blocking Observability</span>
                </div>

                {/* Collapsible Evidence JSON */}
                {isExpanded && (
                  <div className="mt-3 rounded-xl border border-[#E5E5F0] dark:border-white/10 bg-white dark:bg-[#26282E] p-3 text-[11px] font-mono">
                    <span className="text-[10px] font-bold uppercase tracking-wider text-[#8A8FA3] dark:text-[#9CA3AF] block mb-2">
                      Passive Evidence Payload
                    </span>
                    <pre className="text-xs text-[#1E1E2D] dark:text-[#F3F4F6] overflow-x-auto whitespace-pre-wrap">
                      {JSON.stringify(alert.evidence, null, 2)}
                    </pre>
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
