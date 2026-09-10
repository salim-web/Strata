"use client";

import React from 'react';
import { GeminiAnalystCard } from '../../components/GeminiAnalystCard';
import { useEnclave } from '../../context/EnclaveContext';
import {
  Sparkles,
  Bot,
  Layers,
  ShieldAlert,
  ArrowRight,
  ChevronRight,
  Clock,
} from 'lucide-react';

export default function AnalystPage() {
  const {
    alerts,
    selectedAlert,
    setSelectedAlert,
    assessment,
    analystLoading,
    generateAssessmentForAlert,
    refreshCurrentAssessment,
  } = useEnclave();

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
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 rounded-3xl border border-[#E5E5F0] dark:border-white/5 bg-white dark:bg-[#26282E] p-6 shadow-saas-light dark:shadow-saas-dark">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="flex h-7 w-7 items-center justify-center rounded-full bg-violet-50 dark:bg-violet-500/15 text-violet-600 dark:text-violet-400">
              <Sparkles className="h-4 w-4" />
            </span>
            <h2 className="text-lg sm:text-xl font-extrabold tracking-tight text-[#1E1E2D] dark:text-white">
              Cognitive Threat Analyst // Google Gemini
            </h2>
          </div>
          <p className="text-xs font-medium text-[#8A8FA3] dark:text-[#9CA3AF]">
            Autonomous threat hypothesis formulation and MITRE ATT&CK correlation grounded strictly in passive handshake evidence.
          </p>
        </div>

        <div className="inline-flex items-center gap-2 rounded-full border border-violet-200 dark:border-violet-500/20 bg-violet-50 dark:bg-violet-500/10 px-3.5 py-1.5 text-xs font-bold text-violet-700 dark:text-violet-400 shadow-sm shrink-0">
          <Bot className="h-4 w-4" />
          <span>Zero Payload Decryption AI</span>
        </div>
      </div>

      {/* Main Grid: Incident Selector Drawer (4 cols) + Full Analyst Workspace (8 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Incident Investigation Selector */}
        <div className="lg:col-span-4 space-y-4">
          <div className="rounded-3xl border border-[#E5E5F0] dark:border-white/5 bg-white dark:bg-[#26282E] p-5 shadow-saas-light dark:shadow-saas-dark space-y-3">
            <div className="flex items-center justify-between border-b border-[#E5E5F0] dark:border-white/5 pb-3">
              <div className="flex items-center gap-2">
                <Layers className="h-4 w-4 text-indigo-600 dark:text-indigo-400" />
                <h3 className="text-xs font-bold tracking-tight text-[#1E1E2D] dark:text-white uppercase">
                  Select Incident To Investigate
                </h3>
              </div>
              <span className="text-[11px] font-bold text-[#8A8FA3] dark:text-[#9CA3AF]">
                {alerts.length} In-Memory
              </span>
            </div>

            <div className="max-h-[580px] overflow-y-auto space-y-2 pr-1 custom-scrollbar">
              {alerts.map((alert, idx) => {
                const isSelected = selectedAlert?.flow_id === alert.flow_id;
                const confidencePct = Math.round(alert.confidence_score * 100);

                return (
                  <div
                    key={`${alert.flow_id}-${idx}`}
                    onClick={() => generateAssessmentForAlert(alert)}
                    className={`cursor-pointer rounded-2xl border p-3.5 transition-all text-xs ${
                      isSelected
                        ? 'border-indigo-500 bg-indigo-50/50 dark:bg-indigo-950/25 ring-1 ring-indigo-500/30'
                        : 'border-[#E5E5F0] dark:border-white/5 bg-[#F8F8FC] dark:bg-[#1E1F24] hover:border-indigo-200 dark:hover:border-white/10'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-1 mb-1">
                      <span
                        className={`inline-flex items-center rounded-full border px-2 py-0.2 text-[9px] font-bold ${getSeverityPill(
                          alert.severity
                        )}`}
                      >
                        {alert.severity}
                      </span>
                      <span className="font-bold text-indigo-600 dark:text-indigo-400 text-[10px]">
                        {confidencePct}% conf
                      </span>
                    </div>

                    <div className="font-bold text-[#1E1E2D] dark:text-white truncate">
                      {alert.threat_class}
                    </div>

                    <div className="text-[10px] font-mono text-[#8A8FA3] dark:text-[#9CA3AF] truncate mt-0.5">
                      {alert.flow_id}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Right: Full Gemini Threat Analyst Card */}
        <div className="lg:col-span-8">
          <GeminiAnalystCard
            currentAlert={selectedAlert}
            assessment={assessment}
            loading={analystLoading}
            onRefreshAssessment={refreshCurrentAssessment}
          />
        </div>
      </div>
    </div>
  );
}
