"use client";

import React from 'react';
import {
  Sparkles,
  Bot,
  ShieldAlert,
  Terminal,
  CheckCircle2,
  RefreshCw,
  Layers,
  ArrowRight,
} from 'lucide-react';
import { StandardizedAlert, GeminiAssessment } from '../lib/mockData';

interface GeminiAnalystCardProps {
  currentAlert: StandardizedAlert | null;
  assessment: GeminiAssessment | null;
  loading?: boolean;
  onRefreshAssessment?: () => void;
}

export const GeminiAnalystCard: React.FC<GeminiAnalystCardProps> = ({
  currentAlert,
  assessment,
  loading = false,
  onRefreshAssessment,
}) => {
  return (
    <div className="relative overflow-hidden rounded-2xl border border-[#E5E5F0] dark:border-white/5 bg-white dark:bg-[#26282E] p-5 shadow-saas-light dark:shadow-saas-dark transition-colors">
      {/* Card Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#E5E5F0] dark:border-white/5 pb-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-full bg-violet-50 dark:bg-violet-500/15 text-violet-600 dark:text-violet-400">
            <Sparkles className="h-5 w-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold tracking-tight text-[#1E1E2D] dark:text-white">
                AI Threat Intelligence Analyst
              </h3>
              <span className="hidden sm:inline-flex items-center rounded-full bg-violet-50 dark:bg-violet-500/10 px-2.5 py-0.5 text-[10px] font-bold text-violet-700 dark:text-violet-400 border border-violet-200 dark:border-violet-500/20">
                Cognitive Enclave
              </span>
            </div>
            <p className="text-[11px] font-medium text-[#8A8FA3] dark:text-[#9CA3AF]">
              Zero-decryption threat assessment grounded in passive metadata attributes
            </p>
          </div>
        </div>

        {onRefreshAssessment && (
          <button
            onClick={onRefreshAssessment}
            disabled={loading || !currentAlert}
            className="inline-flex items-center gap-1.5 rounded-full bg-indigo-600 dark:bg-indigo-500 hover:bg-indigo-700 px-4 py-1.5 text-xs font-semibold text-white shadow-sm disabled:opacity-50 transition-all cursor-pointer"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>{loading ? 'Evaluating...' : 'Re-Evaluate with Gemini'}</span>
          </button>
        )}
      </div>

      {/* Body Content */}
      {loading ? (
        <div className="flex flex-col items-center justify-center py-16 text-center">
          <div className="relative mb-3 flex h-12 w-12 items-center justify-center rounded-full bg-violet-50 dark:bg-violet-500/15 text-violet-600 dark:text-violet-400">
            <Bot className="h-6 w-6 animate-bounce" />
          </div>
          <span className="text-xs font-bold text-indigo-600 dark:text-indigo-400">
            Querying Google Gemini Threat Intelligence Engine...
          </span>
          <span className="text-[11px] font-medium text-[#8A8FA3] dark:text-[#9CA3AF] mt-1">
            Synthesizing passive metadata &bull; MITRE ATT&CK correlation &bull; Zero return path
          </span>
        </div>
      ) : assessment ? (
        <div className="mt-4 space-y-4 text-xs">
          {/* Target Flow & Threat Banner */}
          <div className="flex flex-wrap items-center justify-between gap-2.5 rounded-xl border border-[#E5E5F0] dark:border-white/5 bg-[#F8F8FC] dark:bg-[#1E1F24] p-3 font-mono">
            <div className="flex items-center gap-2">
              <span className="text-[#8A8FA3] dark:text-[#9CA3AF]">Target Flow:</span>
              <span className="font-bold text-[#1E1E2D] dark:text-white select-all">
                {assessment.flow_id || currentAlert?.flow_id}
              </span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="text-[#8A8FA3] dark:text-[#9CA3AF]">Model:</span>
              <span className="inline-flex items-center rounded-full bg-indigo-50 dark:bg-indigo-500/10 px-2 py-0.5 text-[10px] font-bold text-indigo-700 dark:text-indigo-400">
                {assessment.model_used}
              </span>
            </div>
          </div>

          {/* MITRE ATT&CK Mapping Grid */}
          <div className="rounded-xl border border-[#E5E5F0] dark:border-white/5 bg-[#F8F8FC] dark:bg-[#1E1F24] p-3.5">
            <div className="text-[10px] uppercase font-bold text-[#8A8FA3] dark:text-[#9CA3AF] mb-2.5 flex items-center gap-1.5">
              <Layers className="h-3.5 w-3.5 text-indigo-600 dark:text-indigo-400" />
              <span>MITRE ATT&CK TTP Mapping</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              <div className="rounded-xl border border-[#E5E5F0] dark:border-white/5 bg-white dark:bg-[#26282E] p-3 shadow-saas-light-sm dark:shadow-saas-dark-sm">
                <span className="text-[10px] uppercase font-semibold text-[#8A8FA3] dark:text-[#9CA3AF] block mb-1">
                  Tactic
                </span>
                <span className="font-bold text-amber-600 dark:text-amber-400 block leading-snug">
                  {assessment.mitre_attack_mapping.tactic}
                </span>
              </div>

              <div className="rounded-xl border border-[#E5E5F0] dark:border-white/5 bg-white dark:bg-[#26282E] p-3 shadow-saas-light-sm dark:shadow-saas-dark-sm">
                <span className="text-[10px] uppercase font-semibold text-[#8A8FA3] dark:text-[#9CA3AF] block mb-1">
                  Technique ID
                </span>
                <span className="font-bold font-mono text-indigo-600 dark:text-indigo-400 block leading-snug">
                  {assessment.mitre_attack_mapping.technique_id}
                </span>
              </div>

              <div className="col-span-1 sm:col-span-2 rounded-xl border border-[#E5E5F0] dark:border-white/5 bg-white dark:bg-[#26282E] p-3 shadow-saas-light-sm dark:shadow-saas-dark-sm">
                <span className="text-[10px] uppercase font-semibold text-[#8A8FA3] dark:text-[#9CA3AF] block mb-1">
                  Technique Name
                </span>
                <span className="font-bold text-[#1E1E2D] dark:text-white block">
                  {assessment.mitre_attack_mapping.technique_name}
                </span>
              </div>
            </div>
          </div>

          {/* Threat Hypothesis */}
          <div className="rounded-xl border border-[#E5E5F0] dark:border-white/5 bg-[#F8F8FC] dark:bg-[#1E1F24] p-3.5">
            <div className="text-[10px] uppercase font-bold text-[#8A8FA3] dark:text-[#9CA3AF] mb-1.5 flex items-center gap-1.5">
              <ShieldAlert className="h-3.5 w-3.5 text-rose-500 dark:text-rose-400" />
              <span>Analyst Threat Hypothesis</span>
            </div>
            <p className="text-[#1E1E2D] dark:text-[#F3F4F6] leading-relaxed text-xs">
              {assessment.threat_hypothesis}
            </p>
          </div>

          {/* Passive Evidence Breakdown */}
          <div className="rounded-xl border border-[#E5E5F0] dark:border-white/5 bg-[#F8F8FC] dark:bg-[#1E1F24] p-3.5">
            <div className="text-[10px] uppercase font-bold text-[#8A8FA3] dark:text-[#9CA3AF] mb-1.5 flex items-center gap-1.5">
              <Terminal className="h-3.5 w-3.5 text-indigo-600 dark:text-indigo-400" />
              <span>Passive Evidence Evaluation (Zero Decryption)</span>
            </div>
            <div className="rounded-lg bg-white dark:bg-[#26282E] border border-[#E5E5F0] dark:border-white/5 p-2.5 text-[11px] font-mono font-medium text-indigo-700 dark:text-indigo-300 leading-normal">
              {assessment.passive_evidence_analysis}
            </div>
          </div>

          {/* Passive Monitoring Recommendations */}
          <div className="rounded-xl border border-[#E5E5F0] dark:border-white/5 bg-[#F8F8FC] dark:bg-[#1E1F24] p-3.5">
            <div className="text-[10px] uppercase font-bold text-[#8A8FA3] dark:text-[#9CA3AF] mb-2 flex items-center gap-1.5">
              <CheckCircle2 className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-400" />
              <span>Recommended Non-Intrusive Actions (Zero Return Path)</span>
            </div>

            <ul className="space-y-2">
              {assessment.passive_monitoring_recommendations.map((rec, i) => (
                <li key={i} className="flex items-start gap-2 text-[#1E1E2D] dark:text-[#F3F4F6] text-xs leading-normal">
                  <ArrowRight className="h-3.5 w-3.5 text-indigo-600 dark:text-indigo-400 mt-0.5 shrink-0" />
                  <span>{rec}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      ) : (
        <div className="flex flex-col items-center justify-center py-16 text-center">
          <div className="flex h-12 w-12 items-center justify-center rounded-full bg-[#F8F8FC] dark:bg-[#1E1F24] text-[#8A8FA3] dark:text-[#9CA3AF] mb-2">
            <Bot className="h-6 w-6" />
          </div>
          <p className="text-xs font-medium text-[#8A8FA3] dark:text-[#9CA3AF]">
            Select an incident from the stream to generate a Google Gemini Threat Intelligence Assessment.
          </p>
        </div>
      )}
    </div>
  );
};
