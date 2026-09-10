"use client";

import React, { useState } from 'react';
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
import { requestGeminiAssessment } from '../lib/api';

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
    <div className="relative overflow-hidden rounded-xl border border-cyan-500/30 bg-gradient-to-b from-slate-900/90 via-[#070d18] to-slate-950 p-5 shadow-[0_0_30px_rgba(6,182,212,0.12)] backdrop-blur-xl">
      {/* Glow decorative corner */}
      <div className="pointer-events-none absolute -top-12 -right-12 h-36 w-36 rounded-full bg-cyan-500/10 blur-3xl" />

      {/* Card Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-cyan-950/60 pb-3.5">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 shadow-[0_0_12px_rgba(6,182,212,0.3)]">
            <Sparkles className="h-5 w-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold font-mono text-white tracking-wide">
                AI Intelligence Analyst 
              </h3>
            </div>
            <p className="text-[11px] font-mono text-slate-400">
              Zero-decryption threat assessment grounded strictly in passive evidence attributes
            </p>
          </div>
        </div>

        {onRefreshAssessment && (
          <button
            onClick={onRefreshAssessment}
            disabled={loading || !currentAlert}
            className="flex items-center gap-1.5 rounded-lg border border-cyan-500/30 bg-cyan-950/40 px-3 py-1.5 text-xs font-mono font-semibold text-cyan-300 hover:bg-cyan-900/40 hover:border-cyan-400 disabled:opacity-50 transition shadow-sm"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
            <span>{loading ? 'Evaluating...' : 'Re-Evaluate with Gemini'}</span>
          </button>
        )}
      </div>

      {/* Body Content */}
      {loading ? (
        <div className="flex flex-col items-center justify-center py-16 text-center">
          <div className="relative mb-3">
            <Bot className="h-8 w-8 text-cyan-400 animate-bounce" />
            <div className="absolute inset-0 rounded-full bg-cyan-400/20 animate-ping" />
          </div>
          <span className="text-xs font-mono font-semibold text-cyan-300">
            Querying Google Gemini Threat Intelligence Engine...
          </span>
          <span className="text-[11px] font-mono text-slate-500 mt-1">
            Synthesizing passive metadata &bull; MITRE ATT&CK correlation &bull; Zero return path
          </span>
        </div>
      ) : assessment ? (
        <div className="mt-4 space-y-4 text-xs font-mono">
          {/* Target Flow & Threat Banner */}
          <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg bg-slate-950/80 border border-slate-800 p-2.5">
            <div className="flex items-center gap-2">
              <span className="text-slate-400">Target Flow:</span>
              <span className="font-bold text-slate-200 select-all">{assessment.flow_id || currentAlert?.flow_id}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-slate-400">Model:</span>
              <span className="font-semibold text-cyan-400">{assessment.model_used}</span>
            </div>
          </div>

          {/* MITRE ATT&CK Mapping Grid */}
          <div className="rounded-xl border border-slate-800/80 bg-slate-950/60 p-3">
            <div className="text-[10px] uppercase font-bold text-slate-400 mb-2 flex items-center gap-1.5">
              <Layers className="h-3.5 w-3.5 text-cyan-400" />
              <span>MITRE ATT&CK TTP Mapping</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 text-xs">
              <div className="rounded-lg bg-slate-900/80 border border-slate-800/80 p-2.5">
                <span className="text-[10px] uppercase font-bold text-slate-400 block mb-1">Tactic</span>
                <span className="font-bold text-amber-400 break-words block leading-snug">
                  {assessment.mitre_attack_mapping.tactic}
                </span>
              </div>

              <div className="rounded-lg bg-slate-900/80 border border-slate-800/80 p-2.5">
                <span className="text-[10px] uppercase font-bold text-slate-400 block mb-1">Technique ID</span>
                <span className="font-bold text-cyan-400 font-mono break-words block leading-snug">
                  {assessment.mitre_attack_mapping.technique_id}
                </span>
              </div>

              <div className="col-span-1 sm:col-span-2 rounded-lg bg-slate-900/80 border border-slate-800/80 p-2.5">
                <span className="text-[10px] uppercase font-bold text-slate-400 block mb-1">Technique Name</span>
                <span
                  className="font-bold text-slate-100 break-words leading-relaxed block text-xs sm:text-[13px]"
                  title={assessment.mitre_attack_mapping.technique_name}
                >
                  {assessment.mitre_attack_mapping.technique_name}
                </span>
              </div>
            </div>
          </div>

          {/* Threat Hypothesis */}
          <div className="rounded-xl border border-slate-800/80 bg-slate-950/60 p-3.5">
            <div className="text-[10px] uppercase font-bold text-slate-400 mb-1.5 flex items-center gap-1.5">
              <ShieldAlert className="h-3.5 w-3.5 text-rose-400" />
              <span>Analyst Threat Hypothesis</span>
            </div>
            <p className="text-slate-300 leading-relaxed font-sans text-xs">
              {assessment.threat_hypothesis}
            </p>
          </div>

          {/* Passive Evidence Breakdown */}
          <div className="rounded-xl border border-slate-800/80 bg-slate-950/60 p-3.5">
            <div className="text-[10px] uppercase font-bold text-slate-400 mb-1.5 flex items-center gap-1.5">
              <Terminal className="h-3.5 w-3.5 text-cyan-400" />
              <span>Passive Evidence Evaluation (Zero Payload Decryption)</span>
            </div>
            <div className="rounded bg-slate-900/90 border border-slate-800 p-2 text-cyan-300 font-mono text-[11px] leading-normal">
              {assessment.passive_evidence_analysis}
            </div>
          </div>

          {/* Passive Monitoring Recommendations (Strictly Out-of-band / No inline blocking) */}
          <div className="rounded-xl border border-slate-800/80 bg-slate-950/60 p-3.5">
            <div className="text-[10px] uppercase font-bold text-slate-400 mb-2 flex items-center gap-1.5">
              <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
              <span>Recommended Passive Actions (Strictly Non-Intrusive)</span>
            </div>

            <ul className="space-y-1.5">
              {assessment.passive_monitoring_recommendations.map((rec, i) => (
                <li key={i} className="flex items-start gap-2 text-slate-300 font-sans text-xs leading-normal">
                  <ArrowRight className="h-3 w-3 text-cyan-400 mt-0.5 shrink-0" />
                  <span>{rec}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      ) : (
        <div className="py-12 text-center text-xs font-mono text-slate-500">
          Select an incident from the stream above to generate a Google Gemini Threat Intelligence Assessment.
        </div>
      )}
    </div>
  );
};
