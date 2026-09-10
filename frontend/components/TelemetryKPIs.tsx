"use client";

import React from 'react';
import { Activity, Gauge, Database, Clock } from 'lucide-react';
import { EnclaveKPIs } from '../lib/mockData';

interface TelemetryKPIsProps {
  kpis: EnclaveKPIs;
}

export const TelemetryKPIs: React.FC<TelemetryKPIsProps> = ({ kpis }) => {
  const flows = kpis.sustained_flows_per_sec || 0;
  const mbps = kpis.sustained_mbps || 0;
  const packets = kpis.ingested_packets_total || 0;
  const totalFlows = kpis.ingested_flows_total || 0;
  const latency = kpis.pipeline_latency_ms || 0;
  const anomalies = kpis.active_anomalies_count || 0;

  // Rate capacity percentage against 5,000 flows/sec baseline target
  const targetCapacityPct = Math.min(100, Math.round((flows / 5000.0) * 100));

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 sm:gap-5">
      {/* 1. Sustained Flows/sec */}
      <div className="group relative overflow-hidden rounded-2xl border border-[#E5E5F0] dark:border-white/5 bg-white dark:bg-[#26282E] p-5 shadow-saas-light dark:shadow-saas-dark transition-all duration-200 hover:-translate-y-0.5">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold uppercase tracking-wider text-[#8A8FA3] dark:text-[#9CA3AF]">
            Sustained Ingest Rate
          </span>
          <div className="flex h-10 w-10 items-center justify-center rounded-full bg-indigo-50 dark:bg-indigo-500/15 text-indigo-600 dark:text-indigo-400">
            <Activity className="h-5 w-5" />
          </div>
        </div>

        <div className="mt-3 flex items-baseline gap-2">
          <span className="text-2xl lg:text-3xl font-extrabold tracking-tight text-[#1E1E2D] dark:text-white">
            {flows.toLocaleString(undefined, { maximumFractionDigits: 0 })}
          </span>
          <span className="text-xs font-semibold text-indigo-600 dark:text-indigo-400">flows/sec</span>
        </div>

        {/* Progress bar towards target */}
        <div className="mt-4">
          <div className="flex justify-between text-[11px] font-medium text-[#8A8FA3] dark:text-[#9CA3AF] mb-1.5">
            <span>Target: 2,000 – 5,000 fps</span>
            <span className="font-semibold text-indigo-600 dark:text-indigo-400">{targetCapacityPct}%</span>
          </div>
          <div className="h-2 w-full overflow-hidden rounded-full bg-[#ECEBF5] dark:bg-white/10">
            <div
              className="h-full rounded-full bg-gradient-to-r from-indigo-500 via-indigo-600 to-violet-500 transition-all duration-500"
              style={{ width: `${Math.max(6, targetCapacityPct)}%` }}
            />
          </div>
        </div>
      </div>

      {/* 2. Network Bandwidth (Mbps) */}
      <div className="group relative overflow-hidden rounded-2xl border border-[#E5E5F0] dark:border-white/5 bg-white dark:bg-[#26282E] p-5 shadow-saas-light dark:shadow-saas-dark transition-all duration-200 hover:-translate-y-0.5">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold uppercase tracking-wider text-[#8A8FA3] dark:text-[#9CA3AF]">
            Network Bandwidth
          </span>
          <div className="flex h-10 w-10 items-center justify-center rounded-full bg-emerald-50 dark:bg-emerald-500/15 text-emerald-600 dark:text-emerald-400">
            <Gauge className="h-5 w-5" />
          </div>
        </div>

        <div className="mt-3 flex items-baseline gap-2">
          <span className="text-2xl lg:text-3xl font-extrabold tracking-tight text-[#1E1E2D] dark:text-white">
            {mbps.toFixed(2)}
          </span>
          <span className="text-xs font-semibold text-emerald-600 dark:text-emerald-400">Mbps</span>
        </div>

        <div className="mt-4 flex items-center justify-between text-xs font-medium text-[#8A8FA3] dark:text-[#9CA3AF]">
          <span>Mirror Ingress</span>
          <span className="inline-flex items-center rounded-full bg-emerald-50 dark:bg-emerald-500/10 px-2.5 py-0.5 text-[11px] font-semibold text-emerald-700 dark:text-emerald-400">
            100% Passive
          </span>
        </div>
      </div>

      {/* 3. Ingested Packets & Total Flows */}
      <div className="group relative overflow-hidden rounded-2xl border border-[#E5E5F0] dark:border-white/5 bg-white dark:bg-[#26282E] p-5 shadow-saas-light dark:shadow-saas-dark transition-all duration-200 hover:-translate-y-0.5">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold uppercase tracking-wider text-[#8A8FA3] dark:text-[#9CA3AF]">
            Telemetry Accounting
          </span>
          <div className="flex h-10 w-10 items-center justify-center rounded-full bg-sky-50 dark:bg-sky-500/15 text-sky-600 dark:text-sky-400">
            <Database className="h-5 w-5" />
          </div>
        </div>

        <div className="mt-3 flex items-baseline gap-2">
          <span className="text-2xl lg:text-3xl font-extrabold tracking-tight text-[#1E1E2D] dark:text-white">
            {(packets / 1_000_000).toFixed(2)}M
          </span>
          <span className="text-xs font-semibold text-sky-600 dark:text-sky-400">packets</span>
        </div>

        <div className="mt-4 flex items-center justify-between text-xs font-medium text-[#8A8FA3] dark:text-[#9CA3AF]">
          <span>Cumulative Flows</span>
          <span className="font-semibold text-[#1E1E2D] dark:text-white">{totalFlows.toLocaleString()}</span>
        </div>
      </div>

      {/* 4. Pipeline Latency (<50ms SLA) & Active Anomalies */}
      <div className="group relative overflow-hidden rounded-2xl border border-[#E5E5F0] dark:border-white/5 bg-white dark:bg-[#26282E] p-5 shadow-saas-light dark:shadow-saas-dark transition-all duration-200 hover:-translate-y-0.5">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold uppercase tracking-wider text-[#8A8FA3] dark:text-[#9CA3AF]">
            Pipeline Latency SLA
          </span>
          <div className="flex h-10 w-10 items-center justify-center rounded-full bg-amber-50 dark:bg-amber-500/15 text-amber-600 dark:text-amber-400">
            <Clock className="h-5 w-5" />
          </div>
        </div>

        <div className="mt-3 flex items-baseline gap-2">
          <span className="text-2xl lg:text-3xl font-extrabold tracking-tight text-emerald-600 dark:text-emerald-400">
            {latency.toFixed(1)}
          </span>
          <span className="text-xs font-medium text-[#8A8FA3] dark:text-[#9CA3AF]">ms</span>
          <span className="ml-auto inline-flex items-center rounded-full bg-emerald-50 dark:bg-emerald-500/10 px-2 py-0.5 text-[10px] font-bold text-emerald-700 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-500/20">
            &lt; 50ms SLA
          </span>
        </div>

        <div className="mt-4 flex items-center justify-between text-xs font-medium text-[#8A8FA3] dark:text-[#9CA3AF]">
          <span>Active In-Window</span>
          <span className="inline-flex items-center rounded-full bg-amber-50 dark:bg-amber-500/10 px-2 py-0.5 text-[11px] font-bold text-amber-700 dark:text-amber-400">
            {anomalies} anomalies
          </span>
        </div>
      </div>
    </div>
  );
};
