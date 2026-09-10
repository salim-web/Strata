"use client";

import React from 'react';
import { Activity, Gauge, Database, Clock, ArrowUpRight } from 'lucide-react';
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
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {/* 1. Sustained Flows/sec */}
      <div className="relative overflow-hidden rounded-xl border border-slate-800/80 bg-slate-900/60 p-4 shadow-lg backdrop-blur-md transition-all hover:border-cyan-500/40 hover:shadow-[0_0_20px_rgba(6,182,212,0.15)] group">
        <div className="flex items-center justify-between">
          <span className="text-xs font-mono font-medium uppercase tracking-wider text-slate-400">
            Sustained Ingest Rate
          </span>
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-cyan-950/50 text-cyan-400 border border-cyan-500/20">
            <Activity className="h-4 w-4" />
          </div>
        </div>

        <div className="mt-2 flex items-baseline gap-2">
          <span className="text-2xl lg:text-3xl font-bold font-mono text-white tracking-tight">
            {flows.toLocaleString(undefined, { maximumFractionDigits: 0 })}
          </span>
          <span className="text-xs font-mono text-cyan-400 font-semibold">flows/sec</span>
        </div>

        {/* Progress bar towards 5,000 fps target */}
        <div className="mt-3">
          <div className="flex justify-between text-[10px] font-mono text-slate-400 mb-1">
            <span>Target: 2,000 - 5,000 fps</span>
            <span className="text-cyan-400 font-semibold">{targetCapacityPct}% capacity</span>
          </div>
          <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
            <div
              className="h-full bg-gradient-to-r from-cyan-500 to-emerald-400 transition-all duration-500"
              style={{ width: `${Math.max(5, targetCapacityPct)}%` }}
            />
          </div>
        </div>
      </div>

      {/* 2. Sustained Throughput (Mbps) */}
      <div className="relative overflow-hidden rounded-xl border border-slate-800/80 bg-slate-900/60 p-4 shadow-lg backdrop-blur-md transition-all hover:border-emerald-500/40 hover:shadow-[0_0_20px_rgba(16,185,129,0.15)] group">
        <div className="flex items-center justify-between">
          <span className="text-xs font-mono font-medium uppercase tracking-wider text-slate-400">
            Network Bandwidth
          </span>
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-950/50 text-emerald-400 border border-emerald-500/20">
            <Gauge className="h-4 w-4" />
          </div>
        </div>

        <div className="mt-2 flex items-baseline gap-2">
          <span className="text-2xl lg:text-3xl font-bold font-mono text-white tracking-tight">
            {mbps.toFixed(2)}
          </span>
          <span className="text-xs font-mono text-emerald-400 font-semibold">Mbps</span>
        </div>

        <div className="mt-3 flex items-center justify-between text-[11px] font-mono text-slate-400">
          <span>Mirror Ingress</span>
          <span className="text-emerald-400 font-medium">100% Non-Intrusive</span>
        </div>
      </div>

      {/* 3. Ingested Packets & Total Flows */}
      <div className="relative overflow-hidden rounded-xl border border-slate-800/80 bg-slate-900/60 p-4 shadow-lg backdrop-blur-md transition-all hover:border-indigo-500/40 hover:shadow-[0_0_20px_rgba(99,102,241,0.15)] group">
        <div className="flex items-center justify-between">
          <span className="text-xs font-mono font-medium uppercase tracking-wider text-slate-400">
            Telemetry Accounting
          </span>
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-indigo-950/50 text-indigo-400 border border-indigo-500/20">
            <Database className="h-4 w-4" />
          </div>
        </div>

        <div className="mt-2 flex items-baseline gap-2">
          <span className="text-2xl lg:text-3xl font-bold font-mono text-white tracking-tight">
            {(packets / 1_000_000).toFixed(2)}M
          </span>
          <span className="text-xs font-mono text-indigo-400 font-semibold">packets</span>
        </div>

        <div className="mt-3 flex items-center justify-between text-[11px] font-mono text-slate-400">
          <span>Cumulative Flows</span>
          <span className="text-slate-200 font-semibold">{totalFlows.toLocaleString()}</span>
        </div>
      </div>

      {/* 4. Pipeline Latency (<50ms SLA) & Active Anomalies */}
      <div className="relative overflow-hidden rounded-xl border border-slate-800/80 bg-slate-900/60 p-4 shadow-lg backdrop-blur-md transition-all hover:border-amber-500/40 hover:shadow-[0_0_20px_rgba(245,158,11,0.15)] group">
        <div className="flex items-center justify-between">
          <span className="text-xs font-mono font-medium uppercase tracking-wider text-slate-400">
            Pipeline Latency SLA
          </span>
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-amber-950/50 text-amber-400 border border-amber-500/20">
            <Clock className="h-4 w-4" />
          </div>
        </div>

        <div className="mt-2 flex items-baseline gap-2">
          <span className="text-2xl lg:text-3xl font-bold font-mono text-emerald-400 tracking-tight">
            {latency.toFixed(1)}
          </span>
          <span className="text-xs font-mono text-slate-400">ms</span>
          <span className="ml-auto inline-flex items-center rounded-md bg-emerald-500/10 px-2 py-0.5 text-[10px] font-mono font-bold text-emerald-400 border border-emerald-500/20">
            BOUNDED &lt; 50ms
          </span>
        </div>

        <div className="mt-3 flex items-center justify-between text-[11px] font-mono text-slate-400">
          <span>Active In-Window Anomalies</span>
          <span className="text-amber-400 font-bold font-mono">{anomalies}</span>
        </div>
      </div>
    </div>
  );
};
