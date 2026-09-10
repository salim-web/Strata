"use client";

import React from 'react';
import Link from 'next/link';
import { TelemetryKPIs } from '../components/TelemetryKPIs';
import { useEnclave } from '../context/EnclaveContext';
import {
  Shield,
  Radar,
  AlertCircle,
  Sparkles,
  Sliders,
  ArrowRight,
  ShieldCheck,
  Zap,
  Activity,
  ChevronRight,
  ExternalLink,
} from 'lucide-react';

export default function ExecutiveOverviewPage() {
  const { kpis, threatRadar, alerts, setSelectedAlert } = useEnclave();

  // Pick top 6 recent alerts
  const recentAlerts = alerts.slice(0, 6);

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
      {/* 1. Enclave Status Hero Banner */}
      <div className="relative overflow-hidden rounded-3xl border border-[#E5E5F0] dark:border-white/5 bg-white dark:bg-[#26282E] p-6 sm:p-8 shadow-saas-light dark:shadow-saas-dark transition-all">
        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="space-y-2 max-w-2xl">
            <div className="inline-flex items-center gap-2 rounded-full bg-indigo-50 dark:bg-indigo-500/15 border border-indigo-200 dark:border-indigo-500/20 px-3.5 py-1 text-xs font-bold text-indigo-700 dark:text-indigo-400">
              <Shield className="h-3.5 w-3.5" />
              <span>PASSIVE NETWORK SURVEILLANCE ENCLAVE</span>
            </div>

            <h2 className="text-xl sm:text-2xl lg:text-3xl font-extrabold tracking-tight text-[#1E1E2D] dark:text-white">
              Autonomous Threat Intelligence & Real-time Diode Telemetry
            </h2>

            <p className="text-xs sm:text-sm font-medium text-[#8A8FA3] dark:text-[#9CA3AF] leading-relaxed">
              Operating under strict unidirectional optical tap constraints. Transmit fiber cut, zero return path, zero inline blocking, and payload decryption strictly forbidden.
            </p>
          </div>

          <div className="flex flex-wrap md:flex-col gap-2.5 shrink-0">
            <Link
              href="/radar"
              className="inline-flex items-center justify-center gap-2 rounded-2xl bg-indigo-600 hover:bg-indigo-700 text-white px-5 py-2.5 text-xs font-semibold shadow-md shadow-indigo-500/20 transition-all cursor-pointer"
            >
              <span>6-Vector Radar</span>
              <ArrowRight className="h-4 w-4" />
            </Link>

            <Link
              href="/incidents"
              className="inline-flex items-center justify-center gap-2 rounded-2xl border border-[#E5E5F0] dark:border-white/10 bg-[#F8F8FC] dark:bg-[#1E1F24] hover:bg-white dark:hover:bg-[#26282E] text-[#1E1E2D] dark:text-white px-5 py-2.5 text-xs font-semibold shadow-sm transition-all cursor-pointer"
            >
              <span>Incident Forensics</span>
              <ChevronRight className="h-4 w-4" />
            </Link>
          </div>
        </div>
      </div>

      {/* 2. Top-Row Telemetry KPIs */}
      <TelemetryKPIs kpis={kpis} />

      {/* 3. Two-Column Dashboard Split: Threat Radar Overview (7 cols) + Recent Alerts (5 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: 6-Vector Threat Posture Overview */}
        <div className="lg:col-span-7 rounded-2xl border border-[#E5E5F0] dark:border-white/5 bg-white dark:bg-[#26282E] p-5 sm:p-6 shadow-saas-light dark:shadow-saas-dark space-y-4">
          <div className="flex items-center justify-between border-b border-[#E5E5F0] dark:border-white/5 pb-3.5">
            <div className="flex items-center gap-2.5">
              <div className="flex h-9 w-9 items-center justify-center rounded-full bg-indigo-50 dark:bg-indigo-500/15 text-indigo-600 dark:text-indigo-400">
                <Radar className="h-4 w-4 animate-spin" style={{ animationDuration: '8s' }} />
              </div>
              <div>
                <h3 className="text-sm font-bold tracking-tight text-[#1E1E2D] dark:text-white">
                  Multi-Threat Radar Status
                </h3>
                <p className="text-[11px] font-medium text-[#8A8FA3] dark:text-[#9CA3AF]">
                  Sliding-window detection confidence across 6 calibrated vectors
                </p>
              </div>
            </div>

            <Link
              href="/radar"
              className="inline-flex items-center gap-1 text-xs font-bold text-indigo-600 dark:text-indigo-400 hover:underline"
            >
              <span>View Deep Dive</span>
              <ChevronRight className="h-3.5 w-3.5" />
            </Link>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5 pt-1">
            {Object.entries(threatRadar).map(([key, item]) => {
              const confPct = Math.round(item.latest_confidence * 100);
              const label = key.replace(/_/g, ' ');

              return (
                <Link
                  key={key}
                  href="/radar"
                  className="rounded-xl border border-[#E5E5F0] dark:border-white/5 bg-[#F8F8FC] dark:bg-[#1E1F24] p-3.5 hover:border-indigo-300 dark:hover:border-white/15 transition-all group cursor-pointer"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-[#1E1E2D] dark:text-white group-hover:text-indigo-600 dark:group-hover:text-indigo-400 transition-colors">
                      {label}
                    </span>
                    <span
                      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[9px] font-bold ${getSeverityPill(
                        item.severity
                      )}`}
                    >
                      {item.severity}
                    </span>
                  </div>

                  <div className="mt-2.5 flex items-center justify-between text-xs">
                    <span className="text-[11px] text-[#8A8FA3] dark:text-[#9CA3AF]">Confidence</span>
                    <span className="font-extrabold text-indigo-600 dark:text-indigo-400">{confPct}%</span>
                  </div>

                  <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-[#ECEBF5] dark:bg-white/10">
                    <div
                      className="h-full rounded-full bg-indigo-600 transition-all duration-300"
                      style={{ width: `${Math.max(6, confPct)}%` }}
                    />
                  </div>

                  <div className="mt-2 text-[10px] text-[#8A8FA3] dark:text-[#9CA3AF] truncate">
                    {item.sample_evidence}
                  </div>
                </Link>
              );
            })}
          </div>
        </div>

        {/* Right: Recent Incidents Snapshot */}
        <div className="lg:col-span-5 rounded-2xl border border-[#E5E5F0] dark:border-white/5 bg-white dark:bg-[#26282E] p-5 sm:p-6 shadow-saas-light dark:shadow-saas-dark space-y-4">
          <div className="flex items-center justify-between border-b border-[#E5E5F0] dark:border-white/5 pb-3.5">
            <div className="flex items-center gap-2.5">
              <div className="flex h-9 w-9 items-center justify-center rounded-full bg-rose-50 dark:bg-rose-500/15 text-rose-600 dark:text-rose-400">
                <AlertCircle className="h-4 w-4" />
              </div>
              <div>
                <h3 className="text-sm font-bold tracking-tight text-[#1E1E2D] dark:text-white">
                  Recent Anomalies
                </h3>
                <p className="text-[11px] font-medium text-[#8A8FA3] dark:text-[#9CA3AF]">
                  Latest passive telemetry alerts
                </p>
              </div>
            </div>

            <Link
              href="/incidents"
              className="inline-flex items-center gap-1 text-xs font-bold text-indigo-600 dark:text-indigo-400 hover:underline"
            >
              <span>All Incidents</span>
              <ChevronRight className="h-3.5 w-3.5" />
            </Link>
          </div>

          <div className="space-y-2.5">
            {recentAlerts.map((alert, idx) => (
              <div
                key={`${alert.flow_id}-${idx}`}
                className="flex items-center justify-between rounded-xl border border-[#E5E5F0] dark:border-white/5 bg-[#F8F8FC] dark:bg-[#1E1F24] p-3 text-xs hover:border-indigo-200 dark:hover:border-white/10 transition-colors"
              >
                <div className="space-y-0.5 truncate max-w-[220px] sm:max-w-xs">
                  <div className="flex items-center gap-2">
                    <span
                      className={`inline-flex items-center rounded-full border px-2 py-0.2 text-[9px] font-bold ${getSeverityPill(
                        alert.severity
                      )}`}
                    >
                      {alert.severity}
                    </span>
                    <span className="font-bold text-[#1E1E2D] dark:text-white truncate">
                      {alert.threat_class}
                    </span>
                  </div>
                  <div className="text-[10px] font-mono text-[#8A8FA3] dark:text-[#9CA3AF] truncate">
                    {alert.flow_id}
                  </div>
                </div>

                <Link
                  href="/analyst"
                  onClick={() => setSelectedAlert(alert)}
                  className="inline-flex items-center gap-1 rounded-full bg-indigo-50 dark:bg-indigo-500/15 hover:bg-indigo-100 text-indigo-700 dark:text-indigo-400 px-3 py-1 text-[11px] font-bold transition-colors cursor-pointer"
                >
                  <Sparkles className="h-3 w-3" />
                  <span>Analyze</span>
                </Link>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* 4. Quick Navigation Workbench Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 sm:gap-5">
        <Link
          href="/radar"
          className="group rounded-2xl border border-[#E5E5F0] dark:border-white/5 bg-white dark:bg-[#26282E] p-5 shadow-saas-light dark:shadow-saas-dark hover:-translate-y-0.5 transition-all cursor-pointer"
        >
          <div className="flex h-10 w-10 items-center justify-center rounded-full bg-indigo-50 dark:bg-indigo-500/15 text-indigo-600 dark:text-indigo-400 mb-3">
            <Radar className="h-5 w-5" />
          </div>
          <h4 className="text-sm font-bold text-[#1E1E2D] dark:text-white group-hover:text-indigo-600 dark:group-hover:text-indigo-400 transition-colors">
            6-Vector Threat Radar
          </h4>
          <p className="text-xs font-medium text-[#8A8FA3] dark:text-[#9CA3AF] mt-1">
            Examine entropy spikes, IAT variance, and fan-out cardinality in sliding windows.
          </p>
        </Link>

        <Link
          href="/incidents"
          className="group rounded-2xl border border-[#E5E5F0] dark:border-white/5 bg-white dark:bg-[#26282E] p-5 shadow-saas-light dark:shadow-saas-dark hover:-translate-y-0.5 transition-all cursor-pointer"
        >
          <div className="flex h-10 w-10 items-center justify-center rounded-full bg-rose-50 dark:bg-rose-500/15 text-rose-600 dark:text-rose-400 mb-3">
            <Activity className="h-5 w-5" />
          </div>
          <h4 className="text-sm font-bold text-[#1E1E2D] dark:text-white group-hover:text-rose-600 dark:group-hover:text-rose-400 transition-colors">
            Live Incident Forensics
          </h4>
          <p className="text-xs font-medium text-[#8A8FA3] dark:text-[#9CA3AF] mt-1">
            Search, filter, and inspect passive telemetry streams with zero payload decryption.
          </p>
        </Link>

        <Link
          href="/analyst"
          className="group rounded-2xl border border-[#E5E5F0] dark:border-white/5 bg-white dark:bg-[#26282E] p-5 shadow-saas-light dark:shadow-saas-dark hover:-translate-y-0.5 transition-all cursor-pointer"
        >
          <div className="flex h-10 w-10 items-center justify-center rounded-full bg-violet-50 dark:bg-violet-500/15 text-violet-600 dark:text-violet-400 mb-3">
            <Sparkles className="h-5 w-5" />
          </div>
          <h4 className="text-sm font-bold text-[#1E1E2D] dark:text-white group-hover:text-violet-600 dark:group-hover:text-violet-400 transition-colors">
            Cognitive AI Analyst
          </h4>
          <p className="text-xs font-medium text-[#8A8FA3] dark:text-[#9CA3AF] mt-1">
            Query Google Gemini for automated MITRE ATT&CK correlation and non-intrusive actions.
          </p>
        </Link>

        <Link
          href="/enclave"
          className="group rounded-2xl border border-[#E5E5F0] dark:border-white/5 bg-white dark:bg-[#26282E] p-5 shadow-saas-light dark:shadow-saas-dark hover:-translate-y-0.5 transition-all cursor-pointer"
        >
          <div className="flex h-10 w-10 items-center justify-center rounded-full bg-emerald-50 dark:bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 mb-3">
            <Sliders className="h-5 w-5" />
          </div>
          <h4 className="text-sm font-bold text-[#1E1E2D] dark:text-white group-hover:text-emerald-600 dark:group-hover:text-emerald-400 transition-colors">
            Enclave Health & Diode
          </h4>
          <p className="text-xs font-medium text-[#8A8FA3] dark:text-[#9CA3AF] mt-1">
            Verify hardware zero return path and inject calibrated synthetic threat bursts.
          </p>
        </Link>
      </div>

      {/* 5. Footer info banner */}
      <footer className="pt-4 border-t border-[#E5E5F0] dark:border-white/5 flex flex-col sm:flex-row items-center justify-between text-xs font-medium text-[#8A8FA3] dark:text-[#9CA3AF] gap-3">
        <div className="flex items-center gap-2">
          <ShieldCheck className="h-4 w-4 text-emerald-600 dark:text-emerald-400" />
          <span>UNIDIRECTIONAL PASSIVE MIRRORING ACTIVE &bull; HARDWARE RX AIR-GAP EMULATED</span>
        </div>
        <div>
          STRATA Security Enclave &bull; Strictly Zero Return Path &bull; Metadata Inspection SLA &lt; 50ms
        </div>
      </footer>
    </div>
  );
}
