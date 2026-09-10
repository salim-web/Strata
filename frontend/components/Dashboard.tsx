"use client";

import React, { useState, useEffect } from 'react';
import { ThreatMetrics, TrafficDataPoint } from '../lib/mockData';
import { ApiResponseMeta } from '../lib/api';
import { TrafficChart } from './TrafficChart';
import { ThreatFeed } from './ThreatFeed';
import { BlockedIPsTable } from './BlockedIPsTable';
import {
  Shield,
  Activity,
  Lock,
  CheckCircle2,
  HelpCircle,
  RefreshCw,
  Server,
  Zap,
  Layers,
  Globe,
  Cpu,
  Sliders,
  Sun,
  Moon,
} from 'lucide-react';

interface DashboardProps {
  metrics: ThreatMetrics;
  meta?: ApiResponseMeta;
  trafficHistory?: TrafficDataPoint[];
  loading?: boolean;
  samplingRate?: number;
  theme?: 'dark' | 'light';
  onRefresh?: () => void;
  onUnblockIp?: (ip: string) => void;
  onSamplingRateChange?: (newRate: number) => void;
  onTriggerSimulatedAttack?: () => void;
  onToggleTheme?: () => void;
}

const SAMPLING_OPTIONS = [
  { rate: 0.25, label: "25%", subtitle: "Max Efficiency", computeSaved: "75% Compute Saved" },
  { rate: 0.50, label: "50%", subtitle: "Balanced Mode", computeSaved: "50% Compute Saved" },
  { rate: 0.75, label: "75%", subtitle: "High Inspection", computeSaved: "25% Compute Saved" },
  { rate: 1.0, label: "100%", subtitle: "Full Inspection", computeSaved: "100% Monitored" },
];

export const Dashboard: React.FC<DashboardProps> = ({
  metrics,
  meta,
  trafficHistory = [],
  loading = false,
  samplingRate,
  theme = 'dark',
  onRefresh,
  onUnblockIp,
  onSamplingRateChange,
  onToggleTheme,
}) => {
  const [lastUpdatedTime, setLastUpdatedTime] = useState<string>('');
  const [activeTooltip, setActiveTooltip] = useState<string | null>(null);
  const [isMounted, setIsMounted] = useState<boolean>(false);

  const isLight = theme === 'light';

  useEffect(() => {
    setIsMounted(true);
    const updateTime = () => {
      setLastUpdatedTime(
        new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
      );
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  const currentSamplingRate = samplingRate !== undefined ? samplingRate : (metrics.sampling_rate ?? 1.0);
  const isLive = meta ? !meta.isFallback : false;

  // Real-time Dynamic Protection Status
  const anomalyScore = metrics.current_anomaly_score ?? 0.12;
  const isMitigating = anomalyScore > 0.65;
  const isElevated = anomalyScore > 0.35 && !isMitigating;

  let protectionStatus = {
    label: "Protected",
    dotColor: "bg-emerald-400",
    bgBorder: isLight ? "bg-emerald-50 border-emerald-300 text-emerald-700" : "bg-emerald-500/10 border-emerald-500/20 text-emerald-400"
  };

  if (!isLive) {
    protectionStatus = {
      label: "Simulation",
      dotColor: "bg-amber-400",
      bgBorder: isLight ? "bg-amber-50 border-amber-300 text-amber-700" : "bg-amber-500/10 border-amber-500/20 text-amber-400"
    };
  } else if (isMitigating) {
    protectionStatus = {
      label: "Mitigating Attack",
      dotColor: "bg-rose-400",
      bgBorder: isLight ? "bg-rose-50 border-rose-300 text-rose-700 shadow-[0_0_12px_rgba(244,63,94,0.3)]" : "bg-rose-500/10 border-rose-500/30 text-rose-400 shadow-[0_0_12px_rgba(244,63,94,0.2)]"
    };
  } else if (isElevated) {
    protectionStatus = {
      label: "Shield Active",
      dotColor: "bg-cyan-400",
      bgBorder: isLight ? "bg-cyan-50 border-cyan-300 text-cyan-700" : "bg-cyan-500/10 border-cyan-500/20 text-cyan-400"
    };
  }

  const securityControls = [
    {
      name: "Zero-Trust",
      status: "Enforced",
      icon: <Layers className="w-4 h-4 text-cyan-400" />,
      hint: "Every request is verified before access is granted.",
    },
    {
      name: "WAF",
      status: "Active",
      icon: <Globe className="w-4 h-4 text-emerald-400" />,
      hint: "Filters malicious web requests before they reach the application.",
    },
    {
      name: "AI Threat Detection",
      status: "Monitoring",
      icon: <Cpu className="w-4 h-4 text-indigo-400" />,
      hint: "Identifies unusual traffic patterns and potential attacks.",
    },
    {
      name: "Rate Limiting",
      status: "Enabled",
      icon: <Sliders className="w-4 h-4 text-teal-400" />,
      hint: "Controls excessive requests to reduce abuse.",
    },
  ];

  return (
    <div className={`${isLight ? 'bg-slate-100 text-slate-900' : 'bg-[#080b11] text-slate-100'} p-4 sm:p-6 lg:p-8 ambient-bg selection:bg-cyan-500 selection:text-slate-950 h-full transition-colors`}>
      <div className="max-w-7xl mx-auto space-y-6">

        {/* ========================================================= */}
        {/* 1. HEADER */}
        {/* ========================================================= */}
        <header className={`flex flex-col md:flex-row md:items-center justify-between gap-4 pb-5 border-b ${isLight ? 'border-slate-300' : 'border-white/[0.06]'}`}>
          {/* Logo & Title */}
          <div className="flex items-center gap-3.5">
            <div className="p-2.5 bg-cyan-950/40 border border-cyan-500/20 rounded-xl text-cyan-400">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <h1 className={`text-xl font-bold tracking-tight ${isLight ? 'text-slate-900' : 'text-white'}`}>
                Strata
              </h1>
              <p className={`text-xs ${isLight ? 'text-slate-500' : 'text-slate-400'} mt-0.5`}>
                Real-time threat visibility
              </p>
            </div>
          </div>

          {/* System Status Indicator & Metadata */}
          <div className="flex flex-wrap items-center gap-3 text-xs">
            {/* Theme Toggle Button */}
            {onToggleTheme && (
              <button
                onClick={onToggleTheme}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-medium transition ${
                  isLight
                    ? 'bg-white hover:bg-slate-200 border-slate-300 text-slate-800 shadow-sm'
                    : 'bg-slate-900/60 hover:bg-slate-800 border-white/[0.06] text-slate-200'
                }`}
                title="Toggle Dark / Light Theme"
              >
                {isLight ? (
                  <>
                    <Moon className="w-3.5 h-3.5 text-indigo-600" />
                    <span>Dark</span>
                  </>
                ) : (
                  <>
                    <Sun className="w-3.5 h-3.5 text-amber-400" />
                    <span>Light</span>
                  </>
                )}
              </button>
            )}

            {/* Dynamic Real-time Protection Status Pill */}
            <div className={`flex items-center gap-2 px-3 py-1.5 border rounded-full transition-all duration-300 ${protectionStatus.bgBorder}`}>
              <span className={`w-2 h-2 rounded-full ${protectionStatus.dotColor} inline-block animate-pulse`}></span>
              <span className="font-semibold text-xs tracking-wide">{protectionStatus.label}</span>
            </div>

            {/* Dynamic Real-time Backend connection indicator */}
            <div className={`flex items-center gap-1.5 px-3 py-1.5 border rounded-lg font-mono text-[11px] transition-all duration-300 ${
              isLive 
                ? (isLight ? 'bg-emerald-50 border-emerald-300 text-emerald-800' : 'bg-emerald-950/40 border-emerald-500/30 text-emerald-300')
                : (isLight ? 'bg-amber-50 border-amber-300 text-amber-800' : 'bg-amber-950/40 border-amber-500/30 text-amber-300')
            }`}>
              <Server className={`w-3.5 h-3.5 ${isLive ? 'text-emerald-400' : 'text-amber-400'}`} />
              <span>
                {isLive ? `Backend: Live (${meta?.latencyMs ?? 1}ms)` : 'Backend: Fallback (Sim)'}
              </span>
            </div>

            {/* Last updated timestamp */}
            <div className={`font-mono text-[11px] px-2.5 py-1.5 rounded-lg border ${
              isLight ? 'bg-white border-slate-200 text-slate-600' : 'bg-slate-950/60 border-white/[0.06] text-slate-400'
            }`}>
              Last updated:{' '}
              <span suppressHydrationWarning>
                {isMounted && lastUpdatedTime ? lastUpdatedTime : 'Just now'}
              </span>
            </div>

            {/* Refresh button */}
            {onRefresh && (
              <button
                onClick={onRefresh}
                className={`p-1.5 border rounded-lg transition ${
                  isLight ? 'bg-white hover:bg-slate-200 border-slate-300 text-slate-700' : 'bg-slate-900/60 hover:bg-slate-800 border-white/[0.06] text-slate-400 hover:text-slate-200'
                }`}
                title="Poll now"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              </button>
            )}
          </div>
        </header>

        {/* ========================================================= */}
        {/* SUBTLE ENTERPRISE THREAT MITIGATION TICKER (Feature 5) */}
        {/* ========================================================= */}
        <div className={`flex items-center justify-between gap-3 px-4 py-2.5 rounded-xl text-xs shadow-sm border ${
          isLight ? 'bg-white border-slate-200 text-slate-800' : 'bg-slate-950/70 border-white/[0.06] text-slate-300'
        }`}>
          <div className="flex items-center gap-2.5">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-400"></span>
            </span>
            <span className={`font-mono uppercase tracking-wider text-[10px] font-semibold ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>Enterprise Defense Ticker:</span>
            <span className={`font-medium ${isLight ? 'text-slate-800' : 'text-slate-200'}`}>
              <strong className="text-cyan-600 font-mono font-bold">{metrics.blocked_ips_count} malicious IPs</strong> quarantined seamlessly in background • Zero user friction
            </span>
          </div>
          <div className={`hidden sm:flex items-center gap-2 text-[11px] font-mono ${isLight ? 'text-slate-500' : 'text-slate-500'}`}>
            <span>Isolation Rate: 100%</span>
          </div>
        </div>

        {/* ========================================================= */}
        {/* 2. KPI SECTION (4 Compact Cards with Circular Icons & Gauge) */}
        {/* ========================================================= */}
        <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Card 1: Total Requests */}
          <div className={`glass-panel p-4 shadow-sm transition-all flex items-center justify-between ${
            isLight ? 'bg-white border-slate-200 hover:border-slate-300' : 'hover:border-white/[0.12]'
          }`}>
            <div>
              <div className={`text-[11px] font-semibold uppercase tracking-wider mb-1 ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
                Total Requests
              </div>
              <div className={`text-2xl font-bold font-mono tracking-tight ${isLight ? 'text-slate-900' : 'text-slate-100'}`}>
                {metrics.total_requests.toLocaleString()}
              </div>
              <div className={`mt-1 text-[11px] ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
                Processed real time
              </div>
            </div>

            <div className={`w-10 h-10 rounded-full flex items-center justify-center shrink-0 ml-3 ${
              isLight ? 'bg-cyan-50 border border-cyan-200 text-cyan-600' : 'bg-cyan-950/50 border border-cyan-500/20 text-cyan-400'
            }`}>
              <Activity className="w-4 h-4" />
            </div>
          </div>

          {/* Card 2: Threats Blocked */}
          <div className={`glass-panel p-4 shadow-sm transition-all flex items-center justify-between ${
            isLight ? 'bg-white border-slate-200 hover:border-slate-300' : 'hover:border-white/[0.12]'
          }`}>
            <div>
              <div className={`text-[11px] font-semibold uppercase tracking-wider mb-1 ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
                Threats Blocked
              </div>
              <div className={`text-2xl font-bold font-mono tracking-tight ${isLight ? 'text-slate-900' : 'text-slate-100'}`}>
                {metrics.blocked_ips_count}
              </div>
              <div className={`mt-1 text-[11px] ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
                Malicious sources
              </div>
            </div>

            <div className={`w-10 h-10 rounded-full flex items-center justify-center shrink-0 ml-3 ${
              isLight ? 'bg-rose-50 border border-rose-200 text-rose-600' : 'bg-rose-950/50 border border-rose-500/20 text-rose-400'
            }`}>
              <Lock className="w-4 h-4" />
            </div>
          </div>

          {/* Card 3: ML Anomaly Score Gauge (Feature 3) */}
          {(() => {
            const latestAnomaly = trafficHistory.length > 0 ? trafficHistory[trafficHistory.length - 1].anomalyScore : 0.15;
            const isHigh = latestAnomaly > 0.6;
            const isMed = latestAnomaly > 0.35 && !isHigh;
            return (
              <div className={`glass-panel p-4 shadow-sm transition-all flex items-center justify-between ${
                isLight ? 'bg-white border-slate-200 hover:border-slate-300' : 'hover:border-white/[0.12]'
              }`}>
                <div>
                  <div className={`text-[11px] font-semibold uppercase tracking-wider mb-1 ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
                    ML Anomaly Index
                  </div>
                  <div className={`text-2xl font-bold font-mono tracking-tight ${
                    isHigh ? (isLight ? 'text-rose-600' : 'text-rose-400') : isMed ? (isLight ? 'text-amber-600' : 'text-amber-400') : (isLight ? 'text-cyan-600' : 'text-cyan-400')
                  }`}>
                    {latestAnomaly.toFixed(2)}
                  </div>
                  <div className={`mt-1 text-[11px] ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
                    {isHigh ? 'CRITICAL SPIKE' : isMed ? 'SUSPICIOUS' : 'NORMAL PATTERN'}
                  </div>
                </div>

                <div className={`w-10 h-10 rounded-full border flex items-center justify-center shrink-0 ml-3 ${
                  isHigh 
                    ? (isLight ? 'bg-rose-50 border-rose-200 text-rose-600' : 'bg-rose-950/50 border-rose-500/40 text-rose-400')
                    : isMed 
                    ? (isLight ? 'bg-amber-50 border-amber-200 text-amber-600' : 'bg-amber-950/50 border-amber-500/40 text-amber-400')
                    : (isLight ? 'bg-cyan-50 border-cyan-200 text-cyan-600' : 'bg-cyan-950/50 border-cyan-500/20 text-cyan-400')
                }`}>
                  <Cpu className="w-4 h-4" />
                </div>
              </div>
            );
          })()}

          {/* Card 4: System Status */}
          <div className={`glass-panel p-4 shadow-sm transition-all flex items-center justify-between ${
            isLight ? 'bg-white border-slate-200 hover:border-slate-300' : 'hover:border-white/[0.12]'
          }`}>
            <div>
              <div className={`text-[11px] font-semibold uppercase tracking-wider mb-1 ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
                System Status
              </div>
              <div className="text-2xl font-bold text-emerald-500 tracking-tight">
                Protected
              </div>
              <div className={`mt-1 text-[11px] ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
                Zero-Trust Active
              </div>
            </div>

            <div className={`w-10 h-10 rounded-full flex items-center justify-center shrink-0 ml-3 ${
              isLight ? 'bg-emerald-50 border border-emerald-200 text-emerald-600' : 'bg-emerald-950/50 border border-emerald-500/20 text-emerald-400'
            }`}>
              <CheckCircle2 className="w-4 h-4" />
            </div>
          </div>
        </section>

        {/* ========================================================= */}
        {/* EXECUTIVE AI THREAT CARD */}
        {/* ========================================================= */}
        {metrics.recent_alerts && metrics.recent_alerts.length > 0 && metrics.recent_alerts[0].severity === 'HIGH' && (
          <section className={`relative overflow-hidden rounded-xl border p-1 ${
            isLight ? 'bg-indigo-50/60 border-indigo-200 shadow-sm' : 'bg-slate-900/40 border-indigo-500/30'
          }`}>
            <div className="absolute inset-0 bg-gradient-to-r from-indigo-500/10 via-purple-500/10 to-cyan-500/10 blur-xl"></div>
            <div className={`relative backdrop-blur-sm p-5 rounded-lg border flex flex-col gap-3 ${
              isLight ? 'bg-white/90 border-indigo-100' : 'bg-slate-950/80 border-white/5'
            }`}>
              <div className="flex items-center gap-2">
                <div className={`p-1.5 rounded-md ${isLight ? 'bg-indigo-100 text-indigo-700' : 'bg-indigo-500/20 text-indigo-400'}`}>
                  <Zap className="w-4 h-4" />
                </div>
                <h3 className={`text-sm font-bold tracking-wide uppercase ${isLight ? 'text-indigo-900' : 'text-indigo-300'}`}>AI Threat Analysis (Local Scikit-Learn ML)</h3>
                <span className="ml-auto flex h-2 w-2 relative">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-indigo-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-indigo-500"></span>
                </span>
              </div>
              <p className={`text-sm leading-relaxed font-mono ${isLight ? 'text-slate-800' : 'text-slate-300'}`}>
                {metrics.recent_alerts[0].message}
              </p>
            </div>
          </section>
        )}

        {/* ========================================================= */}
        {/* 2.5. API TRAFFIC SAMPLING OPTIONS */}
        {/* ========================================================= */}
        <section className={`glass-panel p-5 shadow-sm ${isLight ? 'bg-white border-slate-200' : ''}`}>
          <div className={`flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3.5 border-b ${
            isLight ? 'border-slate-200' : 'border-white/[0.06]'
          }`}>
            <div className="flex items-center gap-2.5">
              <div className={`p-2 rounded-lg ${isLight ? 'bg-indigo-50 border border-indigo-200 text-indigo-600' : 'bg-indigo-950/50 border border-indigo-500/20 text-indigo-400'}`}>
                <Sliders className="w-4 h-4" />
              </div>
              <div>
                <h3 className={`text-sm font-semibold tracking-tight ${isLight ? 'text-slate-900' : 'text-slate-100'}`}>
                  API Traffic Sampling Rate
                </h3>
                <p className={`text-xs mt-0.5 ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
                  Choose the ML anomaly detection sampling of the API
                </p>
              </div>
            </div>

            {/* Current Active Badge */}
            <div className="flex items-center gap-2">
              <span className={`text-[11px] font-mono ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>Active Rate:</span>
              <span className={`px-2.5 py-1 rounded-full text-xs font-mono font-bold border ${
                isLight ? 'bg-cyan-50 text-cyan-700 border-cyan-300' : 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/30'
              }`}>
                {Math.round(currentSamplingRate * 100)}% Sampling
              </span>
            </div>
          </div>

          {/* Sampling Option Buttons: 25%, 50%, 75%, 100% */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-4">
            {SAMPLING_OPTIONS.map((opt) => {
              const isSelected = Math.round(currentSamplingRate * 100) === Math.round(opt.rate * 100);
              return (
                <button
                  key={opt.label}
                  type="button"
                  onClick={() => onSamplingRateChange && onSamplingRateChange(opt.rate)}
                  className={`p-3.5 rounded-xl border text-left transition-all duration-200 cursor-pointer ${
                    isSelected
                      ? (isLight
                          ? 'bg-cyan-50/90 border-cyan-500 shadow-md ring-2 ring-cyan-500/40 text-slate-900'
                          : 'bg-gradient-to-br from-cyan-950/80 via-slate-900 to-slate-900 border-cyan-400/70 shadow-[0_0_16px_rgba(6,182,212,0.25)] text-white ring-1 ring-cyan-400/50')
                      : (isLight
                          ? 'bg-slate-50 hover:bg-slate-100/80 border-slate-200 text-slate-700'
                          : 'bg-slate-950/60 hover:bg-slate-900/80 border-white/[0.08] hover:border-white/[0.18] text-slate-300')
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className={`text-lg font-bold font-mono tracking-tight ${
                      isLight ? (isSelected ? 'text-cyan-950' : 'text-slate-900') : 'text-white'
                    }`}>
                      {opt.label}
                    </span>
                    {isSelected && (
                      <span className="flex h-2.5 w-2.5 relative">
                        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
                        <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-cyan-500"></span>
                      </span>
                    )}
                  </div>
                  <div className={`text-xs font-semibold mt-1.5 ${isLight ? 'text-slate-700' : 'text-slate-200'}`}>
                    {opt.subtitle}
                  </div>
                  <div className={`text-[10px] font-mono mt-0.5 ${
                    isSelected 
                      ? (isLight ? 'text-cyan-800 font-bold' : 'text-cyan-300 font-semibold')
                      : (isLight ? 'text-slate-500' : 'text-slate-400')
                  }`}>
                    {opt.computeSaved}
                  </div>
                </button>
              );
            })}
          </div>
        </section>

        {/* ========================================================= */}
        {/* 3. TRAFFIC SECTION */}
        {/* ========================================================= */}
        <section>
          <TrafficChart data={trafficHistory} theme={theme} />
        </section>

        {/* ========================================================= */}
        {/* 4 & 5. RECENT THREATS & BLOCKED SOURCES */}
        {/* ========================================================= */}
        <section className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Recent Threats Feed */}
          <ThreatFeed alerts={metrics.recent_alerts} theme={theme} />

          {/* Blocked Sources Table */}
          <BlockedIPsTable
            blockedIps={metrics.blocked_ips_list}
            alerts={metrics.recent_alerts}
            onUnblock={onUnblockIp}
            theme={theme}
          />
        </section>

        {/* ========================================================= */}
        {/* 6 & 7. SECURITY CONTROLS & CYBERSECURITY HINTS */}
        {/* ========================================================= */}
        <section className="glass-panel p-5 shadow-sm">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                Security Controls
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Active automated defense layers
              </p>
            </div>

            {/* Control Badges with Tooltips */}
            <div className="flex flex-wrap items-center gap-2.5 sm:gap-3">
              {securityControls.map((control) => (
                <div
                  key={control.name}
                  className="relative group flex items-center gap-2 px-3 py-1.5 bg-slate-950/50 border border-white/[0.06] rounded-xl text-xs"
                >
                  <span className="text-emerald-400 font-bold">✓</span>
                  {control.icon}
                  <span className="text-slate-200 font-medium">{control.name}</span>
                  <span className="text-[10px] text-slate-400 font-mono">({control.status})</span>

                  {/* Info Icon with Accessible Tooltip */}
                  <button
                    type="button"
                    onClick={() => setActiveTooltip(activeTooltip === control.name ? null : control.name)}
                    className="text-slate-500 hover:text-slate-300 ml-0.5 focus:outline-none"
                    aria-label={`Info for ${control.name}`}
                  >
                    <HelpCircle className="w-3.5 h-3.5" />
                  </button>

                  {/* Tooltip Card */}
                  <div
                    className={`absolute bottom-full mb-2 left-1/2 -translate-x-1/2 w-52 p-2.5 bg-slate-900 text-slate-200 text-[11px] rounded-xl shadow-2xl border border-slate-700 pointer-events-none transition-all z-20 leading-relaxed ${
                      activeTooltip === control.name ? 'opacity-100 visible' : 'opacity-0 invisible group-hover:opacity-100 group-hover:visible'
                    }`}
                  >
                    {control.hint}
                    <div className="absolute top-full left-1/2 -translate-x-1/2 border-4 border-transparent border-t-slate-900"></div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

      </div>
    </div>
  );
};
