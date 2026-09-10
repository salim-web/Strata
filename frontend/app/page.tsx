"use client";

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { DiodeHeader } from '../components/DiodeHeader';
import { TelemetryKPIs } from '../components/TelemetryKPIs';
import { MultiThreatRadar } from '../components/MultiThreatRadar';
import { StreamingIncidentFeed } from '../components/StreamingIncidentFeed';
import { GeminiAnalystCard } from '../components/GeminiAnalystCard';
import {
  fetchDiodeStats,
  fetchStandardizedAlerts,
  requestGeminiAssessment,
  triggerThreatBurst,
} from '../lib/api';
import {
  EnclaveKPIs,
  ThreatRadarItem,
  StandardizedAlert,
  GeminiAssessment,
  initialKPIs,
  initialThreatRadar,
  initialStandardizedAlerts,
} from '../lib/mockData';
import { Radio, RefreshCw, Layers } from 'lucide-react';

export default function DiodeConsolePage() {
  const [kpis, setKpis] = useState<EnclaveKPIs>(initialKPIs);
  const [threatRadar, setThreatRadar] = useState<Record<string, ThreatRadarItem>>(initialThreatRadar);
  const [alerts, setAlerts] = useState<StandardizedAlert[]>(initialStandardizedAlerts);
  const [selectedAlert, setSelectedAlert] = useState<StandardizedAlert | null>(initialStandardizedAlerts[0]);
  const [assessment, setAssessment] = useState<GeminiAssessment | null>(null);
  const [analystLoading, setAnalystLoading] = useState<boolean>(false);
  const [lastSyncTime, setLastSyncTime] = useState<string>('');
  const [selectedThreatFilter, setSelectedThreatFilter] = useState<string | null>(null);

  const isPollingRef = useRef<boolean>(false);

  // Initial Assessment generation for the first alert on mount
  useEffect(() => {
    let isCancelled = false;

    async function loadInitialAssessment() {
      if (initialStandardizedAlerts.length > 0) {
        setAnalystLoading(true);
        const initialAssmt = await requestGeminiAssessment(initialStandardizedAlerts[0]);
        if (!isCancelled) {
          setAssessment(initialAssmt);
          setAnalystLoading(false);
        }
      }
    }

    loadInitialAssessment();
    return () => {
      isCancelled = true;
    };
  }, []);

  // Poll function for live passive stats & alerts every 1.5 seconds
  const pollEnclaveTelemetry = useCallback(async () => {
    if (isPollingRef.current) return;
    isPollingRef.current = true;

    try {
      const statsResponse = await fetchDiodeStats();
      const freshAlerts = await fetchStandardizedAlerts(50);

      setKpis(statsResponse.data.kpis);
      setThreatRadar(statsResponse.data.threat_radar);

      if (freshAlerts && freshAlerts.length > 0) {
        setAlerts(freshAlerts);
      }

      setLastSyncTime(
        new Date().toLocaleTimeString([], {
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
        })
      );
    } catch (err) {
      console.error('Passive enclave polling error:', err);
    } finally {
      isPollingRef.current = false;
    }
  }, []);

  // Polling Interval
  useEffect(() => {
    pollEnclaveTelemetry();
    const interval = setInterval(pollEnclaveTelemetry, 1500);
    return () => clearInterval(interval);
  }, [pollEnclaveTelemetry]);

  // Handler for selecting an alert to analyze with Gemini
  const handleSelectAlertForAnalysis = useCallback(async (alert: StandardizedAlert) => {
    setSelectedAlert(alert);
    setAnalystLoading(true);
    try {
      const assmt = await requestGeminiAssessment(alert);
      setAssessment(assmt);
    } catch (err) {
      console.error('Error generating assessment:', err);
    } finally {
      setAnalystLoading(false);
    }
  }, []);

  // Handler for refreshing assessment of current alert
  const handleRefreshCurrentAssessment = useCallback(async () => {
    if (selectedAlert) {
      setAnalystLoading(true);
      try {
        const assmt = await requestGeminiAssessment(selectedAlert);
        setAssessment(assmt);
      } catch (err) {
        console.error('Error refreshing assessment:', err);
      } finally {
        setAnalystLoading(false);
      }
    }
  }, [selectedAlert]);

  const [bursting, setBursting] = useState<boolean>(false);

  const handleInjectBurst = useCallback(async (threatClass: string) => {
    setBursting(true);
    try {
      await triggerThreatBurst(threatClass, 80);
      // Immediately trigger a poll
      setTimeout(() => pollEnclaveTelemetry(), 300);
    } catch (err) {
      console.error('Error injecting threat burst:', err);
    } finally {
      setBursting(false);
    }
  }, [pollEnclaveTelemetry]);

  // Filter alerts if a threat radar card was clicked
  const displayedAlerts = selectedThreatFilter
    ? alerts.filter((a) => a.threat_class === selectedThreatFilter)
    : alerts;

  return (
    <div className="min-h-screen bg-[#06090f] text-slate-100 selection:bg-cyan-500 selection:text-slate-950 font-sans flex flex-col">
      {/* 1. Header with glowing diode badge */}
      <DiodeHeader
        flowsPerSec={kpis.sustained_flows_per_sec}
        mbps={kpis.sustained_mbps}
        pipelineLatency={kpis.pipeline_latency_ms}
        lastUpdated={lastSyncTime || 'LIVE'}
        onInjectBurst={handleInjectBurst}
        bursting={bursting}
      />

      {/* Main Enclave Workspace */}
      <main className="flex-1 p-4 sm:p-6 lg:p-8 space-y-6 max-w-[1700px] mx-auto w-full">
        {/* 2. Telemetry KPIs Row (Flows/s, Mbps, Packets, SLA Latency) */}
        <TelemetryKPIs kpis={kpis} />

        {/* 3. Multi-Threat Radar (6 Threat Vector Breakdown Cards) */}
        <div className="relative">
          <MultiThreatRadar
            radar={threatRadar}
            selectedThreatClass={selectedThreatFilter}
            onSelectThreatClass={(threatClass) => {
              setSelectedThreatFilter((prev) => (prev === threatClass ? null : threatClass));
            }}
          />
          {selectedThreatFilter && (
            <div className="mt-2 flex items-center justify-between bg-cyan-950/30 border border-cyan-500/20 px-3 py-1.5 rounded-lg text-xs font-mono text-cyan-300">
              <span>Filtering Incident Feed by: <strong>{selectedThreatFilter}</strong></span>
              <button
                onClick={() => setSelectedThreatFilter(null)}
                className="text-slate-400 hover:text-white underline text-[11px]"
              >
                Clear Filter
              </button>
            </div>
          )}
        </div>

        {/* 4. Split-Screen Intelligence Deck: Feed (50%) + AI Analyst Card (50%) */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left: Streaming Incident Feed (7 cols on lg) */}
          <div className="lg:col-span-7">
            <StreamingIncidentFeed
              alerts={displayedAlerts}
              onSelectAlertForAnalysis={handleSelectAlertForAnalysis}
              selectedAlertFlowId={selectedAlert?.flow_id}
            />
          </div>

          {/* Right: AI Intelligence Analyst Card powered by Google Gemini (5 cols on lg) */}
          <div className="lg:col-span-5">
            <GeminiAnalystCard
              currentAlert={selectedAlert}
              assessment={assessment}
              loading={analystLoading}
              onRefreshAssessment={handleRefreshCurrentAssessment}
            />
          </div>
        </div>

        {/* Footer info banner */}
        <footer className="pt-4 border-t border-slate-900/80 flex flex-col sm:flex-row items-center justify-between text-[11px] font-mono text-slate-500 gap-2">
          <div className="flex items-center gap-2">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
            <span>UNIDIRECTIONAL PASSIVE MIRRORING ACTIVE &bull; HARDWARE RX AIR-GAP EMULATED</span>
          </div>
          <div>
            STRATA Security Enclave &bull; Strictly Zero Return Path &bull; Metadata Inspection SLA &lt; 50ms
          </div>
        </footer>
      </main>
    </div>
  );
}
