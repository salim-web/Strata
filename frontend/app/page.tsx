"use client";

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { Dashboard } from '../components/Dashboard';
import { AttackerConsole } from '../components/AttackerConsole';
import { fetchThreatMetrics, unblockIpOnBackend, updateSamplingConfig } from '../lib/api';
import {
  initialMockData,
  generateInitialTrafficHistory,
  TrafficDataPoint,
  ThreatMetrics,
  ThreatAlert,
  ApiResponseMeta,
} from '../lib/mockData';


export default function Home() {
  const [metrics, setMetrics] = useState<ThreatMetrics>(initialMockData);
  const [samplingRate, setSamplingRate] = useState<number>(1.0);
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');
  const [meta, setMeta] = useState<ApiResponseMeta>({
    isFallback: true,
    timestamp: "2026-08-28T18:45:00.000Z",
    source: 'mock_simulation',
    latencyMs: 12,
  });
  const [trafficHistory, setTrafficHistory] = useState<TrafficDataPoint[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const isPollingRef = useRef<boolean>(false);
  const lastTotalReqsRef = useRef<number | null>(null);
  const lastBlockedReqsRef = useRef<number | null>(null);

  // Initialize theme from localStorage and traffic history on first mount
  useEffect(() => {
    setTrafficHistory(generateInitialTrafficHistory(15));
    const savedTheme = (localStorage.getItem('strata_theme') || localStorage.getItem('nibdefender_theme')) as 'dark' | 'light';
    if (savedTheme) {
      setTheme(savedTheme);
    }
  }, []);

  const handleToggleTheme = useCallback(() => {
    setTheme((prev) => {
      const next = prev === 'dark' ? 'light' : 'dark';
      localStorage.setItem('strata_theme', next);
      return next;
    });
  }, []);

  // Poll function to fetch metrics every 1 second
  const pollData = useCallback(async (isManual = false) => {
    if (isPollingRef.current && !isManual) return;
    isPollingRef.current = true;
    if (isManual) setLoading(true);

    try {
      const response = await fetchThreatMetrics();
      // Extract IPs from recent alerts to ensure real-time blocked sources updates
      const alertIps: string[] = [];
      const ipRegex = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g;
      (response.data.recent_alerts || []).forEach((alert) => {
        const matches = alert.message.match(ipRegex);
        if (matches) {
          matches.forEach((ip) => {
            if (ip !== '127.0.0.1' && ip !== '0.0.0.0' && !alertIps.includes(ip)) {
              alertIps.push(ip);
            }
          });
        }
      });

      const mergedBlockedIps = Array.from(new Set([...alertIps, ...(response.data.blocked_ips_list || [])]));

      setMetrics({
        ...response.data,
        blocked_ips_list: mergedBlockedIps,
        blocked_ips_count: mergedBlockedIps.length,
      });
      setMeta(response.meta);

      const now = new Date();
      const timeStr = now.toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      });

      const currentTotal = response.data.total_requests;
      const currentBlocked = response.data.blocked_requests_count ?? response.data.blocked_ips_count;

      let reqPerSec = 0;
      let blockedPerSec = 0;

      if (lastTotalReqsRef.current !== null && currentTotal >= lastTotalReqsRef.current) {
        reqPerSec = currentTotal - lastTotalReqsRef.current;
      }

      if (lastBlockedReqsRef.current !== null && currentBlocked >= lastBlockedReqsRef.current) {
        blockedPerSec = currentBlocked - lastBlockedReqsRef.current;
      }

      lastTotalReqsRef.current = currentTotal;
      lastBlockedReqsRef.current = currentBlocked;

      // Ambient baseline if traffic is idle
      if (reqPerSec === 0) {
        reqPerSec = Math.floor(12 + Math.random() * 8);
      }

      const highAlerts = response.data.recent_alerts.filter((a) => a.severity === 'HIGH');
      if (blockedPerSec === 0 && highAlerts.length > 0) {
        blockedPerSec = Math.random() > 0.5 ? Math.floor(Math.random() * 3) + 1 : 0;
      }

      let anomalyIndex = response.data.current_anomaly_score;
      if (anomalyIndex === undefined || isNaN(anomalyIndex)) {
        anomalyIndex = parseFloat((0.12 + (blockedPerSec > 5 ? 0.75 : 0)).toFixed(2));
      }

      setTrafficHistory((prev) => {
        const updated = [
          ...prev,
          {
            time: timeStr,
            requests: reqPerSec,
            blocked: blockedPerSec,
            anomalyScore: anomalyIndex,
          },
        ];
        // Keep sliding window of latest 15 points
        return updated.length > 15 ? updated.slice(updated.length - 15) : updated;
      });
    } catch (err) {
      console.error('Polling error in threat defender dashboard:', err);
    } finally {
      isPollingRef.current = false;
      if (isManual) setLoading(false);
    }
  }, []);

  // 1-second real-time polling effect
  useEffect(() => {
    // Initial fetch on mount
    pollData();

    // 1000ms polling interval
    const interval = setInterval(() => {
      pollData();
    }, 1000);

    return () => clearInterval(interval);
  }, [pollData]);

  // Handler for manual refresh
  const handleRefresh = useCallback(() => {
    pollData(true);
  }, [pollData]);

  // Handler for unblocking an IP from the dashboard
  const handleUnblockIp = useCallback(async (ipToUnblock: string) => {
    setMetrics((prev) => ({
      ...prev,
      blocked_ips_count: Math.max(0, prev.blocked_ips_count - 1),
      blocked_ips_list: prev.blocked_ips_list.filter((ip) => ip !== ipToUnblock),
    }));
    await unblockIpOnBackend(ipToUnblock);
  }, []);

  // Handler for changing API sampling rate
  const handleSamplingRateChange = useCallback(async (newRate: number) => {
    setSamplingRate(newRate);
    setMetrics((prev) => ({
      ...prev,
      sampling_rate: newRate,
      sampling_rate_pct: Math.round(newRate * 100),
      compute_saved_pct: Math.round((1.0 - newRate) * 100),
    }));
    await updateSamplingConfig(newRate);
  }, []);

  // Handler for triggering an immediate attack simulation spike
  const handleTriggerSimulatedAttack = useCallback(async () => {
    // Trigger real attacks against live backend if available
    // triggerLiveAttackApi('sqli');

    const randomIp = `185.220.${Math.floor(Math.random() * 200) + 10}.${Math.floor(Math.random() * 250) + 1}`;
    const spikeAlert: ThreatAlert = {
      id: `ALT-SIM-${Date.now().toString().slice(-4)}`,
      timestamp: new Date().toISOString(),
      severity: 'HIGH',
      message: `CRITICAL ATTACK SPIKE: Multi-threaded credential stuffing & SQLi detected from simulated botnet node ${randomIp}`,
    };

    setMetrics((prev) => ({
      ...prev,
      total_requests: prev.total_requests + 320,
      blocked_ips_count: prev.blocked_ips_count + 1,
      blocked_ips_list: [randomIp, ...prev.blocked_ips_list],
      recent_alerts: [spikeAlert, ...prev.recent_alerts.slice(0, 19)],
    }));

    // Inject spike to chart immediately
    const timeStr = new Date().toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });

    setTrafficHistory((prev) => [
      ...prev.slice(-14),
      {
        time: timeStr,
        requests: 180,
        blocked: 42,
        anomalyScore: 0.98,
      },
    ]);
  }, []);

  const isLight = theme === 'light';

  return (
    <div className={`flex flex-col lg:flex-row h-screen overflow-hidden transition-colors ${
      isLight ? 'bg-slate-100 text-slate-900 light-mode' : 'bg-[#080b11] text-slate-100'
    }`}>
      {/* Left Panel: Attacker Console (40%) */}
      <div className={`lg:w-[40%] h-1/2 lg:h-full p-4 lg:p-6 border-b lg:border-b-0 lg:border-r overflow-y-auto ${
        isLight ? 'border-slate-300 bg-slate-200/50' : 'border-white/[0.06] bg-[#080b11]'
      }`}>
        <AttackerConsole theme={theme} onToggleTheme={handleToggleTheme} />
      </div>

      {/* Right Panel: Defender CISO Dashboard (60%) */}
      <div className="lg:w-[60%] h-1/2 lg:h-full overflow-y-auto">
        <Dashboard
          metrics={metrics}
          meta={meta}
          trafficHistory={trafficHistory}
          loading={loading}
          samplingRate={samplingRate}
          theme={theme}
          onRefresh={handleRefresh}
          onUnblockIp={handleUnblockIp}
          onSamplingRateChange={handleSamplingRateChange}
          onTriggerSimulatedAttack={handleTriggerSimulatedAttack}
          onToggleTheme={handleToggleTheme}
        />
      </div>
    </div>
  );
}
