"use client";

import React, { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';
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

interface EnclaveContextType {
  theme: 'light' | 'dark';
  toggleTheme: () => void;
  kpis: EnclaveKPIs;
  threatRadar: Record<string, ThreatRadarItem>;
  alerts: StandardizedAlert[];
  selectedAlert: StandardizedAlert | null;
  setSelectedAlert: (alert: StandardizedAlert | null) => void;
  assessment: GeminiAssessment | null;
  analystLoading: boolean;
  lastSyncTime: string;
  bursting: boolean;
  triggerBurst: (threatClass: string, count?: number) => Promise<void>;
  generateAssessmentForAlert: (alert: StandardizedAlert) => Promise<void>;
  refreshCurrentAssessment: () => Promise<void>;
}

const EnclaveContext = createContext<EnclaveContextType | undefined>(undefined);

export const EnclaveProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [theme, setTheme] = useState<'light' | 'dark'>('dark');
  const [kpis, setKpis] = useState<EnclaveKPIs>(initialKPIs);
  const [threatRadar, setThreatRadar] = useState<Record<string, ThreatRadarItem>>(initialThreatRadar);
  const [alerts, setAlerts] = useState<StandardizedAlert[]>(initialStandardizedAlerts);
  const [selectedAlert, setSelectedAlert] = useState<StandardizedAlert | null>(initialStandardizedAlerts[0]);
  const [assessment, setAssessment] = useState<GeminiAssessment | null>(null);
  const [analystLoading, setAnalystLoading] = useState<boolean>(false);
  const [lastSyncTime, setLastSyncTime] = useState<string>('');
  const [bursting, setBursting] = useState<boolean>(false);

  const isPollingRef = useRef<boolean>(false);

  // Initialize theme from localStorage or system preference
  useEffect(() => {
    const savedTheme = localStorage.getItem('strata_theme') as 'light' | 'dark' | null;
    if (savedTheme) {
      setTheme(savedTheme);
      document.documentElement.classList.toggle('dark', savedTheme === 'dark');
    } else {
      const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      const initial = prefersDark ? 'dark' : 'light';
      setTheme(initial);
      document.documentElement.classList.toggle('dark', initial === 'dark');
    }
  }, []);

  const toggleTheme = useCallback(() => {
    setTheme((prev) => {
      const nextTheme = prev === 'dark' ? 'light' : 'dark';
      localStorage.setItem('strata_theme', nextTheme);
      document.documentElement.classList.toggle('dark', nextTheme === 'dark');
      return nextTheme;
    });
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

  // Initial Assessment generation for first alert on mount
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

  // Polling Interval
  useEffect(() => {
    pollEnclaveTelemetry();
    const interval = setInterval(pollEnclaveTelemetry, 1500);
    return () => clearInterval(interval);
  }, [pollEnclaveTelemetry]);

  // Generate assessment for a specific alert
  const generateAssessmentForAlert = useCallback(async (alert: StandardizedAlert) => {
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

  // Refresh current assessment
  const refreshCurrentAssessment = useCallback(async () => {
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

  // Trigger burst injection
  const triggerBurst = useCallback(
    async (threatClass: string, count: number = 80) => {
      setBursting(true);
      try {
        await triggerThreatBurst(threatClass, count);
        setTimeout(() => pollEnclaveTelemetry(), 300);
      } catch (err) {
        console.error('Error injecting threat burst:', err);
      } finally {
        setBursting(false);
      }
    },
    [pollEnclaveTelemetry]
  );

  return (
    <EnclaveContext.Provider
      value={{
        theme,
        toggleTheme,
        kpis,
        threatRadar,
        alerts,
        selectedAlert,
        setSelectedAlert,
        assessment,
        analystLoading,
        lastSyncTime,
        bursting,
        triggerBurst,
        generateAssessmentForAlert,
        refreshCurrentAssessment,
      }}
    >
      {children}
    </EnclaveContext.Provider>
  );
};

export const useEnclave = (): EnclaveContextType => {
  const context = useContext(EnclaveContext);
  if (!context) {
    throw new Error('useEnclave must be used within an EnclaveProvider');
  }
  return context;
};
