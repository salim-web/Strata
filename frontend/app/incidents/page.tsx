"use client";

import React, { useState } from 'react';
import { useRouter } from 'next/navigation';
import { StreamingIncidentFeed } from '../../components/StreamingIncidentFeed';
import { useEnclave } from '../../context/EnclaveContext';
import {
  AlertCircle,
  Download,
  Filter,
  Sparkles,
  Layers,
  Database,
  Check,
  Clock,
} from 'lucide-react';
import { StandardizedAlert } from '../../lib/mockData';

export default function IncidentsPage() {
  const router = useRouter();
  const { alerts, setSelectedAlert, generateAssessmentForAlert } = useEnclave();
  const [copiedExport, setCopiedExport] = useState<boolean>(false);

  const handleSelectForAnalysis = (alert: StandardizedAlert) => {
    setSelectedAlert(alert);
    generateAssessmentForAlert(alert);
    router.push('/analyst');
  };

  const handleExportJSON = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(alerts, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `strata_incidents_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const handleExportCSV = () => {
    const headers = ['Timestamp', 'Flow_ID', 'Threat_Class', 'Confidence_Score', 'Severity', 'Evidence'];
    const rows = alerts.map((a) => [
      a.timestamp,
      `"${a.flow_id}"`,
      a.threat_class,
      a.confidence_score,
      a.severity,
      `"${JSON.stringify(a.evidence).replace(/"/g, '""')}"`,
    ]);

    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map((e) => e.join(','))].join('\n');
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', encodeURI(csvContent));
    downloadAnchor.setAttribute('download', `strata_incidents_${Date.now()}.csv`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="space-y-6">
      {/* Top Banner with Statistics and Export Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 rounded-3xl border border-[#E5E5F0] dark:border-white/5 bg-white dark:bg-[#26282E] p-6 shadow-saas-light dark:shadow-saas-dark">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="flex h-7 w-7 items-center justify-center rounded-full bg-rose-50 dark:bg-rose-500/15 text-rose-600 dark:text-rose-400">
              <AlertCircle className="h-4 w-4" />
            </span>
            <h2 className="text-lg sm:text-xl font-extrabold tracking-tight text-[#1E1E2D] dark:text-white">
              Live Incident Feed & Forensics
            </h2>
          </div>
          <p className="text-xs font-medium text-[#8A8FA3] dark:text-[#9CA3AF]">
            Real-time passive telemetry events parsed into the standardized schema with bounded latency SLA.
          </p>
        </div>

        {/* Export Buttons */}
        <div className="flex items-center gap-2.5 shrink-0">
          <button
            onClick={handleExportCSV}
            className="inline-flex items-center gap-1.5 rounded-full border border-[#E5E5F0] dark:border-white/10 bg-[#F8F8FC] dark:bg-[#1E1F24] px-4 py-2 text-xs font-semibold text-[#1E1E2D] dark:text-[#F3F4F6] hover:border-indigo-300 dark:hover:border-white/20 transition-all cursor-pointer shadow-sm"
          >
            <Download className="h-3.5 w-3.5" />
            <span>Export CSV</span>
          </button>

          <button
            onClick={handleExportJSON}
            className="inline-flex items-center gap-1.5 rounded-full bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 text-xs font-semibold shadow-sm transition-all cursor-pointer"
          >
            <Download className="h-3.5 w-3.5" />
            <span>Export JSON</span>
          </button>
        </div>
      </div>

      {/* Incident Summary Metric Strips */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="rounded-2xl border border-[#E5E5F0] dark:border-white/5 bg-white dark:bg-[#26282E] p-4 shadow-saas-light dark:shadow-saas-dark">
          <span className="text-[10px] uppercase font-bold text-[#8A8FA3] dark:text-[#9CA3AF] block mb-1">
            Total Ingested Events
          </span>
          <span className="text-xl sm:text-2xl font-extrabold text-[#1E1E2D] dark:text-white">
            {alerts.length}
          </span>
        </div>

        <div className="rounded-2xl border border-[#E5E5F0] dark:border-white/5 bg-white dark:bg-[#26282E] p-4 shadow-saas-light dark:shadow-saas-dark">
          <span className="text-[10px] uppercase font-bold text-rose-600 dark:text-rose-400 block mb-1">
            Critical Alerts
          </span>
          <span className="text-xl sm:text-2xl font-extrabold text-rose-600 dark:text-rose-400">
            {alerts.filter((a) => a.severity === 'CRITICAL').length}
          </span>
        </div>

        <div className="rounded-2xl border border-[#E5E5F0] dark:border-white/5 bg-white dark:bg-[#26282E] p-4 shadow-saas-light dark:shadow-saas-dark">
          <span className="text-[10px] uppercase font-bold text-orange-600 dark:text-orange-400 block mb-1">
            High Severity
          </span>
          <span className="text-xl sm:text-2xl font-extrabold text-orange-600 dark:text-orange-400">
            {alerts.filter((a) => a.severity === 'HIGH').length}
          </span>
        </div>

        <div className="rounded-2xl border border-[#E5E5F0] dark:border-white/5 bg-white dark:bg-[#26282E] p-4 shadow-saas-light dark:shadow-saas-dark">
          <span className="text-[10px] uppercase font-bold text-emerald-600 dark:text-emerald-400 block mb-1">
            Zero Return Path
          </span>
          <span className="text-xl sm:text-2xl font-extrabold text-emerald-600 dark:text-emerald-400">
            0 Blocked
          </span>
        </div>
      </div>

      {/* Main Full-Width Incident Feed Container */}
      <StreamingIncidentFeed
        alerts={alerts}
        onSelectAlertForAnalysis={handleSelectForAnalysis}
      />
    </div>
  );
}
