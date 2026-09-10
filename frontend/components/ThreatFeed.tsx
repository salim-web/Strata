"use client";

import React, { useState, useEffect, useMemo } from 'react';
import { ThreatAlert } from '../lib/mockData';
import { Search, Copy, Check, Clock } from 'lucide-react';

interface ThreatFeedProps {
  alerts: ThreatAlert[];
  theme?: 'dark' | 'light';
}

export const ThreatFeed: React.FC<ThreatFeedProps> = ({ alerts = [], theme = 'dark' }) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<'ALL' | 'HIGH' | 'MEDIUM' | 'LOW'>('ALL');
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [isMounted, setIsMounted] = useState(false);

  const isLight = theme === 'light';

  useEffect(() => {
    setIsMounted(true);
  }, []);

  const filteredAlerts = useMemo(() => {
    return alerts.filter((alert) => {
      const matchesSeverity = severityFilter === 'ALL' || alert.severity === severityFilter;
      const matchesSearch =
        searchQuery === '' ||
        alert.message.toLowerCase().includes(searchQuery.toLowerCase()) ||
        alert.id.toLowerCase().includes(searchQuery.toLowerCase());
      return matchesSeverity && matchesSearch;
    });
  }, [alerts, severityFilter, searchQuery]);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const getSeverityBadge = (severity: ThreatAlert['severity']) => {
    switch (severity) {
      case 'HIGH':
        return isLight 
          ? 'bg-rose-100 text-rose-700 border border-rose-300 font-bold'
          : 'bg-rose-500/10 text-rose-400 border border-rose-500/20';
      case 'MEDIUM':
        return isLight
          ? 'bg-amber-100 text-amber-800 border border-amber-300 font-bold'
          : 'bg-amber-500/10 text-amber-400 border border-amber-500/20';
      case 'LOW':
      default:
        return isLight
          ? 'bg-slate-200 text-slate-700 border border-slate-300 font-semibold'
          : 'bg-slate-800/80 text-slate-300 border border-slate-700/60';
    }
  };

  const formatTimestamp = (timestamp: string) => {
    if (!isMounted) {
      try {
        const d = new Date(timestamp);
        return d.toISOString().slice(11, 19);
      } catch {
        return '--:--:--';
      }
    }
    try {
      return new Date(timestamp).toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      });
    } catch {
      return timestamp;
    }
  };

  return (
    <div className={`glass-panel p-6 shadow-sm flex flex-col h-[500px] ${isLight ? 'bg-white border-slate-200' : ''}`}>
      {/* Header */}
      <div className={`flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3.5 border-b ${isLight ? 'border-slate-200' : 'border-white/[0.06]'}`}>
        <div>
          <h3 className={`text-base font-semibold tracking-tight ${isLight ? 'text-slate-900' : 'text-slate-100'}`}>
            Recent Threats
          </h3>
          <p className={`text-xs mt-0.5 ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
            {alerts.length} events logged in active window
          </p>
        </div>

        {/* Severity Filter */}
        <div className={`flex items-center gap-1 p-0.5 rounded-lg border text-xs ${
          isLight ? 'bg-slate-100 border-slate-200' : 'bg-slate-950/60 border-white/[0.06]'
        }`}>
          <button
            onClick={() => setSeverityFilter('ALL')}
            className={`px-2.5 py-1 rounded-md transition-colors text-xs ${
              severityFilter === 'ALL'
                ? (isLight ? 'bg-white text-slate-900 font-semibold shadow-sm' : 'bg-slate-800 text-slate-100 font-medium')
                : (isLight ? 'text-slate-600 hover:text-slate-900' : 'text-slate-400 hover:text-slate-200')
            }`}
          >
            All
          </button>
          <button
            onClick={() => setSeverityFilter('HIGH')}
            className={`px-2.5 py-1 rounded-md transition-colors text-xs ${
              severityFilter === 'HIGH'
                ? (isLight ? 'bg-rose-100 text-rose-800 font-bold border border-rose-300' : 'bg-rose-950/60 text-rose-300 font-medium border border-rose-800/40')
                : (isLight ? 'text-slate-600 hover:text-rose-700' : 'text-slate-400 hover:text-rose-400')
            }`}
          >
            High
          </button>
          <button
            onClick={() => setSeverityFilter('MEDIUM')}
            className={`px-2.5 py-1 rounded-md transition-colors text-xs ${
              severityFilter === 'MEDIUM'
                ? (isLight ? 'bg-amber-100 text-amber-800 font-bold border border-amber-300' : 'bg-amber-950/60 text-amber-300 font-medium border border-amber-800/40')
                : (isLight ? 'text-slate-600 hover:text-amber-700' : 'text-slate-400 hover:text-amber-400')
            }`}
          >
            Med
          </button>
          <button
            onClick={() => setSeverityFilter('LOW')}
            className={`px-2.5 py-1 rounded-md transition-colors text-xs ${
              severityFilter === 'LOW'
                ? (isLight ? 'bg-slate-200 text-slate-900 font-semibold' : 'bg-slate-800 text-slate-300 font-medium')
                : (isLight ? 'text-slate-600 hover:text-slate-900' : 'text-slate-400 hover:text-slate-200')
            }`}
          >
            Low
          </button>
        </div>
      </div>

      {/* Search Input */}
      <div className="relative my-3">
        <Search className={`w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 ${isLight ? 'text-slate-400' : 'text-slate-500'}`} />
        <input
          type="text"
          placeholder="Filter threats by keyword or IP..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className={`w-full pl-9 pr-3 py-1.5 rounded-lg text-xs transition focus:outline-none ${
            isLight
              ? 'bg-slate-50 border border-slate-300 text-slate-900 placeholder-slate-400 focus:border-cyan-500'
              : 'bg-slate-950/60 border border-white/[0.06] text-slate-200 placeholder-slate-500 focus:border-slate-700'
          }`}
        />
      </div>

      {/* Threat List Feed */}
      <div className="flex-1 overflow-y-auto pr-1 space-y-2 custom-scrollbar">
        {filteredAlerts.length === 0 ? (
          <div className={`flex items-center justify-center h-full text-xs font-mono ${isLight ? 'text-slate-400' : 'text-slate-500'}`}>
            No incidents found matching criteria.
          </div>
        ) : (
          filteredAlerts.map((alert) => {
            const timeStr = formatTimestamp(alert.timestamp);

            return (
              <div
                key={alert.id}
                className={`rounded-xl p-3.5 transition-all group border ${
                  isLight
                    ? 'bg-slate-50/90 border-slate-200 shadow-sm hover:border-slate-300 hover:bg-white'
                    : 'bg-slate-950/40 border-white/[0.04] hover:border-white/[0.09]'
                }`}
              >
                <div className="flex items-center justify-between gap-2 mb-1.5">
                  <div className="flex items-center gap-2">
                    <span
                      className={`px-2 py-0.5 rounded-full text-[10px] font-semibold tracking-wide uppercase ${getSeverityBadge(
                        alert.severity
                      )}`}
                    >
                      {alert.severity}
                    </span>
                    <span className={`font-mono text-[11px] ${isLight ? 'text-slate-500 font-medium' : 'text-slate-400'}`}>
                      {alert.id}
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    <div className={`flex items-center gap-1 text-[11px] font-mono ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
                      <Clock className="w-3 h-3 text-slate-400" />
                      <span suppressHydrationWarning>{timeStr}</span>
                    </div>

                    <button
                      onClick={() => handleCopy(alert.message, alert.id)}
                      className={`opacity-0 group-hover:opacity-100 p-1 rounded transition ${
                        isLight ? 'hover:bg-slate-200 text-slate-500 hover:text-slate-900' : 'hover:bg-slate-800 text-slate-400 hover:text-slate-200'
                      }`}
                      title="Copy threat message"
                    >
                      {copiedId === alert.id ? (
                        <Check className="w-3 h-3 text-emerald-500" />
                      ) : (
                        <Copy className="w-3 h-3" />
                      )}
                    </button>
                  </div>
                </div>

                <div className={`text-xs leading-relaxed font-normal ${isLight ? 'text-slate-800 font-medium' : 'text-slate-300'}`}>
                  {alert.message}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
