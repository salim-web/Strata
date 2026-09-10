"use client";

import React, { useState, useMemo, useEffect } from 'react';
import { Search, Copy, Check, ShieldCheck } from 'lucide-react';

import { ThreatAlert } from '../lib/mockData';

interface BlockedIPsTableProps {
  blockedIps: string[];
  alerts?: ThreatAlert[];
  onUnblock?: (ip: string) => void;
  theme?: 'dark' | 'light';
}

export const BlockedIPsTable: React.FC<BlockedIPsTableProps> = ({ blockedIps = [], alerts = [], onUnblock, theme = 'dark' }) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [copiedIp, setCopiedIp] = useState<string | null>(null);
  const [unblockedSet, setUnblockedSet] = useState<Set<string>>(new Set());
  const [manualIpInput, setManualIpInput] = useState('');
  const [feedbackMsg, setFeedbackMsg] = useState<string | null>(null);

  const isLight = theme === 'light';

  // 1-second real-time clock state to drive live relative time updates
  const [now, setNow] = useState<number>(Date.now());

  // Store first-seen timestamp (ms) for every blocked IP
  const firstSeenMapRef = React.useRef<Record<string, number>>({});

  useEffect(() => {
    const timer = setInterval(() => {
      setNow(Date.now());
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  // Update timestamps map whenever blockedIps or alerts change
  useEffect(() => {
    const currentTime = Date.now();
    blockedIps.forEach((ip, idx) => {
      if (!firstSeenMapRef.current[ip]) {
        // Find matching alert timestamp if available
        const matchingAlert = alerts.find((a) => a.message.includes(ip));
        if (matchingAlert && matchingAlert.timestamp) {
          const parsed = new Date(matchingAlert.timestamp).getTime();
          if (!isNaN(parsed)) {
            firstSeenMapRef.current[ip] = parsed;
            return;
          }
        }
        // Stagger initial pre-existing IPs so they don't all show the exact same millisecond
        const offsetMs = idx * 18000; // 18s stagger per initial IP
        firstSeenMapRef.current[ip] = Math.max(1000, currentTime - offsetMs);
      }
    });
  }, [blockedIps, alerts]);

  const getIpDetails = (ip: string) => {
    const matchingAlert = alerts.find((a) => a.message.includes(ip));
    
    let reason = "ML Threat Quarantined";
    if (matchingAlert) {
      const msg = matchingAlert.message;
      if (msg.includes("SQL") || msg.includes("sql")) {
        reason = "SQL Injection Vector";
      } else if (msg.includes("ISOLATION") || msg.includes("ANOMALY")) {
        reason = "IsolationForest Anomaly";
      } else if (msg.includes("rate limit") || msg.includes("DDoS") || msg.includes("Exhaustion")) {
        reason = "DDoS Rate Limit Breach";
      } else if (msg.includes("Honeypot") || msg.includes("probe")) {
        reason = "Honeypot Trap Violation";
      } else {
        reason = "Zero-Trust ML Quarantine";
      }
    } else {
      if (ip.startsWith("185.") || ip.startsWith("194.")) {
        reason = "SQL Injection Vector";
      } else if (ip.startsWith("45.") || ip.startsWith("91.")) {
        reason = "DDoS Rate Limit Breach";
      } else {
        reason = "ML Threat Quarantined";
      }
    }

    let ipTimeMs = firstSeenMapRef.current[ip];
    if (!ipTimeMs && matchingAlert && matchingAlert.timestamp) {
      const parsed = new Date(matchingAlert.timestamp).getTime();
      if (!isNaN(parsed)) ipTimeMs = parsed;
    }
    if (!ipTimeMs) {
      ipTimeMs = now;
      firstSeenMapRef.current[ip] = ipTimeMs;
    }

    const diffSec = Math.max(0, Math.floor((now - ipTimeMs) / 1000));
    let timeStr = "Just now";
    if (diffSec < 5) {
      timeStr = "Just now";
    } else if (diffSec < 60) {
      timeStr = `${diffSec}s ago`;
    } else if (diffSec < 3600) {
      timeStr = `${Math.floor(diffSec / 60)}m ago`;
    } else {
      timeStr = `${Math.floor(diffSec / 3600)}h ago`;
    }

    return { reason, time: timeStr };
  };

  const handleCopy = (ip: string) => {
    navigator.clipboard.writeText(ip);
    setCopiedIp(ip);
    setTimeout(() => setCopiedIp(null), 2000);
  };

  const handleUnblock = (ip: string) => {
    const cleanIp = ip.trim();
    if (!cleanIp) return;
    setUnblockedSet((prev) => new Set(prev).add(cleanIp));
    if (onUnblock) {
      onUnblock(cleanIp);
    }
  };

  const handleManualUnblockSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const cleanIp = manualIpInput.trim();
    if (!cleanIp) return;

    handleUnblock(cleanIp);
    setManualIpInput('');
    setFeedbackMsg(`IP ${cleanIp} unblocked successfully`);
    setTimeout(() => setFeedbackMsg(null), 3000);
  };

  const activeBlockedIps = useMemo(() => {
    const list = blockedIps.filter((ip) => !unblockedSet.has(ip));
    // Sort by first-seen timestamp descending so newly blocked sources appear at the top in real-time
    list.sort((a, b) => {
      const timeA = firstSeenMapRef.current[a] || 0;
      const timeB = firstSeenMapRef.current[b] || 0;
      return timeB - timeA;
    });
    return list;
  }, [blockedIps, unblockedSet, alerts]);

  const filteredIps = useMemo(() => {
    return activeBlockedIps.filter((ip) => ip.includes(searchQuery.trim()));
  }, [activeBlockedIps, searchQuery]);

  return (
    <div className={`glass-panel p-6 shadow-sm flex flex-col h-[500px] ${isLight ? 'bg-white border-slate-200' : ''}`}>
      {/* Header */}
      <div className={`flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3.5 border-b ${isLight ? 'border-slate-200' : 'border-white/[0.06]'}`}>
        <div>
          <h3 className={`text-base font-semibold tracking-tight ${isLight ? 'text-slate-900' : 'text-slate-100'}`}>
            Blocked Sources
          </h3>
          <p className={`text-xs mt-0.5 ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
            {activeBlockedIps.length} malicious addresses isolated
          </p>
        </div>

        <div className={`text-xs font-mono ${isLight ? 'text-slate-500 font-medium' : 'text-slate-400'}`}>
          Enforced via Redis Token Bucket
        </div>
      </div>

      {/* Manual Unblock Feedback Notification */}
      {feedbackMsg && (
        <div className="mt-2.5 px-3 py-1.5 bg-emerald-500/10 border border-emerald-500/20 rounded-lg text-xs text-emerald-600 font-mono animate-fade-in font-semibold">
          ✓ {feedbackMsg}
        </div>
      )}

      {/* Search Bar & Manual Unblock Input Form */}
      <div className="flex flex-col sm:flex-row gap-2 my-3">
        {/* Search */}
        <div className="relative flex-1">
          <Search className={`w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 ${isLight ? 'text-slate-400' : 'text-slate-500'}`} />
          <input
            type="text"
            placeholder="Search blacklisted IP..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className={`w-full pl-9 pr-3 py-1.5 rounded-lg text-xs transition focus:outline-none ${
              isLight
                ? 'bg-slate-50 border border-slate-300 text-slate-900 placeholder-slate-400 focus:border-cyan-500'
                : 'bg-slate-950/60 border border-white/[0.06] text-slate-200 placeholder-slate-500 focus:border-slate-700'
            }`}
          />
        </div>

        {/* Manual Unblock Input Form */}
        <form onSubmit={handleManualUnblockSubmit} className="flex gap-1.5">
          <input
            type="text"
            placeholder="Manual IP (e.g. 192.168.1.1)"
            value={manualIpInput}
            onChange={(e) => setManualIpInput(e.target.value)}
            className={`w-44 px-2.5 py-1.5 rounded-lg text-xs font-mono transition focus:outline-none ${
              isLight
                ? 'bg-slate-50 border border-slate-300 text-slate-900 placeholder-slate-400 focus:border-emerald-500'
                : 'bg-slate-950/60 border border-white/[0.06] text-slate-200 placeholder-slate-500 focus:border-emerald-500/50'
            }`}
          />
          <button
            type="submit"
            disabled={!manualIpInput.trim()}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-1 shrink-0 ${
              isLight
                ? 'bg-emerald-100 hover:bg-emerald-200 text-emerald-800 border border-emerald-300 font-semibold'
                : 'bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
            }`}
          >
            <ShieldCheck className="w-3.5 h-3.5" />
            Unblock
          </button>
        </form>
      </div>

      {/* Table Container */}
      <div className={`flex-1 overflow-x-auto overflow-y-auto custom-scrollbar border rounded-xl ${
        isLight ? 'bg-white border-slate-200 shadow-sm' : 'bg-slate-950/30 border-white/[0.04]'
      }`}>
        <table className="w-full text-left text-xs">
          <thead className={`sticky top-0 font-semibold text-[11px] uppercase border-b z-10 ${
            isLight ? 'bg-slate-100 text-slate-700 border-slate-200' : 'bg-slate-950/90 text-slate-400 border-white/[0.06]'
          }`}>
            <tr>
              <th className="py-2.5 px-3">IP Address</th>
              <th className="py-2.5 px-3">Threat</th>
              <th className="py-2.5 px-3">Status</th>
              <th className="py-2.5 px-3">Time</th>
              <th className="py-2.5 px-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className={`divide-y ${isLight ? 'divide-slate-200 text-slate-800' : 'divide-white/[0.04] text-slate-300'}`}>
            {filteredIps.length === 0 ? (
              <tr>
                <td colSpan={5} className={`py-12 text-center text-xs font-mono ${isLight ? 'text-slate-400' : 'text-slate-500'}`}>
                  {searchQuery ? "No IP addresses match search." : "No IP addresses currently blocked."}
                </td>
              </tr>
            ) : (
              filteredIps.map((ip) => {
                const details = getIpDetails(ip);
                return (
                  <tr key={ip} className={`transition-colors ${isLight ? 'hover:bg-slate-50' : 'hover:bg-slate-900/40'}`}>
                    {/* IP */}
                    <td className={`py-2.5 px-3 font-mono font-semibold whitespace-nowrap ${isLight ? 'text-slate-900' : 'text-slate-200'}`}>
                      {ip}
                    </td>

                    {/* Threat */}
                    <td className={`py-2.5 px-3 max-w-[160px] truncate ${isLight ? 'text-slate-700 font-medium' : 'text-slate-300'}`} title={details.reason}>
                      {details.reason}
                    </td>

                    {/* Status */}
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold ${
                        isLight ? 'bg-rose-100 text-rose-700 border border-rose-300' : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                      }`}>
                        BLOCKED
                      </span>
                    </td>

                    {/* Time */}
                    <td className={`py-2.5 px-3 font-mono text-[11px] whitespace-nowrap ${isLight ? 'text-slate-500 font-medium' : 'text-slate-400'}`}>
                      {details.time}
                    </td>

                    {/* Actions */}
                    <td className="py-2.5 px-3 text-right whitespace-nowrap">
                      <div className="flex items-center justify-end gap-1.5">
                        <button
                          onClick={() => handleCopy(ip)}
                          className={`p-1 rounded transition ${
                            isLight ? 'hover:bg-slate-200 text-slate-500 hover:text-slate-900' : 'hover:bg-slate-800 text-slate-400 hover:text-slate-200'
                          }`}
                          title="Copy IP"
                        >
                          {copiedIp === ip ? (
                            <Check className="w-3.5 h-3.5 text-emerald-500" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                        <button
                          onClick={() => handleUnblock(ip)}
                          className={`px-2 py-0.5 rounded transition text-[11px] font-medium border ${
                            isLight
                              ? 'bg-slate-100 hover:bg-emerald-50 border-slate-300 text-slate-700 hover:text-emerald-700'
                              : 'border-white/[0.06] hover:bg-slate-800 text-slate-400 hover:text-emerald-400'
                          }`}
                          title="Unblock IP"
                        >
                          Release
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
