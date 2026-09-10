"use client";

import React, { useState, useRef, useEffect } from 'react';
import { Terminal, Zap, ShieldAlert, Activity, Sun, Moon } from 'lucide-react';

interface LogEntry {
  id: string;
  timestamp: string;
  method: string;
  endpoint: string;
  status: number | string;
  response: string;
  type: 'clean' | 'attack' | 'ddos';
}

interface AttackerConsoleProps {
  theme?: 'dark' | 'light';
  onToggleTheme?: () => void;
}

export const AttackerConsole: React.FC<AttackerConsoleProps> = ({ theme = 'dark', onToggleTheme }) => {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [isAttacking, setIsAttacking] = useState(false);
  const logsEndRef = useRef<HTMLDivElement>(null);

  const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

  const addLog = (log: Omit<LogEntry, 'id' | 'timestamp'>) => {
    const newLog: LogEntry = {
      ...log,
      id: Math.random().toString(36).substring(2, 9),
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3 }),
    };
    setLogs((prev) => [...prev, newLog]);
  };

  useEffect(() => {
    if (logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs]);

  const generateRandomIp = () => `185.220.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;

  const handleCleanTraffic = async () => {
    const payload = { username: 'admin', password: 'secret123' };
    try {
      const res = await fetch(`${API_URL}/api/v1/auth/login`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'X-Forwarded-For': generateRandomIp()
        },
        body: JSON.stringify(payload),
      });
      const data = await res.json().catch(() => ({}));
      addLog({
        method: 'POST',
        endpoint: '/api/v1/auth/login',
        status: res.status,
        response: res.status === 200 ? 'OK - Token Granted' : (res.status === 403 ? 'Forbidden - Quarantined' : JSON.stringify(data).substring(0, 40)),
        type: 'clean'
      });
    } catch (err: any) {
      addLog({ method: 'POST', endpoint: '/api/v1/auth/login', status: 'ERR', response: err.message, type: 'clean' });
    }
  };

  const handleSqlInjection = async () => {
    const payload = { username: "admin' OR 1=1 --", password: 'x' };
    try {
      const res = await fetch(`${API_URL}/api/v1/auth/login`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'X-Forwarded-For': generateRandomIp()
        },
        body: JSON.stringify(payload),
      });
      const data = await res.json().catch(() => ({}));
      addLog({
        method: 'POST',
        endpoint: '/api/v1/auth/login',
        status: res.status,
        response: res.status === 403 ? 'Forbidden - Quarantined' : JSON.stringify(data).substring(0, 40),
        type: 'attack'
      });
    } catch (err: any) {
      addLog({ method: 'POST', endpoint: '/api/v1/auth/login', status: 'ERR', response: err.message, type: 'attack' });
    }
  };

  const handleDdosSpike = async () => {
    setIsAttacking(true);
    const spikeIp = generateRandomIp(); // Use one IP for the burst to trigger rate limit
    for (let i = 0; i < 120; i++) {
      setTimeout(async () => {
        try {
          const res = await fetch(`${API_URL}/api/v1/search?q=ddos`, {
            method: 'GET',
            headers: { 'X-Forwarded-For': spikeIp }
          });
          addLog({
            method: 'GET',
            endpoint: '/api/v1/search',
            status: res.status,
            response: res.status === 429 ? 'Too Many Requests' : (res.status === 403 ? 'Forbidden - Quarantined' : 'OK'),
            type: 'ddos'
          });
        } catch (err: any) {
          addLog({ method: 'GET', endpoint: '/api/v1/search', status: 'ERR', response: err.message, type: 'ddos' });
        }
      }, i * 20); // Fire every 20ms
    }
    setTimeout(() => setIsAttacking(false), 120 * 20 + 500);
  };

  const isLight = theme === 'light';

  return (
    <div className={`flex flex-col h-full rounded-xl overflow-hidden shadow-2xl transition-colors ${
      isLight ? 'bg-white border border-slate-300' : 'bg-zinc-950 border border-slate-800'
    }`}>
      {/* Header */}
      <div className={`flex items-center justify-between px-4 py-3 border-b ${
        isLight ? 'bg-slate-100 border-slate-200' : 'bg-zinc-900 border-slate-800'
      }`}>
        <div className="flex items-center gap-2">
          <Terminal className="w-5 h-5 text-red-500" />
          <h2 className={`text-sm font-bold tracking-wide ${isLight ? 'text-slate-800' : 'text-slate-200'}`}>
            Red-Team Traffic Generator
          </h2>
        </div>
        <div className="flex items-center gap-2">
          {onToggleTheme && (
            <button
              onClick={onToggleTheme}
              className={`p-1.5 rounded-lg border text-xs font-medium flex items-center gap-1.5 transition-colors ${
                isLight ? 'bg-white hover:bg-slate-200 border-slate-300 text-slate-700' : 'bg-zinc-800 hover:bg-zinc-700 border-slate-700 text-slate-300'
              }`}
              title="Toggle Dark / Light Mode"
            >
              {isLight ? <Moon className="w-3.5 h-3.5 text-indigo-600" /> : <Sun className="w-3.5 h-3.5 text-amber-400" />}
              <span className="hidden sm:inline">{isLight ? 'Dark' : 'Light'}</span>
            </button>
          )}
          <div className={`px-2 py-1 rounded text-[10px] font-mono border ${
            isLight ? 'bg-red-50 border-red-200 text-red-700' : 'bg-red-950/30 border-red-900/50 text-red-400'
          }`}>
            TARGET: {API_URL}/api/v1/data
          </div>
        </div>
      </div>

      {/* Controls */}
      <div className={`p-4 border-b flex flex-col gap-3 ${
        isLight ? 'bg-slate-50 border-slate-200' : 'bg-zinc-900/50 border-slate-800'
      }`}>
        <button
          onClick={handleCleanTraffic}
          className={`flex items-center justify-center gap-2 w-full py-2.5 px-4 text-sm font-medium rounded-lg transition-colors border shadow-sm ${
            isLight
              ? 'bg-white hover:bg-slate-100 text-slate-800 border-slate-300'
              : 'bg-slate-800 hover:bg-slate-700 text-slate-200 border-slate-700'
          }`}
        >
          <Activity className="w-4 h-4 text-emerald-500" />
          Send Clean Traffic
        </button>
        <button
          onClick={handleSqlInjection}
          className={`flex items-center justify-center gap-2 w-full py-2.5 px-4 text-sm font-medium rounded-lg transition-colors border ${
            isLight
              ? 'bg-amber-50 hover:bg-amber-100 text-amber-900 border-amber-300'
              : 'bg-amber-950/50 hover:bg-amber-900/60 text-amber-500 border-amber-900/50'
          }`}
        >
          <ShieldAlert className="w-4 h-4" />
          Execute SQL Injection
        </button>
        <button
          onClick={handleDdosSpike}
          disabled={isAttacking}
          className={`flex items-center justify-center gap-2 w-full py-2.5 px-4 text-sm font-medium rounded-lg transition-colors border disabled:opacity-50 ${
            isLight
              ? 'bg-red-50 hover:bg-red-100 text-red-900 border-red-300'
              : 'bg-red-950/50 hover:bg-red-900/60 text-red-500 border-red-900/50'
          }`}
        >
          <Zap className="w-4 h-4" />
          {isAttacking ? 'Firing...' : 'Launch DDoS Spike'}
        </button>
      </div>

      {/* Terminal Output */}
      <div className={`flex-1 p-4 overflow-y-auto font-mono text-xs leading-relaxed ${
        isLight ? 'bg-slate-900 text-slate-200' : 'bg-black text-slate-200'
      }`}>
        {logs.length === 0 ? (
          <div className="text-zinc-500 italic">Waiting for command execution...</div>
        ) : (
          logs.map((log) => (
            <div key={log.id} className="mb-1 flex flex-col sm:flex-row sm:gap-2">
              <span className="text-zinc-500 shrink-0">[{log.timestamp}]</span>
              <span className="text-slate-300">
                <span className={log.type === 'clean' ? 'text-emerald-400 font-semibold' : log.type === 'attack' ? 'text-amber-400 font-semibold' : 'text-red-400 font-semibold'}>
                  {log.method}
                </span>{' '}
                {log.endpoint}
              </span>
              <span className="text-zinc-400 sm:ml-auto">
                <span className={log.status === 200 ? 'text-emerald-400 font-bold' : (log.status === 403 || log.status === 400 || log.status === 429) ? 'text-red-400 font-bold' : 'text-amber-400 font-bold'}>
                  {log.status}
                </span>{' '}
                - {log.response}
              </span>
            </div>
          ))
        )}
        <div ref={logsEndRef} />
      </div>
    </div>
  );
};

