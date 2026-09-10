"use client";

import React, { useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  Shield,
  LayoutDashboard,
  Radar,
  AlertCircle,
  Sparkles,
  Sliders,
  Sun,
  Moon,
  Zap,
  Radio,
} from 'lucide-react';
import { useEnclave } from '../context/EnclaveContext';

interface NavItem {
  name: string;
  href: string;
  icon: React.ReactNode;
  badge?: string;
}

const NAV_ITEMS: NavItem[] = [
  {
    name: 'Overview',
    href: '/',
    icon: <LayoutDashboard className="h-5 w-5" />,
  },
  {
    name: '6-Vector Radar',
    href: '/radar',
    icon: <Radar className="h-5 w-5" />,
    badge: '6',
  },
  {
    name: 'Incident Feed',
    href: '/incidents',
    icon: <AlertCircle className="h-5 w-5" />,
  },
  {
    name: 'AI Analyst',
    href: '/analyst',
    icon: <Sparkles className="h-5 w-5" />,
    badge: 'Gemini',
  },
  {
    name: 'Enclave Controls',
    href: '/enclave',
    icon: <Sliders className="h-5 w-5" />,
  },
];

export const IslandDock: React.FC = () => {
  const pathname = usePathname();
  const { theme, toggleTheme, kpis, bursting, triggerBurst } = useEnclave();
  const isDark = theme === 'dark';
  const [burstThreat, setBurstThreat] = useState<string>('DGA_DNS_TUNNEL');

  return (
    <aside className="sticky top-4 hidden h-[calc(100vh-2rem)] w-64 shrink-0 flex-col justify-between rounded-3xl border border-white/70 dark:border-white/5 bg-white/85 dark:bg-[#23252B]/85 p-4 shadow-xl shadow-slate-200/50 dark:shadow-2xl dark:shadow-black/40 backdrop-blur-xl transition-all duration-300 lg:flex z-30">
      {/* Top: Brand Identity Squircle */}
      <div>
        <div className="flex items-center gap-3 px-2 py-2">
          <div className="relative flex h-11 w-11 items-center justify-center rounded-2xl bg-gradient-to-tr from-indigo-600 via-indigo-500 to-violet-500 text-white shadow-md shadow-indigo-500/25">
            <Shield className="h-6 w-6" />
            <span className="absolute -top-0.5 -right-0.5 flex h-2.5 w-2.5">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
              <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-emerald-500" />
            </span>
          </div>

          <div>
            <div className="flex items-center gap-1.5">
              <span className="text-base font-extrabold tracking-tight text-[#1E1E2D] dark:text-white">
                STRATA
              </span>
              <span className="rounded-full bg-indigo-50 dark:bg-indigo-500/15 px-2 py-0.5 text-[10px] font-bold text-indigo-700 dark:text-indigo-400">
                v2.0
              </span>
            </div>
            <p className="text-[11px] font-medium text-[#8A8FA3] dark:text-[#9CA3AF]">
              Passive Data Diode
            </p>
          </div>
        </div>

        <div className="my-3 h-px w-full bg-[#E5E5F0] dark:bg-white/5" />

        {/* Center: Navigation Links */}
        <nav className="space-y-1.5 pt-1">
          {NAV_ITEMS.map((item) => {
            const isActive =
              item.href === '/'
                ? pathname === '/'
                : pathname.startsWith(item.href);

            return (
              <Link
                key={item.name}
                href={item.href}
                className={`group relative flex items-center justify-between rounded-2xl px-3.5 py-2.5 text-xs font-semibold transition-all duration-200 ${
                  isActive
                    ? 'bg-indigo-600 text-white shadow-md shadow-indigo-500/25'
                    : 'text-[#8A8FA3] dark:text-[#9CA3AF] hover:bg-slate-100 dark:hover:bg-white/5 hover:text-[#1E1E2D] dark:hover:text-white'
                }`}
              >
                <div className="flex items-center gap-3">
                  <div
                    className={`${
                      isActive
                        ? 'text-white'
                        : 'text-[#8A8FA3] dark:text-[#9CA3AF] group-hover:text-indigo-600 dark:group-hover:text-indigo-400 transition-colors'
                    }`}
                  >
                    {item.icon}
                  </div>
                  <span className="tracking-wide">{item.name}</span>
                </div>

                {item.badge && (
                  <span
                    className={`rounded-full px-2 py-0.5 text-[10px] font-bold ${
                      isActive
                        ? 'bg-white/20 text-white'
                        : 'bg-[#ECEBF5] dark:bg-white/10 text-[#8A8FA3] dark:text-[#9CA3AF]'
                    }`}
                  >
                    {item.badge}
                  </span>
                )}

                {/* Animated active bar */}
                {isActive && (
                  <span className="absolute left-0 top-2 bottom-2 w-1 rounded-r-full bg-white opacity-80" />
                )}
              </Link>
            );
          })}
        </nav>
      </div>

      {/* Bottom Utility Section */}
      <div className="space-y-3 pt-3 border-t border-[#E5E5F0] dark:border-white/5">
        {/* Quick Threat Burst Trigger */}
        <div className="rounded-2xl border border-[#E5E5F0] dark:border-white/5 bg-[#F8F8FC] dark:bg-[#1E1F24] p-2.5 text-xs">
          <div className="flex items-center justify-between text-[10px] font-bold text-[#8A8FA3] dark:text-[#9CA3AF] mb-1.5">
            <span>QUICK BURST</span>
            <Radio className="h-3 w-3 text-indigo-500 animate-pulse" />
          </div>

          <select
            value={burstThreat}
            onChange={(e) => setBurstThreat(e.target.value)}
            className="w-full rounded-xl border border-[#E5E5F0] dark:border-white/10 bg-white dark:bg-[#26282E] px-2.5 py-1 text-[11px] font-medium text-[#1E1E2D] dark:text-[#F3F4F6] focus:outline-none mb-2 cursor-pointer"
          >
            <option value="DGA_DNS_TUNNEL">DGA / DNS Tunnel</option>
            <option value="ENCRYPTED_MALWARE">Encrypted Malware (JA3)</option>
            <option value="VOLUMETRIC_DDOS">Volumetric DDoS</option>
            <option value="BOTNET_C2">Botnet C2 Beacon</option>
            <option value="RECON_SCAN">Recon Scan</option>
            <option value="DATA_EXFIL">Data Exfiltration</option>
          </select>

          <button
            onClick={() => triggerBurst(burstThreat, 60)}
            disabled={bursting}
            className="w-full flex items-center justify-center gap-1.5 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white py-1.5 text-xs font-semibold shadow-sm transition-all disabled:opacity-50 cursor-pointer"
          >
            <Radio className={`h-3 w-3 ${bursting ? 'animate-spin' : ''}`} />
            <span>{bursting ? 'Injecting...' : 'Inject Threat'}</span>
          </button>
        </div>

        {/* SLA Health Badge */}
        <div className="flex items-center justify-between rounded-2xl border border-[#E5E5F0] dark:border-white/5 bg-[#F8F8FC] dark:bg-[#1E1F24] px-3 py-2 text-xs">
          <div className="flex items-center gap-2">
            <Zap className="h-3.5 w-3.5 text-amber-500" />
            <span className="font-semibold text-[#1E1E2D] dark:text-[#F3F4F6]">
              {kpis.pipeline_latency_ms.toFixed(1)}ms
            </span>
          </div>
          <span className="rounded-full bg-emerald-50 dark:bg-emerald-500/10 px-2 py-0.5 text-[10px] font-bold text-emerald-700 dark:text-emerald-400">
            SLA &lt; 50ms
          </span>
        </div>

        {/* Sun / Moon Switch Pill */}
        <div className="flex items-center justify-between rounded-2xl border border-[#E5E5F0] dark:border-white/5 bg-[#F8F8FC] dark:bg-[#1E1F24] px-3 py-2">
          <span className="text-xs font-semibold text-[#8A8FA3] dark:text-[#9CA3AF]">
            {isDark ? 'Dark Mode' : 'Light Mode'}
          </span>

          <button
            onClick={toggleTheme}
            aria-label="Toggle Light / Dark theme"
            className="relative inline-flex h-8 w-14 items-center rounded-full border border-[#E5E5F0] dark:border-white/10 bg-white dark:bg-[#26282E] p-1 shadow-sm transition-colors cursor-pointer"
          >
            <div
              className={`flex h-6 w-6 items-center justify-center rounded-full bg-indigo-600 text-white shadow-sm transform transition-transform duration-200 ${
                isDark ? 'translate-x-6' : 'translate-x-0 bg-amber-500'
              }`}
            >
              {isDark ? <Moon className="h-3 w-3" /> : <Sun className="h-3 w-3" />}
            </div>
          </button>
        </div>
      </div>
    </aside>
  );
};
