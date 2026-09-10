"use client";

import React, { useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  Shield,
  Eye,
  Menu,
  X,
  LayoutDashboard,
  Radar,
  AlertCircle,
  Sparkles,
  Sliders,
  Sun,
  Moon,
} from 'lucide-react';
import { useEnclave } from '../context/EnclaveContext';

export const TopBar: React.FC = () => {
  const pathname = usePathname();
  const { lastSyncTime, theme, toggleTheme } = useEnclave();
  const [mobileMenuOpen, setMobileMenuOpen] = useState<boolean>(false);
  const isDark = theme === 'dark';

  const getPageTitle = (path: string) => {
    if (path === '/') return 'Executive Overview';
    if (path.startsWith('/radar')) return '6-Vector Threat Radar';
    if (path.startsWith('/incidents')) return 'Live Incident Feed & Forensics';
    if (path.startsWith('/analyst')) return 'Cognitive Threat Analyst';
    if (path.startsWith('/enclave')) return 'Enclave Health & Diode Controls';
    return 'Enclave Console';
  };

  const navLinks = [
    { name: 'Overview', href: '/', icon: <LayoutDashboard className="h-4 w-4" /> },
    { name: '6-Vector Radar', href: '/radar', icon: <Radar className="h-4 w-4" /> },
    { name: 'Incident Feed', href: '/incidents', icon: <AlertCircle className="h-4 w-4" /> },
    { name: 'AI Analyst', href: '/analyst', icon: <Sparkles className="h-4 w-4" /> },
    { name: 'Enclave Controls', href: '/enclave', icon: <Sliders className="h-4 w-4" /> },
  ];

  return (
    <header className="sticky top-0 z-20 w-full border-b border-[#E5E5F0] dark:border-white/5 bg-[#ECEBF5]/80 dark:bg-[#1C1D21]/80 backdrop-blur-md transition-colors duration-250 py-3.5 px-4 sm:px-6">
      <div className="mx-auto flex max-w-[1700px] items-center justify-between gap-3">
        {/* Page Title & Breadcrumb */}
        <div className="flex items-center gap-3">
          {/* Mobile hamburger toggle */}
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="flex h-9 w-9 items-center justify-center rounded-xl border border-[#E5E5F0] dark:border-white/10 bg-white dark:bg-[#26282E] text-[#1E1E2D] dark:text-white lg:hidden"
            aria-label="Toggle Navigation"
          >
            {mobileMenuOpen ? <X className="h-4 w-4" /> : <Menu className="h-4 w-4" />}
          </button>

          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold text-[#8A8FA3] dark:text-[#9CA3AF]">
                STRATA /
              </span>
              <h1 className="text-sm sm:text-base font-extrabold tracking-tight text-[#1E1E2D] dark:text-white">
                {getPageTitle(pathname)}
              </h1>
            </div>
          </div>
        </div>

        {/* Right: Diode Status Badge & Synced Time */}
        <div className="flex items-center gap-2.5 sm:gap-3">
          {/* Live Diode Read-Only Badge */}
          <div className="inline-flex items-center gap-1.5 rounded-full border border-emerald-200 dark:border-emerald-500/20 bg-emerald-50 dark:bg-emerald-500/10 px-3 py-1 text-[11px] font-bold text-emerald-700 dark:text-emerald-400 shadow-sm">
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500" />
            </span>
            <span className="hidden sm:inline">DIODE READ-ONLY: ZERO RETURN PATH</span>
            <span className="sm:hidden">READ-ONLY</span>
          </div>

          {/* Synced Time Chip */}
          <div className="hidden md:inline-flex items-center gap-1.5 rounded-full border border-[#E5E5F0] dark:border-white/10 bg-white dark:bg-[#26282E] px-3 py-1 text-xs font-medium text-[#8A8FA3] dark:text-[#9CA3AF] shadow-sm">
            <Eye className="h-3.5 w-3.5 text-indigo-500 dark:text-indigo-400" />
            <span>
              Synced: <strong className="text-[#1E1E2D] dark:text-[#F3F4F6]">{lastSyncTime || 'LIVE'}</strong>
            </span>
          </div>
        </div>
      </div>

      {/* Mobile Drawer Menu */}
      {mobileMenuOpen && (
        <div className="lg:hidden mt-3 pt-3 border-t border-[#E5E5F0] dark:border-white/5 space-y-2">
          {navLinks.map((item) => {
            const isActive =
              item.href === '/'
                ? pathname === '/'
                : pathname.startsWith(item.href);

            return (
              <Link
                key={item.name}
                href={item.href}
                onClick={() => setMobileMenuOpen(false)}
                className={`flex items-center gap-3 rounded-xl px-3 py-2 text-xs font-semibold ${
                  isActive
                    ? 'bg-indigo-600 text-white'
                    : 'text-[#8A8FA3] dark:text-[#9CA3AF] hover:bg-white dark:hover:bg-[#26282E]'
                }`}
              >
                {item.icon}
                <span>{item.name}</span>
              </Link>
            );
          })}

          <div className="flex items-center justify-between pt-2 border-t border-[#E5E5F0] dark:border-white/5 px-3">
            <span className="text-xs text-[#8A8FA3] dark:text-[#9CA3AF]">Toggle Theme</span>
            <button
              onClick={toggleTheme}
              className="flex h-7 w-7 items-center justify-center rounded-full bg-indigo-600 text-white"
            >
              {isDark ? <Moon className="h-3.5 w-3.5" /> : <Sun className="h-3.5 w-3.5" />}
            </button>
          </div>
        </div>
      )}
    </header>
  );
};
