import React from 'react';
import './globals.css';
import { Plus_Jakarta_Sans } from 'next/font/google';
import { EnclaveProvider } from '../context/EnclaveContext';
import { IslandDock } from '../components/IslandDock';
import { TopBar } from '../components/TopBar';

const plusJakartaSans = Plus_Jakarta_Sans({
  subsets: ['latin'],
  display: 'swap',
  variable: '--font-sans',
  fallback: ['system-ui', 'sans-serif'],
});

export const metadata = {
  title: 'STRATA | Passive Network Threat Intelligence Enclave',
  description: 'Unidirectional Data Diode Threat Intelligence Console with ML Ensemble & AI Analyst',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className={`dark ${plusJakartaSans.variable}`}>
      <body className="min-h-screen antialiased font-sans bg-[#ECEBF5] dark:bg-[#1C1D21] text-[#1E1E2D] dark:text-[#F3F4F6] transition-colors duration-250">
        <EnclaveProvider>
          <div className="flex min-h-screen">
            {/* Floating Island Dock Navigation (Desktop) */}
            <IslandDock />

            {/* Main Content Viewport */}
            <div className="flex flex-1 flex-col min-w-0">
              <TopBar />
              <main className="flex-1 p-4 sm:p-6 lg:p-8 max-w-[1700px] w-full mx-auto">
                {children}
              </main>
            </div>
          </div>
        </EnclaveProvider>
      </body>
    </html>
  );
}
