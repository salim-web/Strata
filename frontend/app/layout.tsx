import React from 'react';
import './globals.css';

export const metadata = {
  title: 'STRATA | Real-time Threat Intelligence',
  description: 'AI & Redis Powered Security Operations Dashboard for API Threat Mitigation',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="bg-slate-950 text-slate-100 min-h-screen antialiased selection:bg-cyan-500 selection:text-slate-950">
        {children}
      </body>
    </html>
  );
}
