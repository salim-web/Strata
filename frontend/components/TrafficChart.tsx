"use client";

import React, { useState } from 'react';
import { AreaChart } from '@tremor/react';
import { Activity } from 'lucide-react';
import { TrafficDataPoint } from '../lib/mockData';

interface TrafficChartProps {
  data: TrafficDataPoint[];
  theme?: 'dark' | 'light';
}

export const TrafficChart: React.FC<TrafficChartProps> = ({ data = [], theme = 'dark' }) => {
  const [selectedView, setSelectedView] = useState<'all' | 'requests' | 'blocked'>('all');
  const isLight = theme === 'light';

  const getCategories = () => {
    switch (selectedView) {
      case 'requests':
        return ['requests'];
      case 'blocked':
        return ['blocked'];
      case 'all':
      default:
        return ['requests', 'blocked'];
    }
  };

  const getColors = () => {
    switch (selectedView) {
      case 'requests':
        return ['cyan'];
      case 'blocked':
        return ['rose'];
      case 'all':
      default:
        return ['cyan', 'rose'];
    }
  };

  const latestPoint = data.length > 0 ? data[data.length - 1] : { requests: 0, blocked: 0 };

  return (
    <div className={`glass-panel p-6 shadow-sm ${isLight ? 'bg-white border-slate-200 text-slate-900' : ''}`}>
      {/* Header */}
      <div className={`flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b ${isLight ? 'border-slate-200' : 'border-white/[0.06]'}`}>
        <div>
          <div className="flex items-center gap-2.5">
            <h3 className={`text-base font-semibold tracking-tight ${isLight ? 'text-slate-900' : 'text-slate-100'}`}>
              Traffic Overview
            </h3>
            <span className="flex items-center gap-1.5 px-2 py-0.5 bg-emerald-500/10 border border-emerald-500/20 text-emerald-500 text-[10px] font-semibold tracking-wide rounded-full">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
              LIVE
            </span>
          </div>
          <p className={`text-xs mt-0.5 ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
            Real-time request activity
          </p>
        </div>

        {/* Stream Filter & Current Velocity */}
        <div className="flex items-center gap-3">
          <div className={`flex items-center p-0.5 rounded-lg border text-xs ${
            isLight ? 'bg-slate-100 border-slate-200' : 'bg-slate-950/60 border-white/[0.06]'
          }`}>
            <button
              onClick={() => setSelectedView('all')}
              className={`px-3 py-1 rounded-md transition-colors text-xs font-medium ${
                selectedView === 'all'
                  ? (isLight ? 'bg-white text-slate-900 shadow-sm font-semibold' : 'bg-slate-800/90 text-slate-100 shadow-sm')
                  : (isLight ? 'text-slate-600 hover:text-slate-900' : 'text-slate-400 hover:text-slate-200')
              }`}
            >
              All
            </button>
            <button
              onClick={() => setSelectedView('requests')}
              className={`px-3 py-1 rounded-md transition-colors text-xs font-medium ${
                selectedView === 'requests'
                  ? (isLight ? 'bg-white text-cyan-600 shadow-sm font-semibold' : 'bg-slate-800/90 text-cyan-300 shadow-sm')
                  : (isLight ? 'text-slate-600 hover:text-slate-900' : 'text-slate-400 hover:text-slate-200')
              }`}
            >
              Requests
            </button>
            <button
              onClick={() => setSelectedView('blocked')}
              className={`px-3 py-1 rounded-md transition-colors text-xs font-medium ${
                selectedView === 'blocked'
                  ? (isLight ? 'bg-white text-rose-600 shadow-sm font-semibold' : 'bg-slate-800/90 text-rose-300 shadow-sm')
                  : (isLight ? 'text-slate-600 hover:text-slate-900' : 'text-slate-400 hover:text-slate-200')
              }`}
            >
              Blocked
            </button>
          </div>

          <div className={`hidden sm:flex items-center gap-2 pl-3 border-l text-xs font-mono ${
            isLight ? 'border-slate-200 text-slate-700' : 'border-white/[0.06] text-slate-300'
          }`}>
            <span className={isLight ? 'text-slate-500' : 'text-slate-400'}>Current:</span>
            <span className="text-cyan-600 font-semibold">{latestPoint.requests} req/s</span>
          </div>
        </div>
      </div>

      {/* Area Chart */}
      <div className="h-60 mt-4 w-full">
        <AreaChart
          className="h-60"
          data={data}
          index="time"
          categories={getCategories()}
          colors={getColors()}
          valueFormatter={(val: number) => `${val.toLocaleString()} req`}
          yAxisWidth={68}
          showGridLines={true}
          curveType="monotone"
          showLegend={false}
          showAnimation={false}
        />
      </div>

      {/* Legend */}
      <div className={`mt-3 pt-3 border-t flex flex-wrap items-center justify-between text-xs ${
        isLight ? 'border-slate-200 text-slate-600' : 'border-white/[0.04] text-slate-400'
      }`}>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-cyan-500"></span>
            <span className="text-[11px]">Ingress volume</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-rose-500"></span>
            <span className="text-[11px]">Blocked sources</span>
          </div>
        </div>
        <div className={`text-[11px] font-mono ${isLight ? 'text-slate-500' : 'text-slate-500'}`}>
          2s refresh window
        </div>
      </div>
    </div>
  );
};
