import { useRef, useEffect } from 'react';
import * as echarts from 'echarts/core';
import { GaugeChart } from 'echarts/charts';
import { CanvasRenderer } from 'echarts/renderers';
import { TitleComponent } from 'echarts/components';
import type { ECharts } from 'echarts/core';
import type { RiskStreamSnapshot } from '@/types/live';
import { Shield, ShieldAlert, Activity } from 'lucide-react';

echarts.use([GaugeChart, CanvasRenderer, TitleComponent]);

function threatClass(level: string): string {
  switch (level) {
    case 'critical':
      return 'bg-red-50 text-red-700 ring-1 ring-red-200';
    case 'high':
      return 'bg-orange-50 text-orange-700 ring-1 ring-orange-200';
    case 'medium':
      return 'bg-amber-50 text-amber-700 ring-1 ring-amber-200';
    default:
      return 'bg-green-50 text-green-700 ring-1 ring-green-200';
  }
}

interface RiskSummaryCardProps {
  data?: RiskStreamSnapshot;
  isLoading: boolean;
  isError: boolean;
}

export function RiskSummaryCard({ data, isLoading, isError }: RiskSummaryCardProps) {
  const gaugeRef = useRef<HTMLDivElement>(null);
  const chartRef = useRef<ECharts | null>(null);

  useEffect(() => {
    if (!gaugeRef.current) return;
    if (!chartRef.current) {
      chartRef.current = echarts.init(gaugeRef.current, undefined, { renderer: 'canvas' });
    }
    const handleResize = () => chartRef.current?.resize();
    window.addEventListener('resize', handleResize);
    return () => {
      window.removeEventListener('resize', handleResize);
      chartRef.current?.dispose();
      chartRef.current = null;
    };
  }, []);

  useEffect(() => {
    if (!chartRef.current || !data) return;
    const clamped = Math.min(1, Math.max(0, data.risk_avg)) * 100;
    let color = '#22c55e';
    if (clamped >= 76) color = '#ef4444';
    else if (clamped >= 51) color = '#f97316';
    else if (clamped >= 26) color = '#eab308';

    chartRef.current.setOption(
      {
        series: [
          {
            type: 'gauge',
            startAngle: 180,
            endAngle: 0,
            min: 0,
            max: 100,
            splitNumber: 5,
            itemStyle: { color },
            progress: { show: true, width: 16 },
            pointer: { show: false },
            axisLine: { lineStyle: { width: 16, color: [[1, '#e5e7eb']] } },
            axisTick: { show: false },
            splitLine: { length: 8, lineStyle: { width: 2, color: '#999' } },
            axisLabel: { distance: 14, fontSize: 10, color: '#666' },
            detail: {
              valueAnimation: true,
              fontSize: 22,
              fontWeight: 'bold',
              offsetCenter: [0, '35%'],
              formatter: '{value}',
              color: 'inherit',
            },
            data: [{ value: Math.round(clamped), name: 'Risk Score' }],
          },
        ],
      },
      true,
    );
  }, [data]);

  if (isLoading) {
    return (
      <div className="bg-white border border-gray-200 rounded-xl p-5 animate-pulse">
        <div className="h-48 bg-gray-100 rounded-lg" />
        <div className="mt-3 h-4 w-24 bg-gray-100 rounded" />
      </div>
    );
  }

  if (isError) {
    return (
      <div className="bg-white border border-gray-200 rounded-xl p-5">
        <div className="flex items-center gap-2 mb-3">
          <ShieldAlert className="w-4 h-4 text-red-500" />
          <h3 className="text-sm font-semibold text-gray-700">Risk Summary</h3>
        </div>
        <p className="text-sm text-red-600">Failed to load risk data</p>
      </div>
    );
  }

  const level = data?.threat_level ?? 'low';
  const rules = data?.top_rules_triggered ?? [];

  return (
    <div className="bg-white border border-gray-200 rounded-xl p-5">
      <div className="flex items-center justify-between mb-1">
        <div className="flex items-center gap-2">
          <Activity className="w-4 h-4 text-blue-600" />
          <h3 className="text-sm font-semibold text-gray-700">Risk Summary</h3>
        </div>
        <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold capitalize ${threatClass(level)}`}>
          {level === 'critical' || level === 'high' ? (
            <ShieldAlert className="w-3 h-3" />
          ) : (
            <Shield className="w-3 h-3" />
          )}
          {level}
        </span>
      </div>

      <div ref={gaugeRef} className="w-full h-48" />

      {rules.length > 0 && (
        <div className="mt-2 pt-3 border-t border-gray-100">
          <p className="text-[11px] font-medium text-gray-500 mb-1.5">Top Triggered Rules</p>
          <ul className="space-y-1">
            {rules.map((rule) => (
              <li key={rule} className="text-xs font-mono text-gray-700 truncate">
                {rule}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
