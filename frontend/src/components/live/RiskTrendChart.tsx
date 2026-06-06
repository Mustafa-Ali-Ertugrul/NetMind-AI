import { useRef, useEffect } from 'react';
import * as echarts from 'echarts/core';
import { LineChart } from 'echarts/charts';
import { CanvasRenderer } from 'echarts/renderers';
import { TitleComponent, TooltipComponent, GridComponent } from 'echarts/components';
import type { ECharts } from 'echarts/core';
import type { RiskBucket } from '@/types/live';
import { TrendingUp, TrendingDown, Minus } from 'lucide-react';

echarts.use([LineChart, CanvasRenderer, TitleComponent, TooltipComponent, GridComponent]);

function TrendIcon({ series }: { series: RiskBucket[] }) {
  if (series.length < 2) return <Minus className="w-4 h-4 text-gray-400" />;
  const last = series[series.length - 1].risk_avg;
  const prev = series[series.length - 2].risk_avg;
  if (last > prev) return <TrendingUp className="w-4 h-4 text-red-500" />;
  if (last < prev) return <TrendingDown className="w-4 h-4 text-green-500" />;
  return <Minus className="w-4 h-4 text-gray-400" />;
}

interface RiskTrendChartProps {
  data?: RiskBucket[];
  isLoading: boolean;
  isError: boolean;
}

export function RiskTrendChart({ data, isLoading, isError }: RiskTrendChartProps) {
  const chartRef = useRef<HTMLDivElement>(null);
  const chartInstance = useRef<ECharts | null>(null);

  useEffect(() => {
    if (!chartRef.current) return;
    if (!chartInstance.current) {
      chartInstance.current = echarts.init(chartRef.current, undefined, { renderer: 'canvas' });
    }
    const handleResize = () => chartInstance.current?.resize();
    window.addEventListener('resize', handleResize);
    return () => {
      window.removeEventListener('resize', handleResize);
      chartInstance.current?.dispose();
      chartInstance.current = null;
    };
  }, []);

  useEffect(() => {
    if (!chartInstance.current || !data || data.length === 0) return;

    const times = data.map((b) => {
      const d = new Date(b.timestamp);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    });
    const values = data.map((b) => b.risk_avg);

    chartInstance.current.setOption(
      {
        tooltip: {
          trigger: 'axis',
          valueFormatter: (v: number) => `${(v * 100).toFixed(1)}%`,
        },
        grid: { left: '3%', right: '4%', bottom: '3%', top: '8%', containLabel: true },
        xAxis: {
          type: 'category',
          data: times,
          axisLabel: { fontSize: 10, color: '#888' },
        },
        yAxis: {
          type: 'value',
          min: 0,
          max: 1,
          axisLabel: {
            fontSize: 10,
            color: '#888',
            formatter: (v: number) => `${(v * 100).toFixed(0)}%`,
          },
          splitLine: { lineStyle: { color: '#f3f4f6' } },
        },
        series: [
          {
            type: 'line',
            data: values,
            smooth: true,
            symbol: 'circle',
            symbolSize: 6,
            lineStyle: { width: 2, color: '#3b82f6' },
            areaStyle: {
              color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                { offset: 0, color: 'rgba(59,130,246,0.25)' },
                { offset: 1, color: 'rgba(59,130,246,0.02)' },
              ]),
            },
            itemStyle: { color: '#3b82f6' },
          },
        ],
      },
      true,
    );
  }, [data]);

  if (isLoading) {
    return (
      <div className="bg-white border border-gray-200 rounded-xl p-5">
        <div className="flex items-center gap-2 mb-3">
          <TrendingUp className="w-4 h-4 text-gray-400 animate-pulse" />
          <h3 className="text-sm font-semibold text-gray-700 animate-pulse">Risk Trend</h3>
        </div>
        <div className="h-56 bg-gray-100 rounded-lg animate-pulse" />
      </div>
    );
  }

  if (isError) {
    return (
      <div className="bg-white border border-gray-200 rounded-xl p-5">
        <div className="flex items-center gap-2 mb-3">
          <TrendingUp className="w-4 h-4 text-red-500" />
          <h3 className="text-sm font-semibold text-gray-700">Risk Trend</h3>
        </div>
        <p className="text-sm text-red-600">Failed to load risk trend</p>
      </div>
    );
  }

  const series = data ?? [];

  return (
    <div className="bg-white border border-gray-200 rounded-xl p-5">
      <div className="flex items-center justify-between mb-1">
        <div className="flex items-center gap-2">
          <TrendingUp className="w-4 h-4 text-blue-600" />
          <h3 className="text-sm font-semibold text-gray-700">Risk Trend</h3>
        </div>
        <TrendIcon series={series} />
      </div>

      {series.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-56 text-gray-400">
          <TrendingDown className="w-8 h-8 mb-2" />
          <p className="text-sm">No trend data yet.</p>
        </div>
      ) : (
        <div ref={chartRef} className="w-full h-56" />
      )}
    </div>
  );
}
