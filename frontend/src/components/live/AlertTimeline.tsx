import { useEffect, useRef } from 'react';
import * as echarts from 'echarts/core';
import { BarChart } from 'echarts/charts';
import { CanvasRenderer } from 'echarts/renderers';
import {
  TitleComponent,
  TooltipComponent,
  LegendComponent,
  GridComponent,
} from 'echarts/components';
import type { ECharts } from 'echarts/core';
import type { TimelineBucketResponse } from '@/types/live';
import { formatDate } from '@/lib/format';
import { BarChart3 } from 'lucide-react';

echarts.use([BarChart, CanvasRenderer, TitleComponent, TooltipComponent, LegendComponent, GridComponent]);

interface AlertTimelineProps {
  data?: TimelineBucketResponse[];
  isLoading: boolean;
  isError: boolean;
}

function useChartInit(ref: React.RefObject<HTMLDivElement | null>) {
  const chartRef = useRef<ECharts | null>(null);
  useEffect(() => {
    if (!ref.current) return;
    chartRef.current = echarts.init(ref.current, undefined, { renderer: 'canvas' });
    const handleResize = () => chartRef.current?.resize();
    window.addEventListener('resize', handleResize);
    return () => {
      window.removeEventListener('resize', handleResize);
      chartRef.current?.dispose();
      chartRef.current = null;
    };
  }, [ref]);
  return chartRef;
}

export function AlertTimeline({ data, isLoading, isError }: AlertTimelineProps) {
  const chartRef = useRef<HTMLDivElement>(null);
  const chart = useChartInit(chartRef);

  useEffect(() => {
    if (isLoading || isError || !data || data.length === 0 || !chart.current) return;

    // Group by rule_id and bucket_start
    const ruleSet = Array.from(new Set(data.map((d) => d.rule_id))).sort();
    const bucketSet = Array.from(new Set(data.map((d) => d.bucket_start))).sort();

    const series = ruleSet.map((ruleId) => {
      const seriesData = bucketSet.map((bucket) => {
        const match = data.find((d) => d.rule_id === ruleId && d.bucket_start === bucket);
        return match?.count ?? 0;
      });
      return {
        name: ruleId,
        type: 'bar',
        stack: 'total',
        emphasis: { focus: 'series' },
        data: seriesData,
      };
    });

    chart.current.setOption({
      tooltip: {
        trigger: 'axis',
        axisPointer: { type: 'shadow' },
        formatter: (params: Array<{ seriesName: string; value: number; axisValue: string }>) => {
          const header = formatDate(params[0]?.axisValue);
          const rows = params
            .filter((p) => p.value > 0)
            .map((p) => `${p.seriesName}: ${p.value}`)
            .join('<br/>');
          return `<strong>${header}</strong><br/>${rows}`;
        },
      },
      legend: {
        bottom: 0,
        itemWidth: 10,
        itemHeight: 10,
        textStyle: { fontSize: 11 },
      },
      grid: {
        left: '3%',
        right: '4%',
        bottom: '12%',
        top: '10%',
        containLabel: true,
      },
      xAxis: {
        type: 'category',
        data: bucketSet.map((b) => formatDate(b)),
        axisLabel: { fontSize: 10, rotate: 30 },
      },
      yAxis: {
        type: 'value',
        name: 'Alert count',
        nameTextStyle: { fontSize: 10 },
        axisLabel: { fontSize: 10 },
        splitLine: { lineStyle: { type: 'dashed' } },
      },
      series,
    }, true);
  }, [data, isLoading, isError, chart]);

  if (isLoading) {
    return (
      <div className="bg-white border border-gray-200 rounded-xl p-5">
        <div className="flex items-center gap-2 mb-3">
          <BarChart3 className="w-4 h-4 text-gray-400 animate-pulse" />
          <h3 className="text-sm font-semibold text-gray-700 animate-pulse">Alert Timeline</h3>
        </div>
        <div className="flex items-center justify-center h-56 bg-gray-50 rounded-lg animate-pulse">
          <div className="w-48 h-48 bg-gray-200 rounded-full" />
        </div>
      </div>
    );
  }

  if (isError) {
    return (
      <div className="bg-white border border-gray-200 rounded-xl p-5">
        <div className="flex items-center gap-2 mb-3">
          <BarChart3 className="w-4 h-4 text-red-500" />
          <h3 className="text-sm font-semibold text-gray-700">Alert Timeline</h3>
        </div>
        <p className="text-sm text-red-600">Failed to load timeline</p>
      </div>
    );
  }

  if (!data || data.length === 0) {
    return (
      <div className="bg-white border border-gray-200 rounded-xl p-5">
        <div className="flex items-center gap-2 mb-3">
          <BarChart3 className="w-4 h-4 text-gray-500" />
          <h3 className="text-sm font-semibold text-gray-700">Alert Timeline</h3>
        </div>
        <div className="flex flex-col items-center justify-center h-56 text-gray-400">
          <BarChart3 className="w-8 h-8 mb-2" />
          <p className="text-sm">No data — alerts will appear here.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white border border-gray-200 rounded-xl p-5">
      <div className="flex items-center gap-2 mb-3">
        <BarChart3 className="w-4 h-4 text-blue-600" />
        <h3 className="text-sm font-semibold text-gray-700">Alert Timeline</h3>
      </div>
      <div ref={chartRef} className="w-full h-56" />
    </div>
  );
}
