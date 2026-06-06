import { useEffect, useRef } from 'react';
import * as echarts from 'echarts/core';
import { BarChart } from 'echarts/charts';
import { CanvasRenderer } from 'echarts/renderers';
import { TitleComponent, TooltipComponent, GridComponent } from 'echarts/components';
import type { ECharts, EChartsOption } from 'echarts/core';
import type { TopTalkersResult, TopTalkerItem } from '@/types/api';

echarts.use([BarChart, CanvasRenderer, TitleComponent, TooltipComponent, GridComponent]);

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

function buildBarOption(title: string, items: TopTalkerItem[]): EChartsOption {
  const sorted = [...items].sort((a, b) => b.packets - a.packets).slice(0, 10);
  return {
    title: { text: title, left: 'center', textStyle: { fontSize: 12, fontWeight: 'bold' } },
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    grid: { left: '3%', right: '4%', bottom: '3%', top: '15%', containLabel: true },
    xAxis: { type: 'value', axisLabel: { fontSize: 10 } },
    yAxis: { type: 'category', data: sorted.map((i) => i.key), axisLabel: { fontSize: 10 }, inverse: true },
    series: [
      {
        type: 'bar',
        data: sorted.map((i) => i.packets),
        itemStyle: { borderRadius: [0, 4, 4, 0] },
        barWidth: '60%',
      },
    ],
  };
}

export function TopTalkersPanel({ data }: { data: TopTalkersResult | undefined }) {
  const srcRef = useRef<HTMLDivElement>(null);
  const dstRef = useRef<HTMLDivElement>(null);
  const portRef = useRef<HTMLDivElement>(null);
  const protoRef = useRef<HTMLDivElement>(null);
  const srcChart = useChartInit(srcRef);
  const dstChart = useChartInit(dstRef);
  const portChart = useChartInit(portRef);
  const protoChart = useChartInit(protoRef);

  useEffect(() => {
    if (data) {
      srcChart.current?.setOption(buildBarOption('Top Source IPs', data.src_ips), true);
      dstChart.current?.setOption(buildBarOption('Top Destination IPs', data.dst_ips), true);
      portChart.current?.setOption(buildBarOption('Top Destination Ports', data.dst_ports), true);
      protoChart.current?.setOption(buildBarOption('Protocols', data.protocols), true);
    }
  }, [data, srcChart, dstChart, portChart, protoChart]);

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      <div ref={srcRef} className="w-full h-56" />
      <div ref={dstRef} className="w-full h-56" />
      <div ref={portRef} className="w-full h-56" />
      <div ref={protoRef} className="w-full h-56" />
    </div>
  );
}
