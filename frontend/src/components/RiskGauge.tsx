import { useEffect, useRef } from 'react';
import * as echarts from 'echarts/core';
import { GaugeChart } from 'echarts/charts';
import { CanvasRenderer } from 'echarts/renderers';
import { TitleComponent } from 'echarts/components';
import type { ECharts } from 'echarts/core';

echarts.use([GaugeChart, CanvasRenderer, TitleComponent]);

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

export function RiskGauge({ score }: { score: number | null | undefined }) {
  const gaugeRef = useRef<HTMLDivElement>(null);
  const gaugeChart = useChartInit(gaugeRef);

  useEffect(() => {
    if (gaugeChart.current && score !== null && score !== undefined) {
      const clamped = Math.min(100, Math.max(0, score));
      let color = '#22c55e';
      if (clamped >= 80) color = '#ef4444';
      else if (clamped >= 60) color = '#f97316';
      else if (clamped >= 40) color = '#eab308';

      gaugeChart.current.setOption({
        series: [
          {
            type: 'gauge',
            startAngle: 180,
            endAngle: 0,
            min: 0,
            max: 100,
            splitNumber: 5,
            itemStyle: { color },
            progress: { show: true, width: 18 },
            pointer: { show: false },
            axisLine: { lineStyle: { width: 18, color: [[1, '#e5e7eb']] } },
            axisTick: { show: false },
            splitLine: { length: 8, lineStyle: { width: 2, color: '#999' } },
            axisLabel: { distance: 14, fontSize: 10, color: '#666' },
            detail: {
              valueAnimation: true,
              fontSize: 20,
              fontWeight: 'bold',
              offsetCenter: [0, '30%'],
              formatter: '{value}',
              color: 'inherit',
            },
            data: [{ value: clamped, name: 'Risk Score' }],
          },
        ],
      }, true);
    }
  }, [score, gaugeChart]);

  return <div ref={gaugeRef} className="w-full h-48" />;
}
