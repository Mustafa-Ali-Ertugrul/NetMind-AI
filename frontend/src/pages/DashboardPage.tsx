import { useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import * as echarts from 'echarts/core';
import { PieChart, GaugeChart } from 'echarts/charts';
import { CanvasRenderer } from 'echarts/renderers';
import { TitleComponent, TooltipComponent, LegendComponent } from 'echarts/components';
import type { ECharts } from 'echarts/core';
import { useJobs } from '@/hooks/useJobs';
import { useStorageStatus } from '@/hooks/useStorageStatus';
import { formatDate, formatBytes } from '@/lib/format';
import { Loader2, AlertCircle, Activity, CheckCircle2, XCircle } from 'lucide-react';

echarts.use([PieChart, GaugeChart, CanvasRenderer, TitleComponent, TooltipComponent, LegendComponent]);

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

export function DashboardPage() {
  const jobs = useJobs(50);
  const storage = useStorageStatus();

  const gaugeRef = useRef<HTMLDivElement>(null);
  const pieRef = useRef<HTMLDivElement>(null);
  const gaugeChart = useChartInit(gaugeRef);
  const pieChart = useChartInit(pieRef);

  useEffect(() => {
    if (storage.data && gaugeChart.current) {
      const pct = storage.data.disk.percent;
      gaugeChart.current.setOption({
        series: [{
          type: 'gauge',
          startAngle: 180,
          endAngle: 0,
          min: 0,
          max: 100,
          splitNumber: 5,
          itemStyle: { color: pct > 80 ? '#ef4444' : '#3b82f6' },
          progress: { show: true, width: 18 },
          pointer: { show: false },
          axisLine: { lineStyle: { width: 18 } },
          axisTick: { show: false },
          splitLine: { length: 8, lineStyle: { width: 2, color: '#999' } },
          axisLabel: { distance: 14, fontSize: 10, color: '#666' },
          detail: {
            valueAnimation: true,
            fontSize: 20,
            fontWeight: 'bold',
            offsetCenter: [0, '30%'],
            formatter: '{value}%',
            color: 'inherit',
          },
          data: [{ value: Number(pct.toFixed(1)), name: 'Disk Used' }],
        }],
      }, true);
    }
  }, [storage.data, gaugeChart]);

  useEffect(() => {
    if (jobs.data && pieChart.current) {
      const counts: Record<string, number> = {};
      jobs.data.forEach((j) => { counts[j.status] = (counts[j.status] || 0) + 1; });
      const data = Object.entries(counts).map(([name, value]) => ({ name, value }));
      pieChart.current.setOption({
        tooltip: { trigger: 'item' },
        legend: { bottom: '0%', left: 'center', itemWidth: 10, itemHeight: 10, textStyle: { fontSize: 11 } },
        series: [{
          type: 'pie',
          radius: ['40%', '65%'],
          center: ['50%', '45%'],
          avoidLabelOverlap: false,
          itemStyle: { borderRadius: 6, borderColor: '#fff', borderWidth: 2 },
          label: { show: false },
          emphasis: { label: { show: true, fontSize: 12, fontWeight: 'bold' } },
          data,
        }],
      }, true);
    }
  }, [jobs.data, pieChart]);

  if (jobs.isLoading || storage.isLoading) {
    return (
      <div className="flex items-center gap-2 text-gray-500 py-12 justify-center">
        <Loader2 className="w-5 h-5 animate-spin" />
        Loading dashboard…
      </div>
    );
  }

  if (jobs.isError || storage.isError) {
    return (
      <div className="max-w-2xl mx-auto text-center py-12">
        <AlertCircle className="w-10 h-10 text-red-400 mx-auto mb-3" />
        <p className="text-sm text-red-600">{(jobs.error ?? storage.error)?.message ?? 'Failed to load dashboard'}</p>
      </div>
    );
  }

  const jobList = jobs.data!;
  const total = jobList.length;
  const completed = jobList.filter((j) => j.status === 'completed').length;
  const failed = jobList.filter((j) => j.status === 'failed').length;
  const running = jobList.filter((j) => !['completed', 'failed'].includes(j.status)).length;

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      <div>
        <h2 className="text-xl font-bold text-gray-900">Dashboard</h2>
        <p className="text-sm text-gray-500">Overview of storage, jobs, and system health</p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="bg-white border border-gray-200 rounded-xl p-4 flex items-start gap-3">
          <div className="p-2 bg-blue-50 rounded-lg"><Activity className="w-5 h-5 text-blue-600" /></div>
          <div><p className="text-xs text-gray-500">Total Jobs</p><p className="text-lg font-semibold text-gray-900">{total}</p></div>
        </div>
        <div className="bg-white border border-gray-200 rounded-xl p-4 flex items-start gap-3">
          <div className="p-2 bg-green-50 rounded-lg"><CheckCircle2 className="w-5 h-5 text-green-600" /></div>
          <div><p className="text-xs text-gray-500">Completed</p><p className="text-lg font-semibold text-gray-900">{completed}</p></div>
        </div>
        <div className="bg-white border border-gray-200 rounded-xl p-4 flex items-start gap-3">
          <div className="p-2 bg-red-50 rounded-lg"><XCircle className="w-5 h-5 text-red-600" /></div>
          <div><p className="text-xs text-gray-500">Failed</p><p className="text-lg font-semibold text-gray-900">{failed}</p></div>
        </div>
        <div className="bg-white border border-gray-200 rounded-xl p-4 flex items-start gap-3">
          <div className="p-2 bg-amber-50 rounded-lg"><Loader2 className="w-5 h-5 text-amber-600 animate-spin" /></div>
          <div><p className="text-xs text-gray-500">Running</p><p className="text-lg font-semibold text-gray-900">{running}</p></div>
        </div>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-white border border-gray-200 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-gray-700 mb-2">Disk Usage</h3>
          <div ref={gaugeRef} className="w-full h-56" />
          <p className="text-xs text-gray-500 text-center mt-1">
            {formatBytes(storage.data!.disk.used_gb * 1024 ** 3)} / {formatBytes(storage.data!.disk.total_gb * 1024 ** 3)}
          </p>
        </div>
        <div className="bg-white border border-gray-200 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-gray-700 mb-2">Job Status Distribution</h3>
          <div ref={pieRef} className="w-full h-56" />
        </div>
      </div>

      {/* Recent jobs */}
      <div className="bg-white border border-gray-200 rounded-xl p-5">
        <h3 className="text-sm font-semibold text-gray-700 mb-3">Recent Jobs</h3>
        {jobList.length === 0 ? (
          <p className="text-sm text-gray-500">No jobs yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead>
                <tr className="text-left text-gray-500 border-b border-gray-100">
                  <th className="pb-2 font-medium">ID</th>
                  <th className="pb-2 font-medium">Status</th>
                  <th className="pb-2 font-medium">Model</th>
                  <th className="pb-2 font-medium">Created</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-50">
                {jobList.slice(0, 10).map((j) => (
                  <tr key={j.id}>
                    <td className="py-2">
                      <Link to={`/jobs/${j.id}`} className="font-mono text-blue-600 hover:underline text-xs">
                        {j.id.slice(0, 8)}…
                      </Link>
                    </td>
                    <td className="py-2">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${
                        j.status === 'completed' ? 'bg-green-50 text-green-700' :
                        j.status === 'failed' ? 'bg-red-50 text-red-700' :
                        'bg-amber-50 text-amber-700'
                      }`}>
                        {j.status}
                      </span>
                    </td>
                    <td className="py-2 text-gray-600">{j.model_used ?? '—'}</td>
                    <td className="py-2 text-gray-500">{formatDate(j.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
