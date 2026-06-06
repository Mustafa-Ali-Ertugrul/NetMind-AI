import { useLiveAlerts, useAlertTimeline, useRuleStats, useLiveMetrics } from '@/hooks/useLive';
import { ActiveAlerts, AlertTimeline, RuleStatistics, ServiceMetrics } from '@/components/live';
import { Radio } from 'lucide-react';

export function LiveMonitorPage() {
  const alerts = useLiveAlerts({ status: 'open', limit: 50 });
  const timeline = useAlertTimeline({ bucket: 'hour', hours: 24 });
  const stats = useRuleStats({ limit: 20 });
  const metrics = useLiveMetrics();

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      <div>
        <div className="flex items-center gap-2">
          <Radio className="w-5 h-5 text-red-500" />
          <h2 className="text-xl font-bold text-gray-900">Live Monitor</h2>
        </div>
        <p className="text-sm text-gray-500">Real-time streaming alerts, timeline, and engine health</p>
      </div>

      {/* Top row: Metrics bar */}
      <ServiceMetrics
        data={metrics.data}
        isLoading={metrics.isLoading}
        isError={metrics.isError}
        error={metrics.error as Error | null}
      />

      {/* Middle row: Alerts + Timeline side by side */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <ActiveAlerts
          data={alerts.data?.items}
          total={alerts.data?.total}
          isLoading={alerts.isLoading}
          isError={alerts.isError}
          error={alerts.error as Error | null}
        />
        <AlertTimeline
          data={timeline.data}
          isLoading={timeline.isLoading}
          isError={timeline.isError}
        />
      </div>

      {/* Bottom row: Rule stats full width */}
      <RuleStatistics
        data={stats.data}
        isLoading={stats.isLoading}
        isError={stats.isError}
        error={stats.error as Error | null}
      />
    </div>
  );
}
