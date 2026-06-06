import type { LiveAlertResponse } from '@/types/live';
import { formatDate } from '@/lib/format';
import { Shield, ShieldAlert, Activity } from 'lucide-react';

function severityClass(sev: string): string {
  switch (sev.toLowerCase()) {
    case 'critical':
      return 'bg-red-50 text-red-700';
    case 'high':
      return 'bg-red-50 text-red-600';
    case 'medium':
      return 'bg-amber-50 text-amber-700';
    case 'low':
      return 'bg-blue-50 text-blue-700';
    default:
      return 'bg-gray-50 text-gray-700';
  }
}

function statusClass(st: string): string {
  switch (st.toLowerCase()) {
    case 'open':
      return 'bg-red-50 text-red-600';
    case 'acked':
      return 'bg-yellow-50 text-yellow-700';
    case 'resolved':
      return 'bg-green-50 text-green-700';
    default:
      return 'bg-gray-50 text-gray-700';
  }
}

interface ActiveAlertsProps {
  data?: LiveAlertResponse[];
  total?: number;
  isLoading: boolean;
  isError: boolean;
  error: Error | null;
}

export function ActiveAlerts({ data, total, isLoading, isError, error }: ActiveAlertsProps) {
  if (isLoading) {
    return (
      <div className="bg-white border border-gray-200 rounded-xl p-5 space-y-3">
        <div className="flex items-center gap-2 mb-3">
          <ShieldAlert className="w-4 h-4 text-gray-400 animate-pulse" />
          <h3 className="text-sm font-semibold text-gray-700 animate-pulse">Loading alerts…</h3>
        </div>
        <div className="space-y-2">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="h-16 bg-gray-100 rounded-lg animate-pulse" />
          ))}
        </div>
      </div>
    );
  }

  if (isError) {
    return (
      <div className="bg-white border border-gray-200 rounded-xl p-5">
        <div className="flex items-center gap-2 mb-3">
          <ShieldAlert className="w-4 h-4 text-red-500" />
          <h3 className="text-sm font-semibold text-gray-700">Active Alerts</h3>
        </div>
        <p className="text-sm text-red-600">{error?.message ?? 'Failed to load alerts'}</p>
      </div>
    );
  }

  const alerts = [...(data ?? [])].sort((a, b) => b.risk_score - a.risk_score);

  return (
    <div className="bg-white border border-gray-200 rounded-xl p-5">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-red-500" />
          <h3 className="text-sm font-semibold text-gray-700">Active Alerts</h3>
        </div>
        <span className="text-xs text-gray-500">{total ?? alerts.length} total</span>
      </div>

      {alerts.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-8 text-gray-400">
          <Shield className="w-8 h-8 mb-2" />
          <p className="text-sm">No alerts — all quiet.</p>
        </div>
      ) : (
        <div className="space-y-2 max-h-96 overflow-y-auto">
          {alerts.slice(0, 20).map((alert) => (
            <div
              key={alert.id}
              className="border border-gray-100 rounded-lg p-3 hover:bg-gray-50 transition-colors"
            >
              <div className="flex items-center justify-between mb-1">
                <div className="flex items-center gap-2">
                  <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wide ${severityClass(alert.severity)}`}>
                    {alert.severity}
                  </span>
                  {alert.severity?.toLowerCase() === 'critical' && (
                    <span className="relative flex h-2 w-2 ml-0.5">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75" />
                      <span className="relative inline-flex rounded-full h-2 w-2 bg-red-500" />
                    </span>
                  )}
                  <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wide ${statusClass(alert.status)}`}>
                    {alert.status}
                  </span>
                </div>
                <span className="text-xs text-gray-400">{formatDate(alert.triggered_at)}</span>
              </div>
              <h4 className="text-sm font-medium text-gray-900 truncate">{alert.title}</h4>
              {alert.description && (
                <p className="text-xs text-gray-500 mt-0.5 line-clamp-2">{alert.description}</p>
              )}
              <div className="flex items-center gap-3 mt-2 text-[10px] text-gray-400">
                <span className="font-mono">{alert.rule_id}</span>
                <span className="flex items-center gap-1">
                  <Activity className="w-3 h-3" />
                  score {alert.risk_score}
                </span>
                <span>{alert.confidence}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
