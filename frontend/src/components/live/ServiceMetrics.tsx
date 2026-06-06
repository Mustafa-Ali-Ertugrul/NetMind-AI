import { useCallback, useState } from 'react';
import { toast } from 'sonner';
import type { LiveMetricsResponse } from '@/types/live';
import { formatDuration } from '@/lib/format';
import {
  Activity,
  Clock,
  Layers,
  Zap,
  AlertTriangle,
  Wifi,
  Send,
  Loader2,
} from 'lucide-react';
import { useIngestMutation } from '@/hooks/useLive';

interface ServiceMetricsProps {
  data?: LiveMetricsResponse;
  isLoading: boolean;
  isError: boolean;
  error: Error | null;
}

function MetricCard({
  icon: Icon,
  label,
  value,
  color,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  value: string | number;
  color: 'blue' | 'green' | 'amber' | 'red';
}) {
  const colorMap = {
    blue: 'bg-blue-50 text-blue-600',
    green: 'bg-green-50 text-green-600',
    amber: 'bg-amber-50 text-amber-600',
    red: 'bg-red-50 text-red-600',
  };
  return (
    <div className="bg-gray-50 border border-gray-100 rounded-lg p-3 flex items-center gap-3">
      <div className={`p-2 rounded-lg ${colorMap[color]}`}>
        <Icon className="w-4 h-4" />
      </div>
      <div>
        <p className="text-xs text-gray-500">{label}</p>
        <p className="text-sm font-semibold text-gray-900">{value}</p>
      </div>
    </div>
  );
}

export function ServiceMetrics({ data, isLoading, isError, error }: ServiceMetricsProps) {
  const ingest = useIngestMutation();
  const [eventCount, setEventCount] = useState(0);

  const handleIngest = useCallback(() => {
    setEventCount((c) => c + 1);
    const ts = Math.floor(Date.now() / 1000);
    ingest.mutate(
      {
        source_ip: '10.0.0.1',
        destination_ip: '10.0.0.2',
        protocol: 'TCP',
        source_port: 1234,
        destination_port: 80,
        timestamp: ts,
        packet_size: 64,
      },
      {
        onSuccess: (resp) => {
          toast.success('Test event ingested', {
            description: `Session ${resp.session_id.slice(0, 8)}… created`,
          });
        },
        onError: (err) => {
          toast.error('Ingest failed', {
            description: err.message,
          });
        },
      },
    );
  }, [ingest]);

  if (isLoading && !data) {
    return (
      <div className="bg-white border border-gray-200 rounded-xl p-5">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-gray-400 animate-pulse" />
            <h3 className="text-sm font-semibold text-gray-700 animate-pulse">Service Metrics</h3>
          </div>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
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
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-red-500" />
            <h3 className="text-sm font-semibold text-gray-700">Service Metrics</h3>
          </div>
        </div>
        <p className="text-sm text-red-600">{error?.message ?? 'Failed to load metrics'}</p>
      </div>
    );
  }

  const m = data!;

  return (
    <div className="bg-white border border-gray-200 rounded-xl p-5">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Activity className="w-4 h-4 text-blue-600" />
          <h3 className="text-sm font-semibold text-gray-700">Service Metrics</h3>
        </div>
        <button
          type="button"
          disabled={ingest.isPending}
          onClick={handleIngest}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          {ingest.isPending ? (
            <Loader2 className="w-3 h-3 animate-spin" />
          ) : (
            <Send className="w-3 h-3" />
          )}
          Test event
        </button>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
        <MetricCard icon={Clock} label="Uptime" value={formatDuration(m.uptime_seconds)} color="blue" />
        <MetricCard icon={Zap} label="Events processed" value={m.events_processed.toLocaleString()} color="green" />
        <MetricCard icon={AlertTriangle} label="Alerts generated" value={m.alerts_generated.toLocaleString()} color="red" />
        <MetricCard icon={Wifi} label="Active sessions" value={m.active_sessions.toLocaleString()} color="amber" />
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <MetricCard icon={Layers} label="Queue size" value={m.queue_size.toLocaleString()} color="blue" />
        <MetricCard icon={Zap} label="Enqueued" value={m.events_enqueued.toLocaleString()} color="green" />
        <MetricCard icon={AlertTriangle} label="Dropped" value={m.events_dropped.toLocaleString()} color="red" />
        <MetricCard icon={Layers} label="Batches" value={m.batches_processed.toLocaleString()} color="amber" />
      </div>

      {eventCount > 0 && (
        <p className="mt-3 text-[10px] text-gray-400 text-right">{eventCount} debug events sent this session.</p>
      )}
    </div>
  );
}
