import { useEffect } from 'react';
import { toast } from 'sonner';
import { useStorageStatus } from '@/hooks/useStorageStatus';
import { useCleanup } from '@/hooks/useCleanup';
import { formatBytes } from '@/lib/format';
import { Loader2, AlertCircle, Trash2, Database, HardDrive, Archive, Clock } from 'lucide-react';

function DiskBar({ used, total, percent, overThreshold }: { used: number; total: number; percent: number; overThreshold: boolean }) {
  return (
    <div className="space-y-2">
      <div className="flex justify-between text-sm">
        <span className="text-gray-600">Disk Usage</span>
        <span className={`font-medium ${overThreshold ? 'text-red-600' : 'text-gray-900'}`}>
          {percent.toFixed(1)}% ({used.toFixed(1)} / {total.toFixed(1)} GB)
        </span>
      </div>
      <div className="w-full h-3 bg-gray-100 rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full transition-all ${overThreshold ? 'bg-red-500' : 'bg-blue-500'}`}
          style={{ width: `${Math.min(percent, 100)}%` }}
        />
      </div>
    </div>
  );
}

function StatCard({ icon: Icon, label, value, sub }: { icon: React.ElementType; label: string; value: string | number; sub?: string }) {
  return (
    <div className="bg-white border border-gray-200 rounded-xl p-4 flex items-start gap-3">
      <div className="p-2 bg-gray-50 rounded-lg">
        <Icon className="w-5 h-5 text-gray-600" />
      </div>
      <div>
        <p className="text-xs text-gray-500">{label}</p>
        <p className="text-lg font-semibold text-gray-900">{value}</p>
        {sub && <p className="text-xs text-gray-400 mt-0.5">{sub}</p>}
      </div>
    </div>
  );
}

export function StorageStatusPage() {
  const status = useStorageStatus();
  const cleanup = useCleanup();

  useEffect(() => {
    if (cleanup.isSuccess) {
      toast.success(`Cleanup done: ${cleanup.data.files_deleted} files deleted`);
    }
  }, [cleanup.isSuccess, cleanup.data]);

  useEffect(() => {
    if (cleanup.isError) {
      toast.error(cleanup.error?.message ?? 'Cleanup failed');
    }
  }, [cleanup.isError, cleanup.error]);

  if (status.isLoading) {
    return (
      <div className="flex items-center gap-2 text-gray-500 py-12 justify-center">
        <Loader2 className="w-5 h-5 animate-spin" />
        Loading storage status…
      </div>
    );
  }

  if (status.isError) {
    return (
      <div className="max-w-2xl mx-auto text-center py-12">
        <AlertCircle className="w-10 h-10 text-red-400 mx-auto mb-3" />
        <p className="text-sm text-red-600">{status.error?.message ?? 'Failed to load storage status'}</p>
      </div>
    );
  }

  const s = status.data!;

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-gray-900">Storage</h2>
          <p className="text-sm text-gray-500">Disk usage, file counts, and lifecycle</p>
        </div>
        <button
          onClick={() => cleanup.mutate()}
          disabled={cleanup.isPending}
          className="inline-flex items-center gap-2 px-4 py-2 bg-red-50 text-red-700 rounded-lg text-sm font-medium hover:bg-red-100 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          {cleanup.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />}
          Run Cleanup
        </button>
      </div>

      {cleanup.isSuccess && (
        <div className="bg-green-50 border border-green-200 rounded-xl p-4 text-sm text-green-800">
          Cleanup complete: {cleanup.data.files_deleted} files deleted, {cleanup.data.artifacts_deleted} artifacts removed.
          {cleanup.data.errors.length > 0 && (
            <ul className="mt-2 list-disc list-inside text-red-700">
              {cleanup.data.errors.map((e, i) => (
                <li key={i}>{e}</li>
              ))}
            </ul>
          )}
        </div>
      )}

      <div className="bg-white border border-gray-200 rounded-xl p-5 space-y-4">
        <div className="flex items-center gap-2">
          <HardDrive className="w-5 h-5 text-gray-600" />
          <h3 className="text-sm font-semibold text-gray-700">Disk</h3>
        </div>
        <DiskBar used={s.disk.used_gb} total={s.disk.total_gb} percent={s.disk.percent} overThreshold={s.disk.over_threshold} />
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        <StatCard
          icon={Database}
          label="PCAP Files"
          value={s.pcap_count}
          sub={formatBytes(s.pcap_total_bytes)}
        />
        <StatCard
          icon={Archive}
          label="Artifacts"
          value={s.artifact_count}
        />
        <StatCard
          icon={Clock}
          label="Expired PCAPs"
          value={s.expired_pcaps}
          sub={`${s.orphan_artifacts} orphan artifacts`}
        />
      </div>
    </div>
  );
}
