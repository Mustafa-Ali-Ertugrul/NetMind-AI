import type { RuleStatsResponse } from '@/types/live';
import { formatDate } from '@/lib/format';
import { Table, Target, Crosshair, CheckCircle2, XCircle } from 'lucide-react';

interface RuleStatisticsProps {
  data?: RuleStatsResponse[];
  isLoading: boolean;
  isError: boolean;
  error: Error | null;
}

export function RuleStatistics({ data, isLoading, isError, error }: RuleStatisticsProps) {
  if (isLoading) {
    return (
      <div className="bg-white border border-gray-200 rounded-xl p-5">
        <div className="flex items-center gap-2 mb-3">
          <Table className="w-4 h-4 text-gray-400 animate-pulse" />
          <h3 className="text-sm font-semibold text-gray-700 animate-pulse">Rule Statistics</h3>
        </div>
        <div className="space-y-2">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="h-8 bg-gray-100 rounded-lg animate-pulse" />
          ))}
        </div>
      </div>
    );
  }

  if (isError) {
    return (
      <div className="bg-white border border-gray-200 rounded-xl p-5">
        <div className="flex items-center gap-2 mb-3">
          <Table className="w-4 h-4 text-red-500" />
          <h3 className="text-sm font-semibold text-gray-700">Rule Statistics</h3>
        </div>
        <p className="text-sm text-red-600">{error?.message ?? 'Failed to load stats'}</p>
      </div>
    );
  }

  const rows = data ?? [];

  return (
    <div className="bg-white border border-gray-200 rounded-xl p-5">
      <div className="flex items-center gap-2 mb-3">
        <Table className="w-4 h-4 text-blue-600" />
        <h3 className="text-sm font-semibold text-gray-700">Rule Statistics</h3>
      </div>

      {rows.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-8 text-gray-400">
          <Target className="w-8 h-8 mb-2" />
          <p className="text-sm">No rule activity yet.</p>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="min-w-full text-sm">
            <thead>
              <tr className="text-left text-gray-500 border-b border-gray-100">
                <th className="pb-2 font-medium">Rule</th>
                <th className="pb-2 font-medium text-center">
                  <Crosshair className="w-3 h-3 inline mr-0.5" />
                  Hits
                </th>
                <th className="pb-2 font-medium text-center">
                  <XCircle className="w-3 h-3 inline mr-0.5" />
                  Miss
                </th>
                <th className="pb-2 font-medium text-center">
                  <CheckCircle2 className="w-3 h-3 inline mr-0.5" />
                  Ratio
                </th>
                <th className="pb-2 font-medium text-center">Max Risk</th>
                <th className="pb-2 font-medium">Last Fired</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-50">
              {rows.map((row) => (
                <tr key={`${row.rule_id}-${row.session_id ?? ''}`}>
                  <td className="py-2 font-mono text-xs text-gray-700">{row.rule_id}</td>
                  <td className="py-2 text-center text-gray-700">{row.hits}</td>
                  <td className="py-2 text-center text-gray-500">{row.miss}</td>
                  <td className="py-2 text-center text-gray-700">{(row.hit_ratio * 100).toFixed(0)}%</td>
                  <td className="py-2 text-center">
                    <span
                      className={`inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                        row.max_risk_score >= 80
                          ? 'bg-red-50 text-red-700'
                          : row.max_risk_score >= 50
                            ? 'bg-amber-50 text-amber-700'
                            : 'bg-gray-50 text-gray-700'
                      }`}
                    >
                      {row.avg_risk_score.toFixed(0)} <span className="mx-0.5 opacity-60">/</span>{' '}
                      {row.max_risk_score.toFixed(0)}
                    </span>
                  </td>
                  <td className="py-2 text-gray-500 text-xs">{formatDate(row.last_evaluation_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
