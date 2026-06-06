import { useState } from 'react';
import type { LiveTalkerItem } from '@/types/live';
import { ArrowUpDown, ArrowUp, ArrowDown, RadioTower } from 'lucide-react';

interface LiveTopTalkersProps {
  data?: LiveTalkerItem[];
  isLoading: boolean;
  isError: boolean;
}

type SortKey = 'ip' | 'direction' | 'bytes' | 'packets';

function SortIcon({ col, sortKey, sortAsc }: { col: SortKey; sortKey: SortKey; sortAsc: boolean }) {
  if (sortKey !== col) return <ArrowUpDown className="w-3 h-3 inline ml-0.5 opacity-30" />;
  return sortAsc
    ? <ArrowUp className="w-3 h-3 inline ml-0.5" />
    : <ArrowDown className="w-3 h-3 inline ml-0.5" />;
}

export function LiveTopTalkers({ data, isLoading, isError }: LiveTopTalkersProps) {
  const [sortKey, setSortKey] = useState<SortKey>('bytes');
  const [sortAsc, setSortAsc] = useState(false);

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortAsc((prev) => !prev);
    } else {
      setSortKey(key);
      setSortAsc(key === 'ip');
    }
  };

  if (isLoading) {
    return (
      <div className="bg-white border border-gray-200 rounded-xl p-5">
        <div className="flex items-center gap-2 mb-3">
          <RadioTower className="w-4 h-4 text-gray-400 animate-pulse" />
          <h3 className="text-sm font-semibold text-gray-700 animate-pulse">Top Talkers</h3>
        </div>
        <div className="space-y-2">
          {Array.from({ length: 5 }).map((_, i) => (
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
          <RadioTower className="w-4 h-4 text-red-500" />
          <h3 className="text-sm font-semibold text-gray-700">Top Talkers</h3>
        </div>
        <p className="text-sm text-red-600">Failed to load talkers</p>
      </div>
    );
  }

  const rows = data ?? [];

  if (rows.length === 0) {
    return (
      <div className="bg-white border border-gray-200 rounded-xl p-5">
        <div className="flex items-center gap-2 mb-3">
          <RadioTower className="w-4 h-4 text-blue-600" />
          <h3 className="text-sm font-semibold text-gray-700">Top Talkers</h3>
        </div>
        <div className="flex flex-col items-center justify-center py-8 text-gray-400">
          <RadioTower className="w-8 h-8 mb-2" />
          <p className="text-sm">No talker data yet.</p>
        </div>
      </div>
    );
  }

  const sorted = [...rows].sort((a, b) => {
    const mul = sortAsc ? 1 : -1;
    if (sortKey === 'ip') return mul * a.ip.localeCompare(b.ip);
    if (sortKey === 'direction') return mul * a.direction.localeCompare(b.direction);
    return mul * (a[sortKey] - b[sortKey]);
  });

  return (
    <div className="bg-white border border-gray-200 rounded-xl p-5">
      <div className="flex items-center gap-2 mb-3">
        <RadioTower className="w-4 h-4 text-blue-600" />
        <h3 className="text-sm font-semibold text-gray-700">Top Talkers</h3>
        <span className="text-xs text-gray-400 ml-auto">{rows.length} IPs</span>
      </div>

      <div className="overflow-x-auto">
        <table className="min-w-full text-sm">
          <thead>
            <tr className="text-left text-gray-500 border-b border-gray-100">
              <th
                className="pb-2 font-medium cursor-pointer select-none hover:text-gray-700"
                onClick={() => toggleSort('ip')}
              >
                IP <SortIcon col="ip" sortKey={sortKey} sortAsc={sortAsc} />
              </th>
              <th
                className="pb-2 font-medium cursor-pointer select-none hover:text-gray-700"
                onClick={() => toggleSort('direction')}
              >
                Dir <SortIcon col="direction" sortKey={sortKey} sortAsc={sortAsc} />
              </th>
              <th
                className="pb-2 font-medium text-right cursor-pointer select-none hover:text-gray-700"
                onClick={() => toggleSort('bytes')}
              >
                Bytes <SortIcon col="bytes" sortKey={sortKey} sortAsc={sortAsc} />
              </th>
              <th
                className="pb-2 font-medium text-right cursor-pointer select-none hover:text-gray-700"
                onClick={() => toggleSort('packets')}
              >
                Packets <SortIcon col="packets" sortKey={sortKey} sortAsc={sortAsc} />
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-50">
            {sorted.map((row) => (
              <tr key={row.ip} className="hover:bg-gray-50 transition-colors">
                <td className="py-2 font-mono text-xs text-gray-800">{row.ip}</td>
                <td className="py-2">
                  <span
                    className={`inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wide ${
                      row.direction === 'src'
                        ? 'bg-blue-50 text-blue-700'
                        : 'bg-purple-50 text-purple-700'
                    }`}
                  >
                    {row.direction}
                  </span>
                </td>
                <td className="py-2 text-right font-mono text-xs text-gray-700">
                  {(row.bytes / 1024).toFixed(1)} KB
                </td>
                <td className="py-2 text-right font-mono text-xs text-gray-700">
                  {row.packets.toLocaleString()}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
