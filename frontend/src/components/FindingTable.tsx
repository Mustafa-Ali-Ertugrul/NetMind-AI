import type { AlertResponse } from '@/types/api';
import { severityClass, severityLabel } from '@/lib/severity';
import { formatDate } from '@/lib/format';

interface FindingTableProps {
  alerts: AlertResponse[];
}

export function FindingTable({ alerts }: FindingTableProps) {
  if (alerts.length === 0) {
    return (
      <div className="text-sm text-gray-500 italic py-4 text-center">
        No findings detected.
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="min-w-full text-sm">
        <thead>
          <tr className="border-b border-gray-200">
            <th className="text-left py-2 px-3 font-medium text-gray-500">Severity</th>
            <th className="text-left py-2 px-3 font-medium text-gray-500">Title</th>
            <th className="text-left py-2 px-3 font-medium text-gray-500">Category</th>
            <th className="text-left py-2 px-3 font-medium text-gray-500">Time</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert) => (
            <tr key={alert.id} className="border-b border-gray-100 hover:bg-gray-50">
              <td className="py-2 px-3">
                <span
                  className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${severityClass(alert.severity)}`}
                >
                  {severityLabel(alert.severity)}
                </span>
              </td>
              <td className="py-2 px-3 text-gray-900 max-w-xs truncate" title={alert.description ?? undefined}>
                {alert.title}
              </td>
              <td className="py-2 px-3 text-gray-600">{alert.category}</td>
              <td className="py-2 px-3 text-gray-500 whitespace-nowrap">
                {formatDate(alert.triggered_at)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
