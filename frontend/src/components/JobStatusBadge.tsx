import { statusClass, severityLabel } from '@/lib/severity';

interface JobStatusBadgeProps {
  status: string;
}

export function JobStatusBadge({ status }: JobStatusBadgeProps) {
  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${statusClass(status)}`}>
      {severityLabel(status)}
    </span>
  );
}
