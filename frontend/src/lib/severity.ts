import type { Severity } from '@/types/api';

export function severityClass(severity: string): string {
  const s = severity.toLowerCase();
  const valid: Severity[] = ['critical', 'high', 'medium', 'low', 'informational'];
  return valid.includes(s as Severity) ? `severity-${s}` : 'severity-informational';
}

export function statusClass(status: string): string {
  const normalized = status.toLowerCase();
  return `status-${normalized}`;
}

export function severityLabel(severity: string): string {
  return severity.charAt(0).toUpperCase() + severity.slice(1);
}
