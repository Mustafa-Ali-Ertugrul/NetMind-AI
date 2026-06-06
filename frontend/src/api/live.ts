import apiClient from './client';
import type {
  LiveAlertListResponse,
  TimelineBucketResponse,
  RuleStatsResponse,
  LiveMetricsResponse,
  AlertListParams,
  TimelineParams,
} from '@/types/live';

/** Fetch paginated live alerts with optional filters. */
export async function getAlerts(params?: AlertListParams): Promise<LiveAlertListResponse> {
  const { data } = await apiClient.get<LiveAlertListResponse>('/live/alerts', { params });
  return data;
}

/** Fetch aggregated timeline buckets. */
export async function getTimeline(params?: TimelineParams): Promise<TimelineBucketResponse[]> {
  const { data } = await apiClient.get<TimelineBucketResponse[]>('/live/alerts/timeline', {
    params,
  });
  return data;
}

/** Fetch per-rule statistics. */
export async function getStats(params?: { session_id?: string; limit?: number }): Promise<RuleStatsResponse[]> {
  const { data } = await apiClient.get<RuleStatsResponse[]>('/live/stats', { params });
  return data;
}

/** Fetch live engine health metrics. */
export async function getMetrics(): Promise<LiveMetricsResponse> {
  const { data } = await apiClient.get<LiveMetricsResponse>('/live/metrics');
  return data;
}

/** Send a minimal test event for debug/demo. */
export interface IngestEventBody {
  source_ip: string;
  destination_ip: string;
  protocol: string;
  source_port: number;
  destination_port: number;
  timestamp: number;
  packet_size: number;
  session_id?: string | null;
}

export async function ingestEvent(body: IngestEventBody): Promise<{ session_id: string }> {
  const { data } = await apiClient.post<{ session_id: string }>('/live/ingest', body);
  return data;
}
