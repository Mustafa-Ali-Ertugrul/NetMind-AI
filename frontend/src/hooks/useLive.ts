import { useQuery, useMutation } from '@tanstack/react-query';
import { getAlerts, getTimeline, getStats, getMetrics, getLiveTalkers, getLiveRiskStream, ingestEvent } from '@/api/live';
import type { AlertListParams, TimelineParams } from '@/types/live';

/** Poll active alerts — most frequently. */
export function useLiveAlerts(params?: AlertListParams) {
  return useQuery({
    queryKey: ['live', 'alerts', params],
    queryFn: () => getAlerts(params),
    refetchInterval: 5_000,
    staleTime: 3_000,
    retry: 2,
  });
}

/** Poll timeline buckets. */
export function useAlertTimeline(params?: TimelineParams) {
  return useQuery({
    queryKey: ['live', 'timeline', params],
    queryFn: () => getTimeline(params),
    refetchInterval: 30_000,
    staleTime: 20_000,
    retry: 2,
  });
}

/** Poll rule statistics. */
export function useRuleStats(params?: { limit?: number }) {
  return useQuery({
    queryKey: ['live', 'stats', params],
    queryFn: () => getStats(params),
    refetchInterval: 30_000,
    staleTime: 20_000,
    retry: 2,
  });
}

/** Poll service health metrics. */
export function useLiveMetrics() {
  return useQuery({
    queryKey: ['live', 'metrics'],
    queryFn: getMetrics,
    refetchInterval: 10_000,
    staleTime: 5_000,
    retry: 2,
  });
}

/** Debug mutation to ingest a test event. */
export function useIngestMutation() {
  return useMutation({
    mutationFn: ingestEvent,
  });
}

/** Poll top talkers every 10 s. */
export function useLiveTalkers(window = '5m', limit = 20) {
  return useQuery({
    queryKey: ['live', 'talkers', window, limit],
    queryFn: () => getLiveTalkers(window, limit),
    refetchInterval: 10_000,
    staleTime: 5_000,
    retry: 2,
  });
}

/** Poll risk-stream every 5 s. */
export function useLiveRiskStream(window = '5m') {
  return useQuery({
    queryKey: ['live', 'risk-stream', window],
    queryFn: () => getLiveRiskStream(window),
    refetchInterval: 5_000,
    staleTime: 2_000,
    retry: 2,
  });
}
