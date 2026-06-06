import { useMemo } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import {
  getAlerts,
  getTimeline,
  getStats,
  getMetrics,
  getLiveTalkers,
  getLiveRiskStream,
  ingestEvent,
} from '@/api/live';
import {
  useDemoAlerts,
  useDemoTalkers,
  useDemoRisk,
} from '@/demo/demoController';
import type {
  AlertListParams,
  TimelineParams,
  LiveAlertListResponse,
  LiveTalkersResponse,
  RiskStreamResponse,
} from '@/types/live';

/** Poll active alerts + merge demo overlay. */
export function useLiveAlerts(params?: AlertListParams) {
  const real = useQuery({
    queryKey: ['live', 'alerts', params],
    queryFn: () => getAlerts(params),
    refetchInterval: 5_000,
    staleTime: 3_000,
    retry: 2,
  });
  const demo = useDemoAlerts();

  const data = useMemo<LiveAlertListResponse | undefined>(() => {
    if (!demo.length) return real.data;
    if (!real.data) return { items: demo, total: demo.length, limit: 50, offset: 0 };
    return {
      ...real.data,
      items: [...demo, ...real.data.items],
      total: real.data.total + demo.length,
    };
  }, [real.data, demo]);

  return { ...real, data };
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

/** Poll top talkers + merge demo overlay. */
export function useLiveTalkers(window = '5m', limit = 20) {
  const real = useQuery({
    queryKey: ['live', 'talkers', window, limit],
    queryFn: () => getLiveTalkers(window, limit),
    refetchInterval: 10_000,
    staleTime: 7_000,
    retry: 2,
  });
  const demo = useDemoTalkers();

  const data = useMemo<LiveTalkersResponse | undefined>(() => {
    if (!demo.length) return real.data;
    if (!real.data) return { window, talkers: demo };
    return { ...real.data, talkers: [...demo, ...real.data.talkers] };
  }, [real.data, demo, window]);

  return { ...real, data };
}

/** Poll risk-stream + overlay demo snapshot. */
export function useLiveRiskStream(window = '5m') {
  const real = useQuery({
    queryKey: ['live', 'risk-stream', window],
    queryFn: () => getLiveRiskStream(window),
    refetchInterval: 5_000,
    staleTime: 3_000,
    retry: 2,
  });
  const demo = useDemoRisk();

  const data = useMemo<RiskStreamResponse | undefined>(() => {
    if (!demo || !real.data) return real.data;
    return { ...real.data, current: demo };
  }, [real.data, demo]);

  return { ...real, data };
}
