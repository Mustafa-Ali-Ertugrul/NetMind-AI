import { useQuery } from '@tanstack/react-query';
import { listJobs } from '@/api/jobs';
import type { JobStatusResponse } from '@/types/api';

export function useJobs(limit = 50) {
  return useQuery<JobStatusResponse[]>({
    queryKey: ['jobs', 'list', limit],
    queryFn: () => listJobs(limit),
    refetchInterval: 5_000,
  });
}
