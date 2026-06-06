import { useQuery } from '@tanstack/react-query';
import { getJobTalkers } from '@/api/jobs';
import type { TopTalkersResult } from '@/types/api';

export function useJobTalkers(jobId: string | null) {
  return useQuery<TopTalkersResult>({
    queryKey: ['jobTalkers', jobId],
    queryFn: () => getJobTalkers(jobId!),
    enabled: !!jobId,
    retry: false,
  });
}
