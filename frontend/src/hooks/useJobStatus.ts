import { useQuery } from '@tanstack/react-query';
import { getJobStatus } from '@/api/jobs';
import type { JobStatusResponse } from '@/types/api';

export function useJobStatus(jobId: string | null) {
  return useQuery<JobStatusResponse>({
    queryKey: ['job', jobId],
    queryFn: () => getJobStatus(jobId!),
    enabled: !!jobId,
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      if (!status || status === 'completed' || status === 'failed') {
        return false; // stop polling
      }
      return 1500; // poll every 1.5s
    },
  });
}
