import { useQuery } from '@tanstack/react-query';
import { getJobResult } from '@/api/jobs';
import type { AnalysisResultResponse } from '@/types/api';

export function useJobResult(jobId: string | null) {
  return useQuery<AnalysisResultResponse>({
    queryKey: ['jobResult', jobId],
    queryFn: () => getJobResult(jobId!),
    enabled: !!jobId,
    retry: false,
  });
}
