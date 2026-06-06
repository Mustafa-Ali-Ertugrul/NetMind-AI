import { useQuery } from '@tanstack/react-query';
import { listArtifacts } from '@/api/jobs';
import type { ArtifactInfo } from '@/types/api';

export function useJobArtifacts(jobId: string | null) {
  return useQuery<ArtifactInfo[]>({
    queryKey: ['job', jobId, 'artifacts'],
    queryFn: () => listArtifacts(jobId!),
    enabled: !!jobId,
  });
}
