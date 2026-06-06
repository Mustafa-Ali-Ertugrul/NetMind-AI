import { useMutation, useQueryClient } from '@tanstack/react-query';
import { runCleanup } from '@/api/storage';
import type { CleanupResult } from '@/types/api';

export function useCleanup() {
  const qc = useQueryClient();
  return useMutation<CleanupResult, Error, void>({
    mutationFn: runCleanup,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['storage', 'status'] });
    },
  });
}
