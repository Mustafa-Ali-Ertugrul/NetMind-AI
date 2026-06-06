import { useQuery } from '@tanstack/react-query';
import { getStorageStatus } from '@/api/storage';
import type { StorageStatus } from '@/types/api';

export function useStorageStatus() {
  return useQuery<StorageStatus>({
    queryKey: ['storage', 'status'],
    queryFn: getStorageStatus,
    refetchInterval: 10_000,
  });
}
