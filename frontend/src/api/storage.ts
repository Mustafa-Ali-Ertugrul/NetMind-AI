import apiClient from './client';
import type { StorageStatus, CleanupResult } from '@/types/api';

/** Fetch aggregate storage status. */
export async function getStorageStatus(): Promise<StorageStatus> {
  const { data } = await apiClient.get<StorageStatus>('/storage/status');
  return data;
}

/** Trigger a manual storage cleanup. */
export async function runCleanup(): Promise<CleanupResult> {
  const { data } = await apiClient.post<CleanupResult>('/storage/cleanup');
  return data;
}
