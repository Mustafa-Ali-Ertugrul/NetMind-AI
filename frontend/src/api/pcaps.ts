import apiClient from './client';
import type { UploadResponse, JobStatusResponse } from '@/types/api';

/** Upload a PCAP file. Returns upload metadata + job_id for polling. */
export async function uploadPcap(file: File): Promise<UploadResponse> {
  const form = new FormData();
  form.append('file', file);
  const { data } = await apiClient.post<UploadResponse>('/pcaps', form);
  return data;
}

/** Get detailed PCAP metadata, including analysis_jobs. */
export async function getPcapDetail(pcapId: string) {
  const { data } = await apiClient.get(`/pcaps/${pcapId}`);
  return data;
}

/** Download the original PCAP file. */
export function getPcapDownloadUrl(pcapId: string): string {
  return `/api/v1/pcaps/${pcapId}/download`;
}

/** Delete a PCAP (soft-delete). */
export async function deletePcap(pcapId: string): Promise<void> {
  await apiClient.delete(`/pcaps/${pcapId}`);
}

/** List all jobs for a given PCAP. */
export async function listJobsForPcap(pcapId: string): Promise<JobStatusResponse[]> {
  const { data } = await apiClient.get<JobStatusResponse[]>(`/jobs/by_pcap/${pcapId}`);
  return data;
}
