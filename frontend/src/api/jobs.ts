import apiClient from './client';
import type { JobStatusResponse, AnalysisResultResponse, TopTalkersResult } from '@/types/api';

/** Poll a single job's status. */
export async function getJobStatus(jobId: string): Promise<JobStatusResponse> {
  const { data } = await apiClient.get<JobStatusResponse>(`/jobs/${jobId}`);
  return data;
}

/** Get the full analysis result for a completed job. */
export async function getJobResult(jobId: string): Promise<AnalysisResultResponse> {
  const { data } = await apiClient.get<AnalysisResultResponse>(`/jobs/${jobId}/result`);
  return data;
}

/** Get top talkers for a job. */
export async function getJobTalkers(jobId: string, limit = 10): Promise<TopTalkersResult> {
  const { data } = await apiClient.get<TopTalkersResult>(`/jobs/${jobId}/talkers`, {
    params: { limit },
  });
  return data;
}

/** Get artifact metadata list for a job. */
export async function listArtifacts(jobId: string) {
  const { data } = await apiClient.get(`/jobs/${jobId}/artifacts`);
  return data;
}

/** List recent analysis jobs. */
export async function listJobs(limit = 50): Promise<JobStatusResponse[]> {
  const { data } = await apiClient.get<JobStatusResponse[]>('/jobs', { params: { limit } });
  return data;
}

/** Get artifact download URL. */
export function getArtifactDownloadUrl(jobId: string, filename: string): string {
  return `/api/v1/jobs/${jobId}/artifacts/${filename}`;
}
