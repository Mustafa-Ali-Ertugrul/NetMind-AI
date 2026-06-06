/** Mirrors backend Pydantic responses. Hand-typed until openapi-typescript supports TS 6. */

export interface UploadResponse {
  id: string;
  filename: string;
  original_name: string;
  file_size: number;
  sha256: string;
  status: string;
  job_id: string | null;
  deduplicated: boolean;
  uploaded_at: string;
  last_accessed_at: string | null;
  expires_at: string | null;
  deleted_at: string | null;
  note: string;
}

export interface JobStatusResponse {
  id: string;
  pcap_id: string;
  status: string;
  worker_id: string | null;
  started_at: string | null;
  completed_at: string | null;
  error_message: string | null;
  model_used: string | null;
  created_at: string;
}

export interface AlertResponse {
  id: string;
  severity: string;
  category: string;
  title: string;
  description: string | null;
  evidence: Record<string, unknown> | null;
  rule_id: string | null;
  triggered_at: string;
  ai_corroborated: boolean;
}

export interface AiAssessment {
  executive_summary: string | null;
  key_findings: Record<string, unknown> | null;
  recommendations: Record<string, unknown> | null;
  model_name: string | null;
  generation_time_ms: number | null;
}

export interface AnalysisResultResponse {
  job: JobStatusResponse;
  pcap_id: string;
  alerts: AlertResponse[];
  ai_assessment: AiAssessment | null;
}

export type JobStatus =
  | 'queued'
  | 'parsing'
  | 'extracting'
  | 'detecting'
  | 'assessing'
  | 'completed'
  | 'failed';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational';

export interface DiskStatus {
  total_gb: number;
  used_gb: number;
  free_gb: number;
  percent: number;
  over_threshold: boolean;
  threshold_pct: number;
}

export interface StorageStatus {
  disk: DiskStatus;
  pcap_count: number;
  pcap_total_bytes: number;
  artifact_count: number;
  expired_pcaps: number;
  orphan_artifacts: number;
}

export interface CleanupResult {
  expired_pcaps_found: number;
  files_deleted: number;
  rows_soft_deleted: number;
  artifacts_deleted: number;
  errors: string[];
}

export interface ArtifactInfo {
  job_id: string;
  pcap_id: string;
  artifact_type: string;
  filename: string;
  file_size: number;
  created_at: string | null;
}
