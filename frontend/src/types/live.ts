/** Live streaming endpoint types — mirror of backend Pydantic schemas. */

export interface LiveAlertResponse {
  id: string;
  session_id: string;
  rule_id: string;
  severity: string;
  confidence: string;
  risk_score: number;
  title: string;
  description: string | null;
  recommendation: string | null;
  affected_entities: string[];
  evidence: Record<string, unknown>;
  feature_snapshot: Record<string, unknown>;
  timestamp_start: string;
  timestamp_end: string;
  triggered_at: string;
  status: string;
}

export interface LiveAlertListResponse {
  items: LiveAlertResponse[];
  total: number;
  limit: number;
  offset: number;
}

export interface TimelineBucketResponse {
  rule_id: string;
  bucket_start: string;
  count: number;
  max_severity: string;
}

export interface RuleStatsResponse {
  rule_id: string;
  session_id: string | null;
  evaluations: number;
  hits: number;
  miss: number;
  avg_risk_score: number;
  max_risk_score: number;
  rolling_window_size: number;
  last_evaluation_at: string;
  hit_ratio: number;
}

export interface LiveMetricsResponse {
  queue_size: number;
  events_enqueued: number;
  events_dropped: number;
  events_processed: number;
  batches_processed: number;
  alerts_generated: number;
  active_sessions: number;
  uptime_seconds: number;
}

/** ───── Sprint 9A: Live Monitor ───── */

/** Single top-talker row (merged src/dst list with direction column). */
export interface LiveTalkerItem {
  ip: string;
  direction: 'src' | 'dst';
  bytes: number;
  packets: number;
}

export interface LiveTalkersResponse {
  window: string;
  talkers: LiveTalkerItem[];
}

/** Current risk snapshot. */
export interface RiskStreamSnapshot {
  timestamp: string;
  risk_avg: number;
  threat_level: string;
  top_rules_triggered: string[];
}

/** One minute-bucketed data point for the trend chart. */
export interface RiskBucket {
  timestamp: string;
  risk_avg: number;
  count: number;
}

export interface RiskStreamResponse {
  window: string;
  current: RiskStreamSnapshot;
  series: RiskBucket[];
}

/** Parameters for alert list filtering. */
export interface AlertListParams {
  status?: string;
  severity?: string;
  rule_id?: string;
  session_id?: string;
  limit?: number;
  offset?: number;
}

/** Parameters for timeline endpoint. */
export interface TimelineParams {
  bucket?: 'hour' | 'day';
  hours?: number;
  rule_id?: string;
  session_id?: string;
}
