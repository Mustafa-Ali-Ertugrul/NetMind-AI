import { useParams, Link } from 'react-router-dom';
import { useJobStatus } from '@/hooks/useJobStatus';
import { useJobResult } from '@/hooks/useJobResult';
import { useJobArtifacts } from '@/hooks/useJobArtifacts';
import { getArtifactDownloadUrl } from '@/api/jobs';
import { JobStatusBadge } from '@/components/JobStatusBadge';
import { JobProgressTimeline } from '@/components/JobProgressTimeline';
import { FindingTable } from '@/components/FindingTable';
import { AIReportPanel } from '@/components/AIReportPanel';
import { formatDate, formatBytes } from '@/lib/format';
import { ArrowLeft, Loader2, AlertCircle, Download, FileText } from 'lucide-react';

export function JobDetailPage() {
  const { jobId } = useParams<{ jobId: string }>();
  const status = useJobStatus(jobId ?? null);
  const result = useJobResult(jobId ?? null);
  const artifacts = useJobArtifacts(jobId ?? null);

  if (status.isLoading) {
    return (
      <div className="flex items-center gap-2 text-gray-500 py-12 justify-center">
        <Loader2 className="w-5 h-5 animate-spin" />
        Loading job…
      </div>
    );
  }

  if (status.isError) {
    return (
      <div className="max-w-2xl mx-auto text-center py-12">
        <AlertCircle className="w-10 h-10 text-red-400 mx-auto mb-3" />
        <p className="text-sm text-red-600">{status.error?.message ?? 'Job not found'}</p>
        <Link to="/upload" className="text-sm text-blue-600 hover:underline mt-2 inline-block">
          Back to upload
        </Link>
      </div>
    );
  }

  const job = status.data!;
  const isDone = job.status === 'completed' || job.status === 'failed';

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Link to="/upload" className="text-gray-400 hover:text-gray-600">
          <ArrowLeft className="w-5 h-5" />
        </Link>
        <div>
          <h2 className="text-xl font-bold text-gray-900">Analysis Job</h2>
          <p className="text-xs text-gray-400 font-mono">{job.id}</p>
        </div>
        <JobStatusBadge status={job.status} />
      </div>

      {/* Progress timeline */}
      <div className="bg-white border border-gray-200 rounded-xl p-5">
        <JobProgressTimeline currentStatus={job.status} />
      </div>

      {/* Job metadata */}
      <div className="bg-white border border-gray-200 rounded-xl p-5">
        <h3 className="text-sm font-semibold text-gray-700 mb-3">Details</h3>
        <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm">
          <div className="flex justify-between">
            <dt className="text-gray-500">PCAP ID</dt>
            <dd className="text-gray-900 font-mono text-xs">{job.pcap_id}</dd>
          </div>
          {job.model_used && (
            <div className="flex justify-between">
              <dt className="text-gray-500">Model</dt>
              <dd className="text-gray-900">{job.model_used}</dd>
            </div>
          )}
          {job.started_at && (
            <div className="flex justify-between">
              <dt className="text-gray-500">Started</dt>
              <dd className="text-gray-900">{formatDate(job.started_at)}</dd>
            </div>
          )}
          {job.completed_at && (
            <div className="flex justify-between">
              <dt className="text-gray-500">Completed</dt>
              <dd className="text-gray-900">{formatDate(job.completed_at)}</dd>
            </div>
          )}
        </dl>
      </div>

      {/* Error message */}
      {job.status === 'failed' && job.error_message && (
        <div className="bg-red-50 border border-red-200 rounded-xl p-4 flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-red-500 shrink-0 mt-0.5" />
          <div>
            <h4 className="text-sm font-semibold text-red-800">Analysis Failed</h4>
            <p className="text-sm text-red-600 mt-0.5">{job.error_message}</p>
          </div>
        </div>
      )}

      {/* Result section (only when completed) */}
      {isDone && result.data && (
        <>
          {/* Alerts / Findings */}
          <div className="bg-white border border-gray-200 rounded-xl p-5">
            <h3 className="text-sm font-semibold text-gray-700 mb-3">
              Findings ({result.data.alerts.length})
            </h3>
            <FindingTable alerts={result.data.alerts} />
          </div>

          {/* AI Assessment */}
          <div className="bg-white border border-gray-200 rounded-xl p-5">
            <h3 className="text-sm font-semibold text-gray-700 mb-3">AI Assessment</h3>
            <AIReportPanel assessment={result.data.ai_assessment} />
          </div>

          {/* Artifacts */}
          {artifacts.data && artifacts.data.length > 0 && (
            <div className="bg-white border border-gray-200 rounded-xl p-5">
              <h3 className="text-sm font-semibold text-gray-700 mb-3">Artifacts</h3>
              <div className="space-y-2">
                {artifacts.data.map((a) => (
                  <a
                    key={a.filename}
                    href={getArtifactDownloadUrl(job.id, a.filename)}
                    className="flex items-center justify-between px-3 py-2 rounded-lg border border-gray-100 hover:bg-gray-50 transition-colors"
                    download
                  >
                    <div className="flex items-center gap-3">
                      <FileText className="w-4 h-4 text-gray-400" />
                      <div>
                        <p className="text-sm font-medium text-gray-900">{a.filename}</p>
                        <p className="text-xs text-gray-500">{a.artifact_type}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className="text-xs text-gray-500">{formatBytes(a.file_size)}</span>
                      <Download className="w-4 h-4 text-blue-600" />
                    </div>
                  </a>
                ))}
              </div>
            </div>
          )}
        </>
      )}

      {/* Loading result */}
      {isDone && result.isLoading && (
        <div className="flex items-center gap-2 text-sm text-gray-500 justify-center py-4">
          <Loader2 className="w-4 h-4 animate-spin" />
          Loading analysis results…
        </div>
      )}
    </div>
  );
}
