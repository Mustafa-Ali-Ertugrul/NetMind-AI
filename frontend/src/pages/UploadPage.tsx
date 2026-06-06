import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { toast } from 'sonner';
import { UploadDropzone } from '@/components/UploadDropzone';
import { useUploadPcap } from '@/hooks/useUploadPcap';
import { formatBytes } from '@/lib/format';
import { FileText, Loader2, CheckCircle2, AlertCircle, ArrowRight } from 'lucide-react';

export function UploadPage() {
  const navigate = useNavigate();
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const upload = useUploadPcap();

  useEffect(() => {
    if (upload.isSuccess) {
      toast.success(upload.data.deduplicated ? 'Duplicate file — using existing analysis' : 'Upload successful');
    }
  }, [upload.isSuccess, upload.data]);

  useEffect(() => {
    if (upload.isError) {
      toast.error(upload.error?.message ?? 'Upload failed');
    }
  }, [upload.isError, upload.error]);

  const handleFile = (file: File) => {
    setSelectedFile(file);
    upload.mutate(file);
  };

  const reset = () => {
    setSelectedFile(null);
    upload.reset();
  };

  return (
    <div className="max-w-2xl mx-auto">
      <h2 className="text-2xl font-bold text-gray-900 mb-1">Upload PCAP</h2>
      <p className="text-sm text-gray-500 mb-6">
        Upload a network capture file for AI-powered security analysis.
      </p>

      {!selectedFile && <UploadDropzone onFile={handleFile} disabled={upload.isPending} />}

      {selectedFile && (
        <div className="space-y-4">
          <div className="bg-white border border-gray-200 rounded-xl p-4 flex items-center gap-4">
            <FileText className="w-8 h-8 text-blue-500 shrink-0" />
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-gray-900 truncate">{selectedFile.name}</p>
              <p className="text-xs text-gray-500">{formatBytes(selectedFile.size)}</p>
            </div>
            {upload.isPending && <Loader2 className="w-5 h-5 text-blue-500 animate-spin" />}
            {upload.isSuccess && <CheckCircle2 className="w-5 h-5 text-green-500" />}
            {upload.isError && <AlertCircle className="w-5 h-5 text-red-500" />}
          </div>

          {upload.isPending && (
            <div className="flex items-center gap-2 text-sm text-blue-600">
              <Loader2 className="w-4 h-4 animate-spin" />
              Uploading and queuing analysis…
            </div>
          )}

          {upload.isSuccess && (
            <div className="bg-green-50 border border-green-200 rounded-xl p-4 space-y-3">
              <div className="flex items-start gap-2 text-sm text-green-800">
                <CheckCircle2 className="w-4 h-4 mt-0.5 shrink-0" />
                <div>
                  <p className="font-medium">Upload successful</p>
                  {upload.data.deduplicated ? (
                    <p className="text-green-600 mt-0.5">
                      This file was already analyzed (deduplicated).
                    </p>
                  ) : (
                    <p className="text-green-600 mt-0.5">Analysis job queued.</p>
                  )}
                </div>
              </div>
              {upload.data.job_id && (
                <button
                  onClick={() => navigate(`/jobs/${upload.data.job_id}`)}
                  className="inline-flex items-center gap-2 px-4 py-2 bg-green-600 text-white text-sm font-medium rounded-lg hover:bg-green-700 transition-colors"
                >
                  View Analysis <ArrowRight className="w-4 h-4" />
                </button>
              )}
              <button
                onClick={reset}
                className="block text-xs text-green-600 hover:text-green-800 underline"
              >
                Upload another file
              </button>
            </div>
          )}

          {upload.isError && (
            <div className="bg-red-50 border border-red-200 rounded-xl p-4 space-y-3">
              <div className="flex items-start gap-2 text-sm text-red-800">
                <AlertCircle className="w-4 h-4 mt-0.5 shrink-0" />
                <div>
                  <p className="font-medium">Upload failed</p>
                  <p className="text-red-600 mt-0.5">{upload.error?.message ?? 'Unknown error'}</p>
                </div>
              </div>
              <button
                onClick={reset}
                className="text-xs text-red-600 hover:text-red-800 underline"
              >
                Try again
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
