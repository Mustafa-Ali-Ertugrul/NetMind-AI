import { useCallback } from 'react';
import { useDropzone } from 'react-dropzone';
import { Upload, FileWarning } from 'lucide-react';

interface UploadDropzoneProps {
  onFile: (file: File) => void;
  disabled?: boolean;
}

const MAX_SIZE_MB = 100;

export function UploadDropzone({ onFile, disabled }: UploadDropzoneProps) {
  const onDrop = useCallback(
    (accepted: File[]) => {
      if (accepted.length > 0) onFile(accepted[0]);
    },
    [onFile],
  );

  const { getRootProps, getInputProps, isDragActive, fileRejections } = useDropzone({
    onDrop,
    accept: {
      'application/vnd.tcpdump.pcap': ['.pcap', '.pcapng'],
      'application/octet-stream': ['.pcap', '.pcapng'],
    },
    maxFiles: 1,
    maxSize: MAX_SIZE_MB * 1024 * 1024,
    disabled,
  });

  const rejection = fileRejections[0];
  const rejectionError = rejection?.errors[0];

  return (
    <div>
      <div
        {...getRootProps()}
        className={`border-2 border-dashed rounded-xl p-10 text-center cursor-pointer transition-colors ${
          isDragActive
            ? 'border-blue-400 bg-blue-50'
            : disabled
              ? 'border-gray-200 bg-gray-50 cursor-not-allowed'
              : 'border-gray-300 hover:border-blue-400 hover:bg-blue-50/50'
        }`}
      >
        <input {...getInputProps()} />
        <Upload className={`mx-auto w-10 h-10 mb-3 ${disabled ? 'text-gray-300' : 'text-gray-400'}`} />
        {isDragActive ? (
          <p className="text-blue-600 font-medium">Drop your PCAP file here…</p>
        ) : (
          <>
            <p className="text-gray-600 font-medium">
              {disabled ? 'Uploading…' : 'Drop a PCAP file here, or click to select'}
            </p>
            <p className="text-xs text-gray-400 mt-1">
              .pcap or .pcapng &middot; max {MAX_SIZE_MB} MB
            </p>
          </>
        )}
      </div>

      {rejectionError && (
        <div className="mt-3 flex items-start gap-2 text-sm text-red-600 bg-red-50 rounded-lg p-3">
          <FileWarning className="w-4 h-4 mt-0.5 shrink-0" />
          <span>
            {rejectionError.code === 'file-too-large'
              ? `File exceeds the ${MAX_SIZE_MB} MB limit.`
              : rejectionError.message}
          </span>
        </div>
      )}
    </div>
  );
}
