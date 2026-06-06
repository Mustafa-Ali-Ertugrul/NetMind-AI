import { useMutation } from '@tanstack/react-query';
import { uploadPcap } from '@/api/pcaps';
import type { UploadResponse } from '@/types/api';

export function useUploadPcap() {
  return useMutation<UploadResponse, Error, File>({
    mutationFn: uploadPcap,
  });
}
