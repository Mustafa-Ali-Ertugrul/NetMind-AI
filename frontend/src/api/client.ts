import axios from 'axios';

const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL ?? '/api/v1',
  timeout: 60_000,
  headers: { 'Accept': 'application/json' },
});

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    const message =
      error.response?.data?.detail ??
      error.message ??
      'An unexpected error occurred';
    return Promise.reject(new Error(message));
  },
);

export default apiClient;
