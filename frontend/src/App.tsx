import { lazy, Suspense } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Toaster } from 'sonner';
import { AppLayout } from '@/components/layout/AppLayout';
import { UploadPage } from '@/pages/UploadPage';
import { NotFoundPage } from '@/pages/NotFoundPage';
import { ErrorBoundary } from '@/components/ErrorBoundary';
import { SkeletonCard, SkeletonTable, SkeletonChart } from '@/components/ui/Skeleton';

const DashboardPage = lazy(() => import('@/pages/DashboardPage').then(m => ({ default: m.DashboardPage })));
const StorageStatusPage = lazy(() => import('@/pages/StorageStatusPage').then(m => ({ default: m.StorageStatusPage })));
const JobDetailPage = lazy(() => import('@/pages/JobDetailPage').then(m => ({ default: m.JobDetailPage })));
const LiveMonitorPage = lazy(() => import('@/pages/LiveMonitorPage').then(m => ({ default: m.LiveMonitorPage })));

function DashboardFallback() {
  return (
    <div className="max-w-5xl mx-auto space-y-6 animate-pulse">
      <div className="h-6 w-28 bg-gray-200 rounded" />
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {Array.from({ length: 4 }).map((_, i) => <SkeletonCard key={i} />)}
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-white border border-gray-200 rounded-xl p-5 space-y-3">
          <div className="h-4 w-20 bg-gray-200 rounded" />
          <SkeletonChart />
        </div>
        <div className="bg-white border border-gray-200 rounded-xl p-5 space-y-3">
          <div className="h-4 w-28 bg-gray-200 rounded" />
          <SkeletonChart />
        </div>
      </div>
      <div className="bg-white border border-gray-200 rounded-xl p-5 space-y-3">
        <div className="h-4 w-24 bg-gray-200 rounded" />
        <SkeletonTable rows={4} />
      </div>
    </div>
  );
}

function StorageFallback() {
  return (
    <div className="max-w-4xl mx-auto space-y-6 animate-pulse">
      <div className="h-6 w-20 bg-gray-200 rounded" />
      <div className="bg-white border border-gray-200 rounded-xl p-5 space-y-3">
        <div className="h-4 w-16 bg-gray-200 rounded" />
        <div className="h-3 w-full bg-gray-200 rounded" />
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {Array.from({ length: 3 }).map((_, i) => <SkeletonCard key={i} />)}
      </div>
    </div>
  );
}

function JobDetailFallback() {
  return (
    <div className="max-w-4xl mx-auto space-y-6 animate-pulse">
      <div className="flex items-center gap-3">
        <div className="h-5 w-5 bg-gray-200 rounded" />
        <div className="h-6 w-32 bg-gray-200 rounded" />
      </div>
      <div className="bg-white border border-gray-200 rounded-xl p-5 space-y-2">
        {Array.from({ length: 4 }).map((_, i) => <div key={i} className="h-3 w-full bg-gray-200 rounded" />)}
      </div>
      <div className="bg-white border border-gray-200 rounded-xl p-5 space-y-2">
        {Array.from({ length: 3 }).map((_, i) => <div key={i} className="h-3 w-2/3 bg-gray-200 rounded" />)}
      </div>
    </div>
  );
}

function LiveMonitorFallback() {
  return (
    <div className="max-w-5xl mx-auto space-y-6 animate-pulse">
      <div className="h-6 w-32 bg-gray-200 rounded" />
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {Array.from({ length: 4 }).map((_, i) => <SkeletonCard key={i} />)}
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white border border-gray-200 rounded-xl p-5 space-y-3">
          <div className="h-4 w-24 bg-gray-200 rounded" />
          <SkeletonTable rows={3} />
        </div>
        <div className="bg-white border border-gray-200 rounded-xl p-5 space-y-3">
          <div className="h-4 w-20 bg-gray-200 rounded" />
          <SkeletonChart />
        </div>
      </div>
      <div className="bg-white border border-gray-200 rounded-xl p-5 space-y-3">
        <div className="h-4 w-28 bg-gray-200 rounded" />
        <SkeletonTable rows={4} />
      </div>
    </div>
  );
}
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 2,
      refetchOnWindowFocus: false,
    },
  },
});

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Toaster position="top-right" richColors closeButton />
        <ErrorBoundary>
          <Routes>
            <Route element={<AppLayout />}>
              <Route
                index
                element={
                  <Suspense fallback={<DashboardFallback />}>
                    <DashboardPage />
                  </Suspense>
                }
              />
              <Route path="upload" element={<UploadPage />} />
              <Route
                path="jobs/:jobId"
                element={
                  <Suspense fallback={<JobDetailFallback />}>
                    <JobDetailPage />
                  </Suspense>
                }
              />
              <Route
                path="storage"
                element={
                  <Suspense fallback={<StorageFallback />}>
                    <StorageStatusPage />
                  </Suspense>
                }
              />
              <Route
                path="live"
                element={
                  <Suspense fallback={<LiveMonitorFallback />}>
                    <LiveMonitorPage />
                  </Suspense>
                }
              />
              <Route path="*" element={<NotFoundPage />} />
            </Route>
          </Routes>
        </ErrorBoundary>
      </BrowserRouter>
    </QueryClientProvider>
  );
}

export default App;
