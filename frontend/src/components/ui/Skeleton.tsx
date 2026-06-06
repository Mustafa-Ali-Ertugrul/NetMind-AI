import type { ComponentPropsWithoutRef } from 'react';
import { clsx } from 'clsx';

type SkeletonProps = ComponentPropsWithoutRef<'div'>;

export function Skeleton({ className, ...props }: SkeletonProps) {
  return (
    <div
      className={clsx('animate-pulse rounded-lg bg-gray-200', className)}
      {...props}
    />
  );
}

export function SkeletonCard({ className }: { className?: string }) {
  return (
    <div className={clsx('bg-white border border-gray-200 rounded-xl p-5 space-y-3', className)}>
      <Skeleton className="h-4 w-24" />
      <Skeleton className="h-8 w-16" />
      <Skeleton className="h-3 w-32" />
    </div>
  );
}

export function SkeletonTable({ rows = 4 }: { rows?: number }) {
  return (
    <div className="space-y-3">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex gap-4">
          <Skeleton className="h-4 w-24" />
          <Skeleton className="h-4 w-16" />
          <Skeleton className="h-4 w-20" />
          <Skeleton className="h-4 w-32" />
        </div>
      ))}
    </div>
  );
}

export function SkeletonChart() {
  return (
    <div className="flex items-center justify-center h-56 bg-gray-50 rounded-lg">
      <Skeleton className="w-48 h-48 rounded-full" />
    </div>
  );
}
