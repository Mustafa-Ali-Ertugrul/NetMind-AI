const STEPS = ['queued', 'parsing', 'extracting', 'detecting', 'assessing', 'completed'] as const;

interface JobProgressTimelineProps {
  currentStatus: string;
}

function stepIndex(status: string): number {
  const idx = STEPS.indexOf(status as typeof STEPS[number]);
  return idx >= 0 ? idx : -1;
}

export function JobProgressTimeline({ currentStatus }: JobProgressTimelineProps) {
  const currentIdx = stepIndex(currentStatus);

  return (
    <div className="flex items-center gap-0 w-full">
      {STEPS.map((step, i) => {
        const done = currentIdx > i;
        const active = currentIdx === i;
        const failed = currentStatus === 'failed';

        return (
          <div key={step} className="flex items-center flex-1 last:flex-none">
            <div className="flex flex-col items-center">
              <div
                className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold transition-colors ${
                  done
                    ? 'bg-green-500 text-white'
                    : active
                      ? failed
                        ? 'bg-red-500 text-white'
                        : 'bg-blue-500 text-white ring-2 ring-blue-300'
                      : 'bg-gray-200 text-gray-500'
                }`}
              >
                {done ? '✓' : active && failed ? '✗' : i + 1}
              </div>
              <span
                className={`text-[10px] mt-1 whitespace-nowrap ${
                  active ? 'font-semibold text-blue-700' : done ? 'text-green-600' : 'text-gray-400'
                }`}
              >
                {step}
              </span>
            </div>
            {i < STEPS.length - 1 && (
              <div
                className={`flex-1 h-0.5 mx-1 ${
                  done ? 'bg-green-400' : active ? 'bg-blue-300' : 'bg-gray-200'
                }`}
              />
            )}
          </div>
        );
      })}
    </div>
  );
}
