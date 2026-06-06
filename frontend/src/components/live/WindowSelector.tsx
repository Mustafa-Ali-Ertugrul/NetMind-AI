import { Clock } from 'lucide-react';

interface WindowSelectorProps {
  value: string;
  onChange: (window: string) => void;
}

const OPTIONS = [
  { label: '5m', value: '5m' },
  { label: '10m', value: '10m' },
  { label: '1h', value: '1h' },
  { label: '6h', value: '6h' },
];

export function WindowSelector({ value, onChange }: WindowSelectorProps) {
  return (
    <div className="flex items-center gap-1.5">
      <Clock className="w-3.5 h-3.5 text-gray-400" />
      <div className="inline-flex rounded-lg bg-gray-100 p-0.5">
        {OPTIONS.map((opt) => (
          <button
            key={opt.value}
            onClick={() => onChange(opt.value)}
            className={`px-2.5 py-1 text-xs font-medium rounded-md transition-all ${
              value === opt.value
                ? 'bg-white text-blue-700 shadow-sm ring-1 ring-gray-200'
                : 'text-gray-500 hover:text-gray-700'
            }`}
          >
            {opt.label}
          </button>
        ))}
      </div>
    </div>
  );
}
