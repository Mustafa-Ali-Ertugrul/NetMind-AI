import { useState, useEffect } from 'react';
import { FlaskConical, Zap, Globe, KeyRound, RotateCcw } from 'lucide-react';
import {
  toggleDemo,
  startScenario,
  getDemoState,
  subscribe,
  type DemoScenario,
} from '@/demo/demoController';

const SCENARIOS: { id: DemoScenario; label: string; icon: React.ElementType }[] = [
  { id: 'port_scan', label: 'Port Scan', icon: Zap },
  { id: 'dns_tunnel', label: 'DNS Tunnel', icon: Globe },
  { id: 'brute_force', label: 'Brute Force', icon: KeyRound },
  { id: 'normal', label: 'Reset', icon: RotateCcw },
];

export function DemoControlPanel() {
  const [isDemo, setIsDemo] = useState(false);
  const [activeScenario, setActiveScenario] = useState<DemoScenario | null>(null);

  useEffect(() => {
    const sync = () => {
      const s = getDemoState();
      setIsDemo(s.isDemo);
      setActiveScenario(s.scenario);
    };
    sync();
    return subscribe(sync);
  }, []);

  const handleToggle = () => {
    const next = !isDemo;
    toggleDemo(next);
    setIsDemo(next);
    if (!next) setActiveScenario(null);
  };

  const handleScenario = (scenario: DemoScenario) => {
    startScenario(scenario);
    setActiveScenario(scenario);
  };

  return (
    <div className="flex flex-col items-end gap-2">
      <button
        onClick={handleToggle}
        className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
          isDemo
            ? 'bg-amber-50 text-amber-700 border border-amber-200'
            : 'bg-gray-50 text-gray-600 border border-gray-200 hover:bg-gray-100'
        }`}
      >
        <FlaskConical className="w-3.5 h-3.5" />
        {isDemo ? 'Demo Mode ON' : 'Demo Mode'}
      </button>

      {isDemo && (
        <div className="flex items-center gap-1.5">
          {SCENARIOS.map((s) => (
            <button
              key={s.id}
              onClick={() => handleScenario(s.id)}
              className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-[10px] font-medium transition-all ${
                activeScenario === s.id
                  ? 'bg-blue-50 text-blue-700 ring-1 ring-blue-200'
                  : 'bg-white text-gray-600 border border-gray-200 hover:bg-gray-50'
              }`}
            >
              <s.icon className="w-3 h-3" />
              {s.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
