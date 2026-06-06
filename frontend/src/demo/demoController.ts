import { useState, useEffect } from 'react';
import type { LiveAlertResponse, LiveTalkerItem, RiskStreamSnapshot } from '@/types/live';

export type DemoScenario = 'normal' | 'port_scan' | 'dns_tunnel' | 'brute_force';

interface DemoState {
  isDemo: boolean;
  scenario: DemoScenario | null;
  alerts: LiveAlertResponse[];
  talkers: LiveTalkerItem[];
  risk: RiskStreamSnapshot | null;
}

let state: DemoState = {
  isDemo: false,
  scenario: null,
  alerts: [],
  talkers: [],
  risk: null,
};

const timers: ReturnType<typeof setTimeout>[] = [];
const listeners = new Set<() => void>();

function notify() {
  listeners.forEach((cb) => cb());
}

export function subscribe(cb: () => void): () => void {
  listeners.add(cb);
  return () => listeners.delete(cb);
}

function clearTimers() {
  timers.forEach((t) => clearTimeout(t));
  timers.length = 0;
}

function createAlert(ruleId: string, ip: string, severity: string, riskScore: number): LiveAlertResponse {
  const now = new Date();
  return {
    id: `demo-${now.getTime()}-${Math.random().toString(36).slice(2, 7)}`,
    session_id: 'demo-session',
    rule_id: ruleId,
    severity,
    confidence: 'high',
    risk_score: riskScore,
    title: `${ruleId.replace(/_/g, ' ')} from ${ip}`,
    description: `Detected ${ruleId} pattern from ${ip}. This is a demo alert for presentation purposes.`,
    recommendation: 'Review the source IP and block if malicious.',
    affected_entities: [ip],
    evidence: {},
    feature_snapshot: {},
    timestamp_start: now.toISOString(),
    timestamp_end: now.toISOString(),
    triggered_at: now.toISOString(),
    status: 'open',
  };
}

function createRiskSnapshot(riskAvg: number, threatLevel: string, topRules: string[]): RiskStreamSnapshot {
  return {
    timestamp: new Date().toISOString(),
    risk_avg: riskAvg,
    threat_level: threatLevel,
    top_rules_triggered: topRules,
  };
}

function pushAlert(alert: LiveAlertResponse) {
  state.alerts = [alert, ...state.alerts].slice(0, 50);
  notify();
}

function setRisk(risk: RiskStreamSnapshot) {
  state.risk = risk;
  notify();
}

function setTalkers(talkers: LiveTalkerItem[]) {
  state.talkers = talkers;
  notify();
}

export function toggleDemo(value: boolean) {
  if (value === state.isDemo && !value) return;
  clearTimers();
  state = { isDemo: value, scenario: null, alerts: [], talkers: [], risk: null };
  notify();
}

export function startScenario(scenario: DemoScenario) {
  if (!state.isDemo) return;
  clearTimers();
  state = { ...state, scenario, alerts: [], talkers: [], risk: null };
  notify();

  if (scenario === 'normal') return;

  if (scenario === 'port_scan') runPortScan();
  else if (scenario === 'dns_tunnel') runDNSTunnel();
  else if (scenario === 'brute_force') runBruteForce();
}

export function getDemoState(): DemoState {
  return state;
}

/* ── Scenarios ─────────────────────────────────────────── */

function runPortScan() {
  const srcIP = '203.0.113.45';
  setTalkers([{ ip: srcIP, direction: 'src', bytes: 999_999, packets: 2000 }]);
  setRisk(createRiskSnapshot(0.85, 'critical', ['PORT_SCAN_DETECTED']));

  for (let i = 0; i < 20; i++) {
    const t = setTimeout(() => {
      pushAlert(createAlert('PORT_SCAN_DETECTED', srcIP, 'critical', 85));
    }, i * 100);
    timers.push(t);
  }

  const t2 = setTimeout(() => setRisk(createRiskSnapshot(0.55, 'high', ['PORT_SCAN_DETECTED'])), 3000);
  timers.push(t2);
  const t3 = setTimeout(() => setRisk(createRiskSnapshot(0.35, 'medium', ['PORT_SCAN_DETECTED'])), 8000);
  timers.push(t3);
}

function runDNSTunnel() {
  const dnsIP = '198.51.100.7';
  setTalkers([{ ip: dnsIP, direction: 'dst', bytes: 50_000, packets: 500 }]);
  setRisk(createRiskSnapshot(0.60, 'high', ['DNS_TUNNEL']));

  let count = 0;
  for (let i = 0; i < 10; i++) {
    const t = setTimeout(() => {
      pushAlert(createAlert('DNS_TUNNEL', dnsIP, 'high', 65));
      count++;
      const risk = Math.min(0.85, 0.60 + count * 0.03);
      setRisk(
        createRiskSnapshot(risk, risk >= 0.76 ? 'critical' : 'high', ['DNS_TUNNEL']),
      );
    }, i * 2000);
    timers.push(t);
  }

  const tDecay = setTimeout(
    () => setRisk(createRiskSnapshot(0.40, 'medium', ['DNS_TUNNEL'])),
    25000,
  );
  timers.push(tDecay);
}

function runBruteForce() {
  const srcIP = '192.0.2.22';
  setTalkers([{ ip: srcIP, direction: 'src', bytes: 80_000, packets: 1200 }]);
  setRisk(createRiskSnapshot(0.92, 'critical', ['BRUTE_FORCE_LOGIN']));

  for (let i = 0; i < 8; i++) {
    const t = setTimeout(() => {
      pushAlert(createAlert('BRUTE_FORCE_LOGIN', srcIP, 'critical', 90));
    }, i * 150);
    timers.push(t);
  }

  const t2 = setTimeout(
    () => setRisk(createRiskSnapshot(0.60, 'high', ['BRUTE_FORCE_LOGIN'])),
    3000,
  );
  timers.push(t2);
  const t3 = setTimeout(
    () => setRisk(createRiskSnapshot(0.35, 'medium', ['BRUTE_FORCE_LOGIN'])),
    8000,
  );
  timers.push(t3);
}

/* ── React hooks ───────────────────────────────────────── */

export function useDemoAlerts() {
  const [alerts, setAlerts] = useState<LiveAlertResponse[]>([]);
  useEffect(() => {
    const update = () => setAlerts(state.alerts);
    update();
    return subscribe(update);
  }, []);
  return alerts;
}

export function useDemoTalkers() {
  const [talkers, setTalkers] = useState<LiveTalkerItem[]>([]);
  useEffect(() => {
    const update = () => setTalkers(state.talkers);
    update();
    return subscribe(update);
  }, []);
  return talkers;
}

export function useDemoRisk() {
  const [risk, setRisk] = useState<RiskStreamSnapshot | null>(null);
  useEffect(() => {
    const update = () => setRisk(state.risk);
    update();
    return subscribe(update);
  }, []);
  return risk;
}
