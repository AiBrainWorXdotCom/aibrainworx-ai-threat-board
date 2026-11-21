import type {
  AiConfigPublic,
  AiConfigUpdate,
  AiModelsResponse,
  AiProviderKind,
  AiQueryResponse,
  AiTestResponse,
  AlertRules,
  DashboardPayload,
  FeedHealth,
  IocLookupResult,
  NetworkTelemetry,
  ThreatAlert,
  ThreatNewsItem,
  Vulnerability,
} from './types';

async function fetchJson<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers ?? {}),
    },
  });
  if (!res.ok) {
    const txt = await res.text().catch(() => '');
    throw new Error(`API ${res.status}: ${txt || res.statusText}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  getDashboard: () => fetchJson<DashboardPayload>('/api/dashboard'),

  getVulnerabilities: (params: Record<string, string | number | boolean | undefined>) => {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== '' && v !== false) {
        qs.set(k, String(v));
      }
    });
    return fetchJson<{ total_matched: number; items: Vulnerability[] }>(
      `/api/vulnerabilities?${qs.toString()}`
    );
  },

  getVulnerabilityDetail: (id: string) =>
    fetchJson<{ vulnerability: Vulnerability; related_news: ThreatNewsItem[] }>(
      `/api/vulnerabilities/${encodeURIComponent(id)}`
    ),

  getNews: (params: Record<string, string | number | boolean | undefined>) => {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== '' && v !== false) {
        qs.set(k, String(v));
      }
    });
    return fetchJson<{ total_matched: number; sources: string[]; items: ThreatNewsItem[] }>(
      `/api/news?${qs.toString()}`
    );
  },

  getIocs: (lookup?: string) => {
    const qs = lookup ? `?lookup=${encodeURIComponent(lookup)}` : '';
    return fetchJson<{ telemetry: NetworkTelemetry; lookup_result: IocLookupResult | null }>(
      `/api/iocs${qs}`
    );
  },

  getAlerts: () =>
    fetchJson<{ unacknowledged_count: number; alerts: ThreatAlert[] }>('/api/alerts'),

  ackAlert: (id: string) =>
    fetchJson<{ ok: boolean }>(`/api/alerts/${encodeURIComponent(id)}/ack`, { method: 'POST' }),

  ackAllAlerts: () =>
    fetchJson<{ ok: boolean }>('/api/alerts/ack-all', { method: 'POST' }),

  triggerTestAlert: () =>
    fetchJson<ThreatAlert>('/api/alerts/test', { method: 'POST' }),

  getFeeds: () =>
    fetchJson<{
      last_sweep_at: string | null;
      next_sweep_at: string | null;
      sweep_in_progress: boolean;
      feeds: FeedHealth[];
    }>('/api/feeds'),

  triggerRefresh: () =>
    fetchJson<{ status: string }>('/api/refresh', { method: 'POST' }),

  getRules: () => fetchJson<AlertRules>('/api/rules'),

  updateRules: (rules: AlertRules) =>
    fetchJson<AlertRules>('/api/rules', {
      method: 'PUT',
      body: JSON.stringify(rules),
    }),

  getAiConfig: () => fetchJson<AiConfigPublic>('/api/ai/config'),

  updateAiConfig: (update: AiConfigUpdate) =>
    fetchJson<AiConfigPublic>('/api/ai/config', {
      method: 'PUT',
      body: JSON.stringify(update),
    }),

  listAiModels: (params: { provider?: AiProviderKind; base_url?: string; api_key?: string }) =>
    fetchJson<AiModelsResponse>('/api/ai/models', {
      method: 'POST',
      body: JSON.stringify(params),
    }),

  testAiConnection: (params: {
    provider?: AiProviderKind;
    base_url?: string;
    model?: string;
    api_key?: string;
    timeout_secs?: number;
  }) =>
    fetchJson<AiTestResponse>('/api/ai/test', {
      method: 'POST',
      body: JSON.stringify(params),
    }),

  analyzeQuery: (query: string) =>
    fetchJson<AiQueryResponse>('/api/ai/analyze', {
      method: 'POST',
      body: JSON.stringify({ query }),
    }),

  triageVulnerability: (id: string) =>
    fetchJson<AiQueryResponse>(`/api/ai/triage/${encodeURIComponent(id)}`, {
      method: 'POST',
      body: JSON.stringify({}),
    }),
};

export function playAlertChime() {
  try {
    const Ctx = window.AudioContext || (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext;
    if (!Ctx) return;
    const ctx = new Ctx();
    const now = ctx.currentTime;
    const tones = [880, 1174.66];
    tones.forEach((freq, idx) => {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'sine';
      osc.frequency.setValueAtTime(freq, now + idx * 0.11);
      gain.gain.setValueAtTime(0.06, now + idx * 0.11);
      gain.gain.exponentialRampToValueAtTime(0.001, now + idx * 0.11 + 0.18);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start(now + idx * 0.11);
      osc.stop(now + idx * 0.11 + 0.2);
    });
  } catch {
    // Ignore autoplay restriction errors
  }
}

export function safeExternalUrl(raw: string | null | undefined): string | undefined {
  if (!raw) return undefined;
  const trimmed = raw.trim();
  if (!trimmed) return undefined;
  try {
    const parsed = new URL(trimmed);
    if (
      (parsed.protocol === 'http:' || parsed.protocol === 'https:') &&
      !parsed.username &&
      !parsed.password
    ) {
      return parsed.toString();
    }
    return undefined;
  } catch {
    return undefined;
  }
}

export function severityBadgeVariant(sev: string): 'error' | 'orange' | 'warning' | 'info' | 'neutral' {
  switch (sev.toUpperCase()) {
    case 'CRITICAL':
      return 'error';
    case 'HIGH':
      return 'orange';
    case 'MEDIUM':
      return 'warning';
    case 'LOW':
      return 'info';
    default:
      return 'neutral';
  }
}
