import type {
  AiConfigPublic,
  AiConfigUpdate,
  AiModelsResponse,
  AiProviderKind,
  AiQueryResponse,
  AiTestResponse,
  AlertRules,
  AuthLoginPayload,
  AuthLoginResponse,
  AuthSessionPublic,
  AuthStatusResponse,
  BulkIocResponse,
  CtiConfigPublic,
  CtiConfigUpdateRequest,
  CtiEnrichmentResponse,
  CtiProviderId,
  CtiTestResponse,
  CustomFeedConfig,
  CustomFeedCreateRequest,
  CveTriage,
  DashboardPayload,
  FeedHealth,
  FeedSettings,
  IocLookupResult,
  MyStackPayload,
  MyStackUpdateRequest,
  NetworkTelemetry,
  OtxSyncResponse,
  PcapAnalysisReport,
  SnapshotImportResult,
  StackImportResponse,
  ThreatAlert,
  ThreatNewsItem,
  TotpEnrollResponse,
  TriageStatus,
  Vulnerability,
  WebhookCreateRequest,
  WebhookTargetPublic,
  WebhookTestResponse,
  WebhookUpdateRequest,
} from './types';
import { demoApi } from './demoData';
import { downloadTextFile } from './utils/opsec';

export const IS_DEMO_MODE = import.meta.env.VITE_DEMO_MODE === '1';

export class ApiError extends Error {
  status: number;
  retryAfterSecs?: number;
  requiresTotp?: boolean;
  setupRequired?: boolean;

  constructor(
    message: string,
    status: number,
    extra?: { retryAfterSecs?: number; requiresTotp?: boolean; setupRequired?: boolean }
  ) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.retryAfterSecs = extra?.retryAfterSecs;
    this.requiresTotp = extra?.requiresTotp;
    this.setupRequired = extra?.setupRequired;
  }
}

async function fetchJson<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, {
    credentials: 'same-origin',
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers ?? {}),
    },
  });
  if (!res.ok) {
    const txt = await res.text().catch(() => '');
    let message = `API ${res.status}: ${txt || res.statusText}`;
    let retryAfterSecs: number | undefined;
    let requiresTotp: boolean | undefined;
    let setupRequired: boolean | undefined;
    try {
      const parsed = JSON.parse(txt) as {
        error?: string;
        retry_after_secs?: number;
        requires_totp?: boolean;
        setup_required?: boolean;
      };
      if (parsed.error) message = parsed.error;
      if (typeof parsed.retry_after_secs === 'number') retryAfterSecs = parsed.retry_after_secs;
      if (typeof parsed.requires_totp === 'boolean') requiresTotp = parsed.requires_totp;
      if (typeof parsed.setup_required === 'boolean') setupRequired = parsed.setup_required;
    } catch {
      // plain text fallback
    }
    const hdrRetry = res.headers.get('retry-after');
    if (retryAfterSecs === undefined && hdrRetry) {
      const n = Number(hdrRetry);
      if (Number.isFinite(n) && n > 0) retryAfterSecs = n;
    }
    throw new ApiError(message, res.status, { retryAfterSecs, requiresTotp, setupRequired });
  }
  return res.json() as Promise<T>;
}

async function downloadEndpointFile(url: string, fallbackFilename: string): Promise<void> {
  const res = await fetch(url, { credentials: 'same-origin' });
  if (!res.ok) {
    const txt = await res.text().catch(() => '');
    throw new Error(`Export ${res.status}: ${txt || res.statusText}`);
  }
  const cd = res.headers.get('content-disposition') || '';
  const match = cd.match(/filename="?([^"]+)"?/i);
  const filename = match?.[1] || fallbackFilename;
  const text = await res.text();
  downloadTextFile(filename, text, res.headers.get('content-type') || 'text/plain;charset=utf-8');
}

export const api = {
  getAuthStatus: async (): Promise<AuthStatusResponse> =>
    IS_DEMO_MODE ? demoApi.getAuthStatus() : fetchJson<AuthStatusResponse>('/api/auth/status'),

  setupAdmin: async (payload: {
    username: string;
    display_name?: string;
    password: string;
  }): Promise<AuthLoginResponse> => {
    if (IS_DEMO_MODE) return { authenticated: true };
    return fetchJson<AuthLoginResponse>('/api/auth/setup', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  login: async (payload: AuthLoginPayload): Promise<AuthLoginResponse> => {
    if (IS_DEMO_MODE) return { authenticated: true };
    return fetchJson<AuthLoginResponse>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  logout: async (): Promise<{ authenticated: boolean }> => {
    if (IS_DEMO_MODE) return { authenticated: false };
    return fetchJson<{ authenticated: boolean }>('/api/auth/logout', { method: 'POST' });
  },

  listSessions: async (): Promise<AuthSessionPublic[]> =>
    IS_DEMO_MODE ? [] : fetchJson<AuthSessionPublic[]>('/api/auth/sessions'),

  revokeOtherSessions: async (): Promise<{ revoked: number }> =>
    IS_DEMO_MODE
      ? { revoked: 0 }
      : fetchJson<{ revoked: number }>('/api/auth/sessions/revoke-all', { method: 'POST' }),

  changePassword: async (
    current_password: string,
    new_password: string
  ): Promise<{ updated: boolean; other_sessions_revoked: number }> =>
    IS_DEMO_MODE
      ? { updated: true, other_sessions_revoked: 0 }
      : fetchJson<{ updated: boolean; other_sessions_revoked: number }>('/api/auth/change-password', {
          method: 'POST',
          body: JSON.stringify({ current_password, new_password }),
        }),

  enrollTotp: async (): Promise<TotpEnrollResponse> =>
    fetchJson<TotpEnrollResponse>('/api/auth/totp/enroll', { method: 'POST' }),

  verifyTotp: async (
    code: string
  ): Promise<{ totp_enabled: boolean; recovery_codes: string[] }> =>
    fetchJson<{ totp_enabled: boolean; recovery_codes: string[] }>('/api/auth/totp/verify', {
      method: 'POST',
      body: JSON.stringify({ code }),
    }),

  disableTotp: async (
    password: string,
    code: string
  ): Promise<{ totp_enabled: boolean }> =>
    fetchJson<{ totp_enabled: boolean }>('/api/auth/totp/disable', {
      method: 'POST',
      body: JSON.stringify({ password, code }),
    }),

  getDashboard: async (): Promise<DashboardPayload> =>
    IS_DEMO_MODE ? demoApi.getDashboard() : fetchJson<DashboardPayload>('/api/dashboard'),

  getVulnerabilities: async (
    params: Record<string, string | number | boolean | undefined>
  ): Promise<{ total_matched: number; items: Vulnerability[] }> => {
    if (IS_DEMO_MODE) return demoApi.getVulnerabilities(params);
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

  getVulnerabilityDetail: async (
    id: string
  ): Promise<{ vulnerability: Vulnerability; related_news: ThreatNewsItem[] }> =>
    IS_DEMO_MODE
      ? demoApi.getVulnerabilityDetail(id)
      : fetchJson<{ vulnerability: Vulnerability; related_news: ThreatNewsItem[] }>(
          `/api/vulnerabilities/${encodeURIComponent(id)}`
        ),

  updateVulnTriage: async (
    id: string,
    status: TriageStatus,
    notes: string
  ): Promise<CveTriage> =>
    IS_DEMO_MODE
      ? demoApi.updateVulnTriage(id, status, notes)
      : fetchJson<CveTriage>(`/api/vulnerabilities/${encodeURIComponent(id)}/triage`, {
          method: 'PUT',
          body: JSON.stringify({ status, notes }),
        }),

  exportSingleVuln: async (id: string, format: 'markdown' | 'json' | 'stix') => {
    if (IS_DEMO_MODE) {
      const { vulnerability } = await demoApi.getVulnerabilityDetail(id);
      const ext = format === 'markdown' ? 'md' : format === 'stix' ? 'stix21.json' : 'json';
      const content =
        format === 'markdown'
          ? `# ${vulnerability.id} - ${vulnerability.title}\n\n- **Severity:** ${vulnerability.severity}\n- **AI Risk Score:** ${vulnerability.ai_risk_score}/100\n\n## Description\n\n${vulnerability.description}\n`
          : JSON.stringify(vulnerability, null, 2);
      downloadTextFile(`${vulnerability.id}.${ext}`, content);
      return;
    }
    return downloadEndpointFile(
      `/api/vulnerabilities/${encodeURIComponent(id)}/export?format=${format}`,
      `${id}.${format === 'markdown' ? 'md' : 'json'}`
    );
  },

  exportVulnerabilities: async (
    format: 'csv' | 'json' | 'stix',
    params: Record<string, string | number | boolean | undefined>
  ) => {
    if (IS_DEMO_MODE) {
      const { items } = await demoApi.getVulnerabilities(params);
      if (format === 'csv') {
        const lines = ['cve_id,severity,ai_risk_score,cvss_score,epss_pct,is_kev,title'];
        items.forEach((v) =>
          lines.push(
            `"${v.id}","${v.severity}",${v.ai_risk_score},${v.cvss_score ?? ''},${((v.epss_score ?? 0) * 100).toFixed(2)},${v.is_kev},"${v.title.replace(/"/g, '""')}"`
          )
        );
        downloadTextFile('aibrainworx-demo-vulnerabilities.csv', lines.join('\n'), 'text/csv');
      } else {
        downloadTextFile(
          `aibrainworx-demo-${format}.json`,
          JSON.stringify(items, null, 2),
          'application/json'
        );
      }
      return;
    }
    const qs = new URLSearchParams({ format });
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== '' && v !== false) {
        qs.set(k, String(v));
      }
    });
    return downloadEndpointFile(
      `/api/export/vulnerabilities?${qs.toString()}`,
      `aibrainworx-vulnerabilities.${format}`
    );
  },

  getStack: async (): Promise<MyStackPayload> =>
    IS_DEMO_MODE ? demoApi.getStack() : fetchJson<MyStackPayload>('/api/stack'),

  updateStack: async (req: MyStackUpdateRequest): Promise<MyStackPayload> =>
    IS_DEMO_MODE
      ? demoApi.updateStack(req)
      : fetchJson<MyStackPayload>('/api/stack', {
          method: 'PUT',
          body: JSON.stringify(req),
        }),

  importStack: async (
    filename: string,
    content: string,
    replace = true
  ): Promise<StackImportResponse> =>
    IS_DEMO_MODE
      ? demoApi.importStack(filename, content, replace)
      : fetchJson<StackImportResponse>('/api/stack/import', {
          method: 'POST',
          body: JSON.stringify({ filename, content, replace }),
        }),

  clearStack: async (): Promise<MyStackPayload> =>
    IS_DEMO_MODE
      ? demoApi.clearStack()
      : fetchJson<MyStackPayload>('/api/stack', { method: 'DELETE' }),

  getNews: async (params: Record<string, string | number | boolean | undefined>) => {
    if (IS_DEMO_MODE) {
      const dash = await demoApi.getDashboard();
      const q = String(params.q || '').trim().toLowerCase();
      const cat = String(params.category || 'ALL');
      const src = String(params.source || 'ALL');
      const filtered = dash.recent_news.filter((n) => {
        if (cat !== 'ALL' && n.category.toLowerCase() !== cat.toLowerCase()) return false;
        if (src !== 'ALL' && n.source.toLowerCase() !== src.toLowerCase()) return false;
        if (params.vuln_only && !n.is_vulnerability_news) return false;
        if (params.ai_only && !n.is_ai_related) return false;
        if (q && !`${n.title} ${n.summary} ${n.source} ${n.extracted_cves.join(' ')}`.toLowerCase().includes(q)) {
          return false;
        }
        return true;
      });
      const sources = Array.from(new Set(dash.recent_news.map((n) => n.source))).sort();
      return { total_matched: filtered.length, sources, items: filtered };
    }
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

  getIocs: async (lookup?: string) => {
    if (IS_DEMO_MODE) {
      const dash = await demoApi.getDashboard();
      return {
        telemetry: dash.telemetry as NetworkTelemetry,
        lookup_result: lookup ? demoApi.lookupSingleIoc(lookup) : null,
      };
    }
    const qs = lookup ? `?lookup=${encodeURIComponent(lookup)}` : '';
    return fetchJson<{ telemetry: NetworkTelemetry; lookup_result: IocLookupResult | null }>(
      `/api/iocs${qs}`
    );
  },

  bulkLookupIocs: async (indicators: string[]): Promise<BulkIocResponse> =>
    IS_DEMO_MODE
      ? demoApi.bulkLookupIocs(indicators)
      : fetchJson<BulkIocResponse>('/api/iocs/bulk', {
          method: 'POST',
          body: JSON.stringify({ indicators }),
        }),

  exportIocs: async (format: 'edl' | 'nftables' | 'pf' | 'csv' | 'wireshark') => {
    if (IS_DEMO_MODE) {
      const { telemetry } = await demoApi.getDashboard();
      const ips = Array.from(
        new Set([
          ...telemetry.botnet_c2s.map((c) => c.ip_address),
          ...telemetry.top_attacking_ips.map((i) => i.ip),
        ])
      );
      if (format === 'wireshark') {
        const filter = ips.length > 0 ? `ip.addr in {${ips.join(' ')}}` : 'tcp.flags.syn == 1';
        downloadTextFile(
          'aibrainworx-demo-wireshark-filter.txt',
          `# AiBrainWorX Demo Wireshark Display Filter\n${filter}\n`
        );
      } else if (format === 'nftables') {
        downloadTextFile(
          'aibrainworx-demo-nftables.nft',
          `set aibrainworx_blocklist {\n  type ipv4_addr\n  elements = { ${ips.join(', ')} }\n}\n`
        );
      } else {
        downloadTextFile(`aibrainworx-demo-iocs.${format === 'csv' ? 'csv' : 'txt'}`, ips.join('\n'));
      }
      return;
    }
    return downloadEndpointFile(`/api/iocs/export?format=${format}`, `aibrainworx-iocs.${format}`);
  },

  getWiresharkFilter: async (): Promise<{
    filter: string;
    c2_count: number;
    attacker_count: number;
  }> =>
    IS_DEMO_MODE
      ? demoApi.getWiresharkFilter()
      : fetchJson<{ filter: string; c2_count: number; attacker_count: number }>(
          '/api/iocs/wireshark-filter'
        ),

  analyzePcapFile: async (file: File): Promise<PcapAnalysisReport> => {
    if (IS_DEMO_MODE) return demoApi.analyzePcapSample(file.name);
    const bytes = await file.arrayBuffer();
    const res = await fetch(
      `/api/iocs/pcap?filename=${encodeURIComponent(file.name || 'capture.pcap')}`,
      {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/octet-stream' },
        body: bytes,
      }
    );
    if (!res.ok) {
      const txt = await res.text().catch(() => '');
      let message = `PCAP analysis failed (${res.status})`;
      try {
        const parsed = JSON.parse(txt) as { error?: string };
        if (parsed.error) message = parsed.error;
      } catch {
        if (txt) message = txt;
      }
      throw new ApiError(message, res.status);
    }
    return res.json() as Promise<PcapAnalysisReport>;
  },

  analyzePcapSample: async (): Promise<PcapAnalysisReport> =>
    IS_DEMO_MODE
      ? demoApi.analyzePcapSample('aibrainworx-demo-capture.pcap')
      : fetchJson<PcapAnalysisReport>('/api/iocs/pcap/sample', {
          method: 'POST',
          body: JSON.stringify({}),
        }),

  getCtiConfig: async (): Promise<CtiConfigPublic> =>
    IS_DEMO_MODE ? demoApi.getCtiConfig() : fetchJson<CtiConfigPublic>('/api/cti/config'),

  updateCtiConfig: async (req: CtiConfigUpdateRequest): Promise<CtiConfigPublic> =>
    IS_DEMO_MODE
      ? demoApi.updateCtiConfig(req)
      : fetchJson<CtiConfigPublic>('/api/cti/config', {
          method: 'PUT',
          body: JSON.stringify(req),
        }),

  testCtiProvider: async (
    provider: CtiProviderId,
    api_key?: string
  ): Promise<CtiTestResponse> =>
    IS_DEMO_MODE
      ? demoApi.testCtiProvider(provider)
      : fetchJson<CtiTestResponse>('/api/cti/test', {
          method: 'POST',
          body: JSON.stringify({ provider, api_key }),
        }),

  syncOtxPulses: async (): Promise<OtxSyncResponse> =>
    IS_DEMO_MODE
      ? demoApi.syncOtxPulses()
      : fetchJson<OtxSyncResponse>('/api/cti/otx/sync', {
          method: 'POST',
          body: JSON.stringify({}),
        }),

  enrichIndicator: async (
    indicator: string,
    force_refresh = false
  ): Promise<CtiEnrichmentResponse> =>
    IS_DEMO_MODE
      ? demoApi.enrichIndicator(indicator)
      : fetchJson<CtiEnrichmentResponse>('/api/cti/enrich', {
          method: 'POST',
          body: JSON.stringify({ indicator, force_refresh }),
        }),

  clearCtiCache: async (): Promise<{ ok: boolean; cleared: number }> =>
    IS_DEMO_MODE
      ? demoApi.clearCtiCache()
      : fetchJson<{ ok: boolean; cleared: number }>('/api/cti/cache', {
          method: 'DELETE',
        }),

  getAlerts: async () => {
    if (IS_DEMO_MODE) {
      const d = await demoApi.getDashboard();
      return { unacknowledged_count: d.kpis.unacknowledged_alerts, alerts: d.alerts };
    }
    return fetchJson<{ unacknowledged_count: number; alerts: ThreatAlert[] }>('/api/alerts');
  },

  ackAlert: async (id: string) =>
    IS_DEMO_MODE
      ? demoApi.ackAlert(id)
      : fetchJson<{ ok: boolean }>(`/api/alerts/${encodeURIComponent(id)}/ack`, { method: 'POST' }),

  ackAllAlerts: async () =>
    IS_DEMO_MODE
      ? demoApi.ackAllAlerts()
      : fetchJson<{ ok: boolean }>('/api/alerts/ack-all', { method: 'POST' }),

  triggerTestAlert: async (): Promise<ThreatAlert> =>
    IS_DEMO_MODE
      ? demoApi.triggerTestAlert()
      : fetchJson<ThreatAlert>('/api/alerts/test', { method: 'POST' }),

  getFeeds: async (): Promise<{
    last_sweep_at: string | null;
    next_sweep_at: string | null;
    sweep_in_progress: boolean;
    feeds: FeedHealth[];
    feed_settings?: FeedSettings;
  }> => (IS_DEMO_MODE ? demoApi.getFeeds() : fetchJson('/api/feeds')),

  updateFeedConfig: async (feed_name: string, enabled: boolean): Promise<FeedSettings> =>
    IS_DEMO_MODE
      ? demoApi.updateFeedConfig(feed_name, enabled)
      : fetchJson<FeedSettings>('/api/feeds/config', {
          method: 'PUT',
          body: JSON.stringify({ feed_name, enabled }),
        }),

  createCustomFeed: async (req: CustomFeedCreateRequest): Promise<CustomFeedConfig> =>
    IS_DEMO_MODE
      ? demoApi.createCustomFeed(req)
      : fetchJson<CustomFeedConfig>('/api/feeds/custom', {
          method: 'POST',
          body: JSON.stringify(req),
        }),

  deleteCustomFeed: async (id: string): Promise<{ ok: boolean }> =>
    IS_DEMO_MODE
      ? demoApi.deleteCustomFeed(id)
      : fetchJson<{ ok: boolean }>(`/api/feeds/custom/${encodeURIComponent(id)}`, {
          method: 'DELETE',
        }),

  listWebhooks: async (): Promise<WebhookTargetPublic[]> =>
    IS_DEMO_MODE ? demoApi.listWebhooks() : fetchJson<WebhookTargetPublic[]>('/api/webhooks'),

  createWebhook: async (req: WebhookCreateRequest): Promise<WebhookTargetPublic> =>
    IS_DEMO_MODE
      ? demoApi.createWebhook(req)
      : fetchJson<WebhookTargetPublic>('/api/webhooks', {
          method: 'POST',
          body: JSON.stringify(req),
        }),

  updateWebhook: async (id: string, req: WebhookUpdateRequest): Promise<WebhookTargetPublic> =>
    IS_DEMO_MODE
      ? demoApi.updateWebhook(id, req)
      : fetchJson<WebhookTargetPublic>(`/api/webhooks/${encodeURIComponent(id)}`, {
          method: 'PUT',
          body: JSON.stringify(req),
        }),

  deleteWebhook: async (id: string): Promise<{ ok: boolean }> =>
    IS_DEMO_MODE
      ? demoApi.deleteWebhook(id)
      : fetchJson<{ ok: boolean }>(`/api/webhooks/${encodeURIComponent(id)}`, {
          method: 'DELETE',
        }),

  testWebhook: async (id: string): Promise<WebhookTestResponse> =>
    IS_DEMO_MODE
      ? demoApi.testWebhook()
      : fetchJson<WebhookTestResponse>(`/api/webhooks/${encodeURIComponent(id)}/test`, {
          method: 'POST',
        }),

  ackDelta: async (): Promise<{ ok: boolean }> =>
    IS_DEMO_MODE
      ? demoApi.ackDelta()
      : fetchJson<{ ok: boolean }>('/api/delta/ack', { method: 'POST' }),

  exportSnapshot: async () => {
    if (IS_DEMO_MODE) {
      const dash = await demoApi.getDashboard();
      downloadTextFile(
        'aibrainworx-demo-snapshot.json',
        JSON.stringify({ schema_version: '2.0-demo', exported_at: new Date().toISOString(), data: dash }, null, 2),
        'application/json'
      );
      return;
    }
    return downloadEndpointFile('/api/snapshot/export', 'aibrainworx-offline-snapshot.json');
  },

  importSnapshot: async (rawJsonText: string): Promise<SnapshotImportResult> =>
    IS_DEMO_MODE
      ? demoApi.importSnapshot()
      : fetchJson<SnapshotImportResult>('/api/snapshot/import', {
          method: 'POST',
          body: rawJsonText,
        }),

  triggerRefresh: async () =>
    IS_DEMO_MODE
      ? { status: 'demo_simulated' }
      : fetchJson<{ status: string }>('/api/refresh', { method: 'POST' }),

  getRules: async () => {
    if (IS_DEMO_MODE) {
      return {
        min_severity: 'HIGH',
        alert_on_any_kev: true,
        alert_on_vuln_news: true,
        alert_on_ai_threats: true,
        watchlist_keywords: ['zero-day', 'rce', 'openssl', 'pytorch', 'mcp'],
        poll_interval_secs: 3600,
      } as AlertRules;
    }
    return fetchJson<AlertRules>('/api/rules');
  },

  updateRules: (rules: AlertRules) =>
    IS_DEMO_MODE
      ? Promise.resolve(rules)
      : fetchJson<AlertRules>('/api/rules', {
          method: 'PUT',
          body: JSON.stringify(rules),
        }),

  getAiConfig: () =>
    IS_DEMO_MODE ? demoApi.getAiConfig() : fetchJson<AiConfigPublic>('/api/ai/config'),

  updateAiConfig: (update: AiConfigUpdate) =>
    IS_DEMO_MODE
      ? demoApi.updateAiConfig(update)
      : fetchJson<AiConfigPublic>('/api/ai/config', {
          method: 'PUT',
          body: JSON.stringify(update),
        }),

  listAiModels: (params: { provider?: AiProviderKind; base_url?: string; api_key?: string }) =>
    IS_DEMO_MODE
      ? Promise.resolve({
          ok: true,
          models: ['local-threat-graph-v1'],
          source: 'Demo',
          error: null,
        } as AiModelsResponse)
      : fetchJson<AiModelsResponse>('/api/ai/models', {
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
    IS_DEMO_MODE
      ? Promise.resolve({
          ok: true,
          latency_ms: 4,
          provider_label: 'Demo Simulator',
          model: 'local-threat-graph-v1',
          reply: 'Static Demo Engine active.',
          error: null,
        } as AiTestResponse)
      : fetchJson<AiTestResponse>('/api/ai/test', {
          method: 'POST',
          body: JSON.stringify(params),
        }),

  analyzeQuery: (query: string) =>
    IS_DEMO_MODE
      ? demoApi.analyzeQuery(query)
      : fetchJson<AiQueryResponse>('/api/ai/analyze', {
          method: 'POST',
          body: JSON.stringify({ query }),
        }),

  triageVulnerability: (id: string) =>
    IS_DEMO_MODE
      ? demoApi.analyzeQuery(`Deep triage ${id}`)
      : fetchJson<AiQueryResponse>(`/api/ai/triage/${encodeURIComponent(id)}`, {
          method: 'POST',
          body: JSON.stringify({}),
        }),
};

export function playAlertChime() {
  try {
    const Ctx =
      window.AudioContext ||
      (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext;
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
