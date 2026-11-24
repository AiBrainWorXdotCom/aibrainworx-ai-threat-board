import type {
  AiConfigPublic,
  AiConfigUpdate,
  AiProviderPreset,
  AiQueryResponse,
  AlertRules,
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
  MyStackConfig,
  MyStackPayload,
  MyStackUpdateRequest,
  OtxSyncResponse,
  PcapAnalysisReport,
  SnapshotImportResult,
  StackComponent,
  StackImportResponse,
  StackMatchSummary,
  SweepDelta,
  ThreatAlert,
  ThreatNewsItem,
  TriageStatus,
  Vulnerability,
  WebhookCreateRequest,
  WebhookTargetPublic,
  WebhookTestResponse,
  WebhookUpdateRequest,
} from './types';

const nowIso = (hoursAgo = 0) =>
  new Date(Date.now() - hoursAgo * 3600 * 1000).toISOString();

const DEMO_PRESETS: AiProviderPreset[] = [
  {
    id: 'builtin',
    name: 'Built-in Rust Engine',
    group: 'local',
    default_base_url: '',
    default_model: 'local-threat-graph-v1',
    suggested_models: ['local-threat-graph-v1'],
    requires_api_key: false,
    env_var_name: null,
    env_key_present: false,
    description: 'Zero-dependency local correlation engine (air-gapped compatible).',
  },
  {
    id: 'ollama',
    name: 'Ollama (Local)',
    group: 'local',
    default_base_url: 'http://127.0.0.1:11434/v1',
    default_model: 'llama3.2:latest',
    suggested_models: ['llama3.2:latest', 'qwen2.5:14b'],
    requires_api_key: false,
    env_var_name: null,
    env_key_present: false,
    description: 'Local Ollama inference on 127.0.0.1.',
  },
  {
    id: 'gemini',
    name: 'Google Gemini',
    group: 'cloud',
    default_base_url: 'https://generativelanguage.googleapis.com/v1beta',
    default_model: 'gemini-2.5-flash',
    suggested_models: ['gemini-2.5-flash', 'gemini-2.5-pro'],
    requires_api_key: true,
    env_var_name: 'GEMINI_API_KEY',
    env_key_present: false,
    description: 'Google Gemini HTTPS API.',
  },
];

const INITIAL_VULNS: Vulnerability[] = [
  {
    id: 'CVE-2026-41001',
    aliases: ['GHSA-demo-41001'],
    title: 'Remote Code Execution in OpenSSL TLS Extension Parser',
    description:
      'Boundary error in experimental certificate extension parsing allows unauthenticated remote code execution prior to authentication.',
    severity: 'CRITICAL',
    cvss_score: 9.8,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    epss_score: 0.914,
    epss_percentile: 0.996,
    ai_risk_score: 96,
    ai_score_factors: [
      { label: 'CISA KEV', points: 32, detail: 'Confirmed active exploitation in the wild' },
      { label: 'EPSS >= 50%', points: 24, detail: '91.4% 30-day exploitation probability' },
      { label: 'Public Exploit PoC', points: 14, detail: 'Working weaponized exploit referenced' },
      { label: 'CVSS >= 9.0', points: 18, detail: 'CVSS v3 base 9.8' },
    ],
    ai_summary: 'CRITICAL Remote Code Execution impacting openssl — active CISA KEV + 91.4% EPSS.',
    is_kev: true,
    kev_date_added: nowIso(72).slice(0, 10),
    kev_due_date: new Date(Date.now() + 2 * 86400 * 1000).toISOString().slice(0, 10),
    kev_required_action: 'Upgrade OpenSSL packages immediately and restart TLS-terminating workers.',
    forensic_triage: 'Inspect unexpected outbound TLS handshakes on ingress proxies.',
    ransomware_use: true,
    has_public_exploit: true,
    is_ai_related: false,
    vendor: 'OpenSSL',
    product: 'openssl',
    ecosystem: 'c',
    patched_version: '3.0.16',
    cwes: ['CWE-122'],
    mitre_tactics: ['Initial Access', 'Execution'],
    attack_vectors: ['Remote Code Execution', 'Network Service Exploit'],
    sources: ['CISA KEV', 'NIST NVD'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2026-41001'],
    published_at: nowIso(18),
    updated_at: nowIso(4),
    first_seen_at: nowIso(18),
    epss_delta_24h: 0.246,
    epss_delta_7d: 0.51,
    epss_spike: true,
    kev_days_remaining: 2,
    matched_stack: ['openssl'],
    triage_status: 'investigating',
    triage_notes: 'Rolling out 3.0.16 container base rebuilds across edge API gateways.',
  },
  {
    id: 'CVE-2026-39812',
    aliases: ['PYSEC-2026-114'],
    title: 'PyTorch Model Weight Deserialization Arbitrary Code Execution',
    description:
      'Unsafe fallback deserialization when loading untrusted checkpoint archives allows arbitrary Python payload execution.',
    severity: 'CRITICAL',
    cvss_score: 9.3,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H',
    epss_score: 0.782,
    epss_percentile: 0.985,
    ai_risk_score: 89,
    ai_score_factors: [
      { label: 'AI/ML Supply Chain', points: 16, detail: 'Affects Python/LLM inference runtime' },
      { label: 'EPSS Surge', points: 22, detail: '78.2% exploit probability (+18.9% 24h)' },
      { label: 'Public Exploit PoC', points: 14, detail: 'PoC checkpoint gadget published' },
    ],
    ai_summary: 'CRITICAL Deserialization RCE impacting torch — AI/ML supply-chain exposure.',
    is_kev: false,
    kev_date_added: null,
    kev_due_date: null,
    kev_required_action: null,
    forensic_triage: null,
    ransomware_use: false,
    has_public_exploit: true,
    is_ai_related: true,
    vendor: 'PyTorch',
    product: 'torch',
    ecosystem: 'pypi',
    patched_version: '2.6.1',
    cwes: ['CWE-502'],
    mitre_tactics: ['Execution', 'Persistence'],
    attack_vectors: ['Deserialization', 'Supply Chain'],
    sources: ['OSV.dev AI', 'GitHub Advisory'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2026-39812'],
    published_at: nowIso(30),
    updated_at: nowIso(6),
    first_seen_at: nowIso(30),
    epss_delta_24h: 0.189,
    epss_delta_7d: 0.41,
    epss_spike: true,
    kev_days_remaining: null,
    matched_stack: ['torch'],
    triage_status: 'new',
    triage_notes: '',
  },
  {
    id: 'CVE-2026-37205',
    aliases: [],
    title: 'Enterprise Perimeter VPN Session Token Bypass (Overdue KEV)',
    description:
      'Authentication state confusion allows attackers to reuse forged session cookies against SSL-VPN endpoints.',
    severity: 'CRITICAL',
    cvss_score: 9.6,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N',
    epss_score: 0.895,
    epss_percentile: 0.994,
    ai_risk_score: 94,
    ai_score_factors: [
      { label: 'CISA KEV', points: 32, detail: 'Confirmed active exploitation; CISA deadline overdue' },
      { label: 'Auth Bypass', points: 18, detail: 'Unauthenticated perimeter session hijack' },
    ],
    ai_summary: 'CRITICAL Auth Bypass impacting perimeter VPN appliances — overdue CISA KEV.',
    is_kev: true,
    kev_date_added: nowIso(360).slice(0, 10),
    kev_due_date: new Date(Date.now() - 2 * 86400 * 1000).toISOString().slice(0, 10),
    kev_required_action: 'Apply emergency firmware patch or isolate management plane immediately.',
    forensic_triage: 'Revoke all active VPN user sessions after patching.',
    ransomware_use: true,
    has_public_exploit: true,
    is_ai_related: false,
    vendor: 'EdgeGate',
    product: 'ssl-vpn-gateway',
    ecosystem: 'firmware',
    patched_version: '7.4.8',
    cwes: ['CWE-287'],
    mitre_tactics: ['Initial Access', 'Credential Access'],
    attack_vectors: ['Authentication Bypass', 'Edge Device'],
    sources: ['CISA KEV', 'NIST NVD'],
    references: ['https://www.cisa.gov/known-exploited-vulnerabilities-catalog'],
    published_at: nowIso(96),
    updated_at: nowIso(12),
    first_seen_at: nowIso(96),
    epss_delta_24h: 0.042,
    epss_delta_7d: 0.19,
    epss_spike: false,
    kev_days_remaining: -2,
    matched_stack: [],
    triage_status: 'mitigated',
    triage_notes: 'Verified appliance not present in corporate perimeter inventory.',
  },
  {
    id: 'CVE-2026-35440',
    aliases: ['GHSA-axios-ssrf-demo'],
    title: 'Axios Proxy Redirect Header Leakage & SSRF Pivot',
    description:
      'Automatic cross-origin redirect handling in server-side requests may forward sensitive Authorization headers or target internal link-local endpoints.',
    severity: 'HIGH',
    cvss_score: 8.1,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N',
    epss_score: 0.34,
    epss_percentile: 0.91,
    ai_risk_score: 76,
    ai_score_factors: [
      { label: 'SSRF', points: 18, detail: 'Server-side request redirection risk' },
      { label: 'High CVSS', points: 14, detail: 'CVSS 8.1 High' },
    ],
    ai_summary: 'HIGH SSRF impacting axios — matched in My Stack package inventory.',
    is_kev: false,
    kev_date_added: null,
    kev_due_date: null,
    kev_required_action: null,
    forensic_triage: null,
    ransomware_use: false,
    has_public_exploit: false,
    is_ai_related: false,
    vendor: 'axios',
    product: 'axios',
    ecosystem: 'npm',
    patched_version: '1.8.2',
    cwes: ['CWE-918'],
    mitre_tactics: ['Discovery', 'Credential Access'],
    attack_vectors: ['SSRF', 'Credential Leak'],
    sources: ['GitHub Advisory'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2026-35440'],
    published_at: nowIso(52),
    updated_at: nowIso(18),
    first_seen_at: nowIso(52),
    epss_delta_24h: 0.055,
    epss_delta_7d: 0.14,
    epss_spike: false,
    kev_days_remaining: null,
    matched_stack: ['axios'],
    triage_status: 'new',
    triage_notes: '',
  },
  {
    id: 'CVE-2026-33109',
    aliases: [],
    title: 'MCP Tool Server Command Argument Injection in Shell Adapter',
    description:
      'Improper shell quoting in unvalidated Model Context Protocol tool wrappers allows indirect prompt injection payloads to invoke host commands.',
    severity: 'HIGH',
    cvss_score: 8.6,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N',
    epss_score: 0.41,
    epss_percentile: 0.94,
    ai_risk_score: 84,
    ai_score_factors: [
      { label: 'AI Agent / MCP', points: 18, detail: 'AI assistant tool-execution boundary bypass' },
      { label: 'RCE', points: 20, detail: 'Indirect command injection risk' },
    ],
    ai_summary: 'HIGH Command Injection impacting MCP agent frameworks.',
    is_kev: false,
    kev_date_added: null,
    kev_due_date: null,
    kev_required_action: null,
    forensic_triage: null,
    ransomware_use: false,
    has_public_exploit: true,
    is_ai_related: true,
    vendor: 'ModelContext',
    product: 'mcp-shell-bridge',
    ecosystem: 'npm',
    patched_version: '0.9.4',
    cwes: ['CWE-78'],
    mitre_tactics: ['Execution'],
    attack_vectors: ['Prompt Injection', 'Command Injection'],
    sources: ['OSV.dev AI'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2026-33109'],
    published_at: nowIso(66),
    updated_at: nowIso(20),
    first_seen_at: nowIso(66),
    epss_delta_24h: 0.162,
    epss_delta_7d: 0.28,
    epss_spike: true,
    kev_days_remaining: null,
    matched_stack: [],
    triage_status: 'new',
    triage_notes: '',
  },
];

const INITIAL_NEWS: ThreatNewsItem[] = [
  {
    id: 'demo-news-1',
    source: 'CISA Cybersecurity Advisories',
    category: 'Advisory',
    title: 'CISA Adds CVE-2026-41001 to Known Exploited Vulnerabilities Catalog',
    summary: 'Rapid exploit activity observed against unpatched OpenSSL TLS inspection gateways. Immediate remediation prioritized.',
    url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
    published_at: nowIso(6),
    first_seen_at: nowIso(6),
    extracted_cves: ['CVE-2026-41001'],
    severity: 'CRITICAL',
    ai_risk_score: 94,
    tags: ['Actively Exploited', 'CISA KEV'],
    is_vulnerability_news: true,
    is_ai_related: false,
    ai_triage_note: 'Verify TLS ingress containers run OpenSSL >= 3.0.16.',
  },
  {
    id: 'demo-news-2',
    source: 'Exploit-DB PoCs',
    category: 'Exploit PoC',
    title: 'Proof-of-Concept Checkpoint Deserialization Gadget targeting PyTorch (CVE-2026-39812)',
    summary: 'Security researchers published a reproducible deserialization chain affecting ML inference hosts.',
    url: 'https://www.exploit-db.com/',
    published_at: nowIso(14),
    first_seen_at: nowIso(14),
    extracted_cves: ['CVE-2026-39812'],
    severity: 'CRITICAL',
    ai_risk_score: 88,
    tags: ['Exploit PoC', 'AI/ML Supply Chain'],
    is_vulnerability_news: true,
    is_ai_related: true,
    ai_triage_note: 'Restrict checkpoint loading to weights_only=True or SafeTensors.',
  },
  {
    id: 'demo-news-3',
    source: 'BleepingComputer',
    category: 'Breaking News',
    title: 'Indirect Prompt Injection Campaigns Target Agentic Coding Tools via Malicious Issues',
    summary: 'Wave of invisible Unicode Tag sequences embedded in public bug reports attempts to exfiltrate local environment tokens.',
    url: 'https://www.bleepingcomputer.com/',
    published_at: nowIso(22),
    first_seen_at: nowIso(22),
    extracted_cves: ['CVE-2026-33109'],
    severity: 'HIGH',
    ai_risk_score: 81,
    tags: ['AI/LLM Security', 'Zero-Day'],
    is_vulnerability_news: true,
    is_ai_related: true,
    ai_triage_note: 'Enable strict Unicode control stripping & CSP tracking-image blocks.',
  },
];

// Strictly RFC 5737 TEST-NET IPs and .invalid phishing domains (zero real infrastructure)
const INITIAL_TELEMETRY = {
  infocon_status: 'yellow',
  top_attacked_ports: [
    { rank: 1, port: 443, service_name: 'HTTPS', records: 142890, targets: 18420, sources: 4920 },
    { rank: 2, port: 22, service_name: 'SSH', records: 118410, targets: 15210, sources: 6380 },
    { rank: 3, port: 3389, service_name: 'RDP', records: 84210, targets: 9810, sources: 3120 },
    { rank: 4, port: 11434, service_name: 'Ollama-API', records: 29450, targets: 1890, sources: 740 },
    { rank: 5, port: 8443, service_name: 'HTTPS-Alt', records: 21340, targets: 4120, sources: 910 },
  ],
  top_attacking_ips: [
    { ip: '198.51.100.14', attacks: 4210, count: 19400, first_seen: '2026-11-18', last_seen: '2026-11-22' },
    { ip: '203.0.113.77', attacks: 3180, count: 14820, first_seen: '2026-11-19', last_seen: '2026-11-22' },
    { ip: '192.0.2.91', attacks: 2640, count: 11200, first_seen: '2026-11-20', last_seen: '2026-11-22' },
    { ip: '198.51.100.203', attacks: 1995, count: 8450, first_seen: '2026-11-21', last_seen: '2026-11-22' },
  ],
  botnet_c2s: [
    {
      ip_address: '198.51.100.42',
      port: 443,
      status: 'online',
      hostname: 'c2-relay-demo.invalid',
      as_number: 64512,
      as_name: 'TEST-NET-ASN-1',
      country: 'XX',
      malware: 'QakBot',
      first_seen: '2026-11-15',
      last_online: '2026-11-22',
    },
    {
      ip_address: '203.0.113.108',
      port: 8080,
      status: 'online',
      hostname: null,
      as_number: 64513,
      as_name: 'TEST-NET-ASN-2',
      country: 'XX',
      malware: 'Pikabot',
      first_seen: '2026-11-17',
      last_online: '2026-11-22',
    },
  ],
  phishing_urls: [
    {
      url: 'https://sso-verify-portal.invalid/login/oauth',
      domain: 'sso-verify-portal.invalid',
      suspected_brand: 'Enterprise SSO (Demo)',
    },
    {
      url: 'https://auth-token-renew.invalid/session',
      domain: 'auth-token-renew.invalid',
      suspected_brand: 'Cloud IdP (Demo)',
    },
  ],
  phishing_total_count: 2480,
  compromised_ips_sample: ['198.51.100.42', '203.0.113.77', '192.0.2.55'],
  compromised_ips_total_count: 1480,
  top_epss_global: [
    { cve: 'CVE-2026-41001', epss: 0.914, percentile: 0.996, date: nowIso(0).slice(0, 10) },
    { cve: 'CVE-2026-37205', epss: 0.895, percentile: 0.994, date: nowIso(0).slice(0, 10) },
    { cve: 'CVE-2026-39812', epss: 0.782, percentile: 0.985, date: nowIso(0).slice(0, 10) },
  ],
};

// Stateful client-side demo store
const demoState = {
  vulns: structuredClone(INITIAL_VULNS) as Vulnerability[],
  news: structuredClone(INITIAL_NEWS) as ThreatNewsItem[],
  alerts: [
    {
      id: 'demo-alert-1',
      created_at: nowIso(1),
      severity: 'CRITICAL',
      alert_type: 'MY_STACK_KEV',
      title: '[STACK EXPOSURE · KEV] CVE-2026-41001: OpenSSL TLS RCE (EPSS +24.6%)',
      summary:
        'Matched your local stack component openssl and triggers CISA KEV active exploitation rules.',
      source: 'AiBrainWorX Stack Correlator',
      url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-41001',
      cve_ids: ['CVE-2026-41001'],
      matched_reasons: ['My Stack Hit: openssl', 'CISA KEV', 'EPSS Surge +24.6%'],
      ai_risk_score: 96,
      acknowledged: false,
      linked_item_id: 'CVE-2026-41001',
    },
  ] as ThreatAlert[],
  rules: {
    min_severity: 'HIGH',
    alert_on_any_kev: true,
    alert_on_vuln_news: true,
    alert_on_ai_threats: true,
    watchlist_keywords: ['zero-day', 'rce', 'openssl', 'pytorch', 'mcp', 'ransomware'],
    poll_interval_secs: 3600,
  } as AlertRules,
  myStack: {
    vendors: ['OpenSSL', 'PyTorch'],
    products: ['nginx'],
    keywords: ['mcp'],
    components: [
      { name: 'openssl', version: '3.0.12', ecosystem: 'c', source_file: 'demo-bom.json' },
      { name: 'torch', version: '2.5.1', ecosystem: 'pypi', source_file: 'requirements.txt' },
      { name: 'axios', version: '1.6.8', ecosystem: 'npm', source_file: 'package-lock.json' },
    ],
    updated_at: nowIso(2),
  } as MyStackConfig,
  feedSettings: {
    disabled_feeds: [],
    custom_feeds: [
      {
        id: 'demo-custom-1',
        name: 'Internal SOC STIX Feed (Demo)',
        url: 'https://feeds.soc-demo.invalid/stix21.json',
        kind: 'stix21',
        enabled: true,
        last_status: 'OK (Demo simulated)',
        last_item_count: 14,
        last_checked: nowIso(1),
      },
    ] as CustomFeedConfig[],
  } as FeedSettings,
  webhooks: [
    {
      id: 'demo-hook-1',
      name: 'SOC Triage Slack (Demo)',
      kind: 'slack',
      url_masked: 'https://hooks.slack.com/services/••••9x7a',
      enabled: true,
      min_severity: 'HIGH',
      kev_only: true,
      stack_only: false,
      has_signing_secret: true,
      last_status: 'Delivered (Demo)',
      last_sent_at: nowIso(2),
      failure_count: 0,
    },
  ] as WebhookTargetPublic[],
  deltaReviewed: false,
};

function recomputeDemoStack(): StackMatchSummary {
  const terms = [
    ...demoState.myStack.vendors,
    ...demoState.myStack.products,
    ...demoState.myStack.keywords,
    ...demoState.myStack.components.map((c) => c.name),
  ]
    .map((t) => t.trim().toLowerCase())
    .filter((t) => t.length >= 3);

  const matchedIds: string[] = [];
  let matchedKevCount = 0;

  for (const v of demoState.vulns) {
    const hay = `${v.vendor || ''} ${v.product || ''} ${v.title} ${v.description}`.toLowerCase();
    const hits = Array.from(new Set(terms.filter((t) => hay.includes(t)))).slice(0, 5);
    v.matched_stack = hits;
    if (hits.length > 0) {
      matchedIds.push(v.id);
      if (v.is_kev) matchedKevCount += 1;
    }
  }

  return {
    configured: terms.length > 0,
    component_count: demoState.myStack.components.length,
    vendor_watch_count:
      demoState.myStack.vendors.length +
      demoState.myStack.products.length +
      demoState.myStack.keywords.length,
    matched_vuln_count: matchedIds.length,
    matched_kev_count: matchedKevCount,
    top_matched_cves: matchedIds.slice(0, 8),
  };
}

function buildDemoFeedHealth(): FeedHealth[] {
  const base: FeedHealth[] = [
    {
      id: 'cisa_kev',
      name: 'CISA Known Exploited Vulnerabilities',
      category: 'Vulnerability DB',
      url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
      status: 'OK',
      http_status: 200,
      latency_ms: 84,
      items_fetched: 1240,
      last_success_at: nowIso(0),
      last_error: null,
    },
    {
      id: 'nvd_api',
      name: 'NIST NVD CVE 2.0 (7-Day)',
      category: 'Vulnerability DB',
      url: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
      status: 'OK',
      http_status: 200,
      latency_ms: 210,
      items_fetched: 380,
      last_success_at: nowIso(0),
      last_error: null,
    },
    {
      id: 'first_epss_top',
      name: 'FIRST.org EPSS Top Risks',
      category: 'Exploit Prediction',
      url: 'https://api.first.org/data/v1/epss',
      status: 'OK',
      http_status: 200,
      latency_ms: 95,
      items_fetched: 25,
      last_success_at: nowIso(0),
      last_error: null,
    },
    {
      id: 'feodo_c2',
      name: 'abuse.ch Feodo Botnet C2s',
      category: 'IOC & Malware',
      url: 'https://feodotracker.abuse.ch/',
      status: 'OK',
      http_status: 200,
      latency_ms: 112,
      items_fetched: 2,
      last_success_at: nowIso(0),
      last_error: null,
    },
  ];
  return base.map((f) => ({
    ...f,
    status: demoState.feedSettings.disabled_feeds.includes(f.id) ? 'DISABLED' : f.status,
  }));
}

export const demoApi = {
  getAuthStatus: async (): Promise<AuthStatusResponse> => ({
    auth_required: false,
    setup_required: false,
    authenticated: true,
    username: 'demo-analyst',
    display_name: 'Demo Analyst',
    totp_enabled: false,
    recovery_codes_remaining: 0,
    token_auth_enabled: false,
    wallboard_mode: false,
    offline_mode: false,
    no_auth_mode: true,
  }),

  getDashboard: async (): Promise<DashboardPayload> => {
    const stackSummary = recomputeDemoStack();
    const spikes = demoState.vulns
      .filter((v) => v.epss_spike)
      .map((v) => ({
        cve_id: v.id,
        title: v.title,
        severity: v.severity,
        current_epss_pct: (v.epss_score || 0) * 100,
        delta_24h_pct: (v.epss_delta_24h || 0) * 100,
        is_kev: v.is_kev,
        matched_stack: v.matched_stack || [],
      }));

    const delta: SweepDelta = {
      sweep_at: nowIso(0),
      new_cves: ['CVE-2026-41001', 'CVE-2026-39812'],
      new_kevs: ['CVE-2026-41001'],
      new_stack_hits: stackSummary.top_matched_cves.slice(0, 3),
      epss_spikes: spikes,
      new_alerts_count: demoState.alerts.filter((a) => !a.acknowledged).length,
      reviewed: demoState.deltaReviewed,
    };

    const feedHealth = buildDemoFeedHealth();
    return {
      ai_brief: {
        generated_at: nowIso(0),
        global_threat_index: 82,
        threat_level_label: 'CRITICAL',
        executive_summary:
          '**Demo SOC Mode (Synthetic Sanitized Data):** Live threat simulation showcasing **My Stack SBOM correlation**, **EPSS 24h exploit surges**, **CISA KEV deadlines**, and **OPSEC RFC-5737 redacted IOCs**.',
        key_findings: [
          `MY STACK EXPOSURE: ${stackSummary.matched_vuln_count} synthetic CVEs match your uploaded SBOM/watchlist (openssl, torch, axios).`,
          'EPSS SURGE ALERT: CVE-2026-41001 jumped +24.6 percentage points over 24h (now 91.4%).',
          'KEV SLA CHECK: CVE-2026-37205 is 2 days overdue (mitigated in demo triage); CVE-2026-41001 due in 2 days.',
        ],
        top_attack_vectors: [
          { label: 'Remote Code Execution', count: 3 },
          { label: 'Deserialization', count: 1 },
          { label: 'SSRF', count: 1 },
        ],
        top_mitre_tactics: [
          { label: 'Execution', count: 4 },
          { label: 'Initial Access', count: 3 },
          { label: 'Credential Access', count: 2 },
        ],
        top_targeted_vendors: [
          { label: 'OpenSSL', count: 2 },
          { label: 'PyTorch', count: 1 },
          { label: 'axios', count: 1 },
        ],
        remediation_priorities: demoState.vulns.slice(0, 4).map((v) => ({
          cve_id: v.id,
          vendor_product: `${v.vendor || ''} ${v.product || ''}`.trim(),
          reason: v.ai_summary,
          urgency: v.is_kev ? 'IMMEDIATE' : 'URGENT (24-48H)',
          due_date: v.kev_due_date,
          ai_risk_score: v.ai_risk_score,
        })),
        velocity_7d: Array.from({ length: 7 }, (_, idx) => ({
          date: `D-${6 - idx}`,
          cves: 12 + idx * 4,
          kev: idx > 3 ? 2 : 1,
          news: 8 + idx * 2,
          exploits: idx > 2 ? 3 : 1,
          critical: 4 + (idx % 3),
        })),
      },
      kpis: {
        total_vulnerabilities: demoState.vulns.length,
        critical_count_7d: demoState.vulns.filter((v) => v.severity === 'CRITICAL').length,
        high_count_7d: demoState.vulns.filter((v) => v.severity === 'HIGH').length,
        kev_total_catalog: 1240,
        kev_tracked: demoState.vulns.filter((v) => v.is_kev).length,
        kev_added_7d: 1,
        kev_overdue_count: demoState.vulns.filter((v) => (v.kev_days_remaining ?? 0) < 0).length,
        high_epss_count: demoState.vulns.filter((v) => (v.epss_score ?? 0) >= 0.5).length,
        max_epss_pct: 91.4,
        ai_related_vulns: demoState.vulns.filter((v) => v.is_ai_related).length,
        news_count_24h: demoState.news.length,
        news_count_7d: demoState.news.length,
        exploit_poc_count: 1,
        botnet_c2_count: INITIAL_TELEMETRY.botnet_c2s.length,
        phishing_total_count: INITIAL_TELEMETRY.phishing_total_count,
        compromised_ips_count: INITIAL_TELEMETRY.compromised_ips_total_count,
        unacknowledged_alerts: demoState.alerts.filter((a) => !a.acknowledged).length,
        feeds_ok: feedHealth.filter((f) => f.status === 'OK').length,
        feeds_total: feedHealth.length,
        stack_exposed_count: stackSummary.matched_vuln_count,
        epss_spike_count: spikes.length,
        triage_investigating_count: demoState.vulns.filter(
          (v) => v.triage_status === 'investigating'
        ).length,
      },
      top_vulnerabilities: [...demoState.vulns],
      recent_news: [...demoState.news],
      telemetry: structuredClone(INITIAL_TELEMETRY),
      alerts: [...demoState.alerts],
      feed_health: feedHealth,
      last_sweep_at: nowIso(0),
      next_sweep_at: new Date(Date.now() + 3600 * 1000).toISOString(),
      poll_interval_secs: demoState.rules.poll_interval_secs,
      sweep_in_progress: false,
      total_sweeps: 3,
      active_ai_provider: 'Built-in Rust Engine (Demo)',
      active_ai_model: 'local-threat-graph-v1',
      stack_summary: stackSummary,
      recent_epss_spikes: spikes,
      latest_delta: delta,
      server_mode: {
        version: '0.2.0-demo',
        wallboard_mode: false,
        offline_mode: false,
        no_auth_mode: true,
        auth_required: false,
        setup_required: false,
        authenticated: true,
        username: 'demo-analyst',
        totp_enabled: false,
        bind_addr: 'static-pages',
      },
    };
  },

  getVulnerabilities: async (params: Record<string, string | number | boolean | undefined>) => {
    recomputeDemoStack();
    const q = String(params.q || '').toLowerCase();
    const items = demoState.vulns.filter((v) => {
      if (params.severity && params.severity !== 'ALL' && v.severity !== params.severity) return false;
      if (params.kev_only && !v.is_kev) return false;
      if (params.ai_only && !v.is_ai_related) return false;
      if (params.ransomware_only && !v.ransomware_use) return false;
      if (params.exploit_only && !v.has_public_exploit) return false;
      if (params.stack_only && (!v.matched_stack || v.matched_stack.length === 0)) return false;
      if (params.epss_spike && !v.epss_spike) return false;
      if (params.triage && params.triage !== 'all' && v.triage_status !== params.triage) return false;
      if (q && !`${v.id} ${v.title} ${v.description} ${v.vendor} ${v.product}`.toLowerCase().includes(q)) {
        return false;
      }
      return true;
    });
    return { total_matched: items.length, items };
  },

  getVulnerabilityDetail: async (id: string) => {
    recomputeDemoStack();
    const vulnerability =
      demoState.vulns.find((v) => v.id === id) || demoState.vulns[0];
    const related_news = demoState.news.filter((n) => n.extracted_cves.includes(vulnerability.id));
    return { vulnerability, related_news };
  },

  updateVulnTriage: async (
    id: string,
    status: TriageStatus,
    notes: string
  ): Promise<CveTriage> => {
    const v = demoState.vulns.find((x) => x.id === id);
    if (v) {
      v.triage_status = status;
      v.triage_notes = notes;
    }
    return { cve_id: id, status, notes, updated_at: nowIso(0) };
  },

  getStack: async (): Promise<MyStackPayload> => {
    const summary = recomputeDemoStack();
    const matched = demoState.vulns.filter((v) => (v.matched_stack?.length ?? 0) > 0);
    return {
      config: structuredClone(demoState.myStack),
      summary,
      matched_vulnerabilities: matched,
    };
  },

  updateStack: async (req: MyStackUpdateRequest): Promise<MyStackPayload> => {
    if (req.vendors) demoState.myStack.vendors = req.vendors;
    if (req.products) demoState.myStack.products = req.products;
    if (req.keywords) demoState.myStack.keywords = req.keywords;
    if (req.components) demoState.myStack.components = req.components;
    demoState.myStack.updated_at = nowIso(0);
    return demoApi.getStack();
  },

  importStack: async (filename: string, content: string, replace = true): Promise<StackImportResponse> => {
    const comps: StackComponent[] = [];
    for (const line of content.split(/\r?\n/)) {
      const m = line.trim().match(/^([A-Za-z0-9._-]+)[=<>!~]*([\d.]*)/);
      if (m && !line.trim().startsWith('#')) {
        comps.push({
          name: m[1],
          version: m[2] || '',
          ecosystem: 'demo',
          source_file: filename || 'manifest',
        });
      }
    }
    if (replace) {
      demoState.myStack.components = comps.slice(0, 200);
    } else {
      demoState.myStack.components.push(...comps.slice(0, 200));
    }
    const summary = recomputeDemoStack();
    return {
      format_detected: 'Demo Client Parser',
      imported_components: comps.length,
      total_components: demoState.myStack.components.length,
      matched_vulnerabilities: summary.matched_vuln_count,
      config: structuredClone(demoState.myStack),
    };
  },

  clearStack: async (): Promise<MyStackPayload> => {
    demoState.myStack = { vendors: [], products: [], keywords: [], components: [], updated_at: nowIso(0) };
    return demoApi.getStack();
  },

  lookupSingleIoc: (raw: string): IocLookupResult => {
    const q = raw.trim();
    const hits: IocLookupResult['hits'] = [];
    for (const ip of INITIAL_TELEMETRY.top_attacking_ips) {
      if (ip.ip === q) {
        hits.push({ feed: 'SANS DShield (Demo)', indicator_type: 'Scanner IP', detail: `${ip.attacks} attacks` });
      }
    }
    for (const c2 of INITIAL_TELEMETRY.botnet_c2s) {
      if (c2.ip_address === q) {
        hits.push({ feed: 'Feodo Tracker (Demo)', indicator_type: 'Botnet C2', detail: c2.malware });
      }
    }
    for (const ph of INITIAL_TELEMETRY.phishing_urls) {
      if (ph.url.includes(q) || ph.domain.includes(q)) {
        hits.push({ feed: 'OpenPhish (Demo)', indicator_type: 'Phishing URL', detail: ph.url });
      }
    }
    return {
      query: q,
      matched: hits.length > 0,
      risk_verdict: hits.length > 0 ? 'MALICIOUS / FLAGGED (DEMO)' : 'NO MATCH IN DEMO FEEDS',
      hits,
    };
  },

  bulkLookupIocs: async (indicators: string[]): Promise<BulkIocResponse> => {
    const results = indicators.slice(0, 200).map((ind) => demoApi.lookupSingleIoc(ind));
    return {
      checked: results.length,
      matched_count: results.filter((r) => r.matched).length,
      results,
    };
  },

  getWiresharkFilter: async () => ({
    filter:
      'ip.addr in {198.51.100.42 203.0.113.108 192.0.2.55} || tcp.port in {443 22 23 8080}',
    c2_count: INITIAL_TELEMETRY.botnet_c2s.length,
    attacker_count: INITIAL_TELEMETRY.top_attacking_ips.length,
  }),

  analyzePcapSample: async (filename = 'aibrainworx-demo-capture.pcap'): Promise<PcapAnalysisReport> => {
    const surfaceId = `demo-pcap-${Date.now()}`;
    const masterFilter =
      '(ip.addr == 198.51.100.42 && (tcp.port == 443 || udp.port == 443)) || (dns.qry.name contains "sso-verify-portal.invalid" || tls.handshake.extensions_server_name contains "sso-verify-portal.invalid" || http.host contains "sso-verify-portal.invalid")';
    return {
      filename,
      format: 'PCAP',
      file_bytes: 3420,
      parse_ms: 2,
      packets_parsed: 19,
      packets_truncated: false,
      total_bytes_observed: 3012,
      protocol_counts: { TCP: 17, UDP: 2, TLS: 4, DNS: 2, HTTP: 1 },
      unique_external_ips: 3,
      unique_internal_ips: 1,
      unique_domains: 2,
      malicious_hits: [
        {
          indicator: '198.51.100.42',
          indicator_type: 'Botnet C2',
          severity: 'CRITICAL',
          feeds: ['abuse.ch Feodo Tracker (Demo)'],
          detail: 'Botnet C2 (QakBot, port 443, XX)',
          packets: 16,
          ports: [443, 22, 23, 445, 3389],
          wireshark_filter: 'ip.addr == 198.51.100.42 && (tcp.port == 443 || udp.port == 443)',
        },
        {
          indicator: 'sso-verify-portal.invalid',
          indicator_type: 'Phishing Domain',
          severity: 'HIGH',
          feeds: ['OpenPhish (Demo)'],
          detail: 'Active phishing campaign domain (Enterprise SSO Demo)',
          packets: 6,
          ports: [],
          wireshark_filter:
            'dns.qry.name contains "sso-verify-portal.invalid" || tls.handshake.extensions_server_name contains "sso-verify-portal.invalid" || http.host contains "sso-verify-portal.invalid"',
        },
      ],
      anomalies: [
        {
          kind: 'PORT_SCAN',
          severity: 'HIGH',
          title: 'Port scan / SYN sweep detected from 198.51.100.42 (12 distinct ports)',
          detail: '12 TCP SYN probes across 12 destination port(s) and 1 target host(s).',
          wireshark_filter: 'ip.src == 198.51.100.42 && tcp.flags.syn == 1 && tcp.flags.ack == 0',
        },
        {
          kind: 'DNS_TUNNELING',
          severity: 'MEDIUM',
          title: 'Suspicious DNS query: 9a8f7e6d5c4b3a291807f6e5d4c3b2a19f8e7d6c.exfil-beacon.invalid',
          detail: 'High-entropy long subdomain (40 chars, entropy 3.92) — possible DNS tunneling/DGA',
          wireshark_filter:
            'dns.qry.name == "9a8f7e6d5c4b3a291807f6e5d4c3b2a19f8e7d6c.exfil-beacon.invalid"',
        },
      ],
      top_external_ips: [
        {
          ip: '198.51.100.42',
          packets: 16,
          bytes: 2140,
          ports: [443, 22, 23, 445, 3389],
          protocols: ['TCP', 'TLS'],
          is_flagged: true,
          matched_feeds: ['abuse.ch Feodo Tracker (Demo)'],
          wireshark_filter: 'ip.addr == 198.51.100.42 && (tcp.port == 443 || udp.port == 443)',
        },
        {
          ip: '192.0.2.80',
          packets: 1,
          bytes: 184,
          ports: [80],
          protocols: ['TCP', 'HTTP'],
          is_flagged: false,
          matched_feeds: [],
          wireshark_filter: 'ip.addr == 192.0.2.80 && (tcp.port == 80 || udp.port == 80)',
        },
      ],
      top_ports: [
        { port: 443, protocol: 'TCP', service_name: 'HTTPS', packets: 5, unique_hosts: 2, is_high_risk: false },
        { port: 53, protocol: 'UDP', service_name: 'DNS', packets: 2, unique_hosts: 1, is_high_risk: false },
        { port: 80, protocol: 'TCP', service_name: 'HTTP', packets: 2, unique_hosts: 2, is_high_risk: false },
        { port: 445, protocol: 'TCP', service_name: 'SMB', packets: 1, unique_hosts: 1, is_high_risk: true },
        { port: 3389, protocol: 'TCP', service_name: 'RDP', packets: 1, unique_hosts: 1, is_high_risk: true },
      ],
      observed_hosts: [
        {
          host: 'sso-verify-portal.invalid',
          kind: 'TLS SNI',
          count: 6,
          is_flagged: true,
          matched_feeds: ['OpenPhish (Demo)'],
          suspicious_reason: null,
          wireshark_filter:
            'dns.qry.name contains "sso-verify-portal.invalid" || tls.handshake.extensions_server_name contains "sso-verify-portal.invalid" || http.host contains "sso-verify-portal.invalid"',
        },
        {
          host: '9a8f7e6d5c4b3a291807f6e5d4c3b2a19f8e7d6c.exfil-beacon.invalid',
          kind: 'DNS',
          count: 1,
          is_flagged: false,
          matched_feeds: [],
          suspicious_reason: 'High-entropy long subdomain (40 chars) — possible DNS tunneling/DGA',
          wireshark_filter:
            'dns.qry.name contains "9a8f7e6d5c4b3a291807f6e5d4c3b2a19f8e7d6c.exfil-beacon.invalid"',
        },
      ],
      http_user_agents: ['Mozilla/5.0 (Sample-SOC-Probe)'],
      master_wireshark_filter: masterFilter,
      ai_prompt_summary: `Analyze this offline Wireshark PCAP capture (${filename}): 19 packets parsed, 3 external IPs, 2 observed DNS/TLS/HTTP hosts, 2 live threat-feed IOC matches (198.51.100.42 [Botnet C2], sso-verify-portal.invalid [Phishing Domain]), and 2 behavioral anomalies (PORT_SCAN, DNS_TUNNELING).`,
      a2ui: {
        version: '1.0',
        surface_id: surfaceId,
        catalog_id: 'aibrainworx.soc.v1',
        intent: 'pcap_triage',
        messages: [
          {
            type: 'createSurface',
            surfaceId,
            catalogId: 'aibrainworx.soc.v1',
            rootComponentId: 'root',
            title: `Wireshark PCAP Triage — ${filename}`,
            subtitle: '100% local pure-Rust packet correlation (Synthetic RFC-5737 Demo)',
          },
          {
            type: 'updateDataModel',
            surfaceId,
            path: '/',
            value: {
              banner: {
                tone: 'error',
                badge: 'PCAP THREAT CORRELATION HIT',
                title: `2 malicious indicators matched live threat feeds in ${filename}`,
                body: 'Copy the Wireshark Display Filter below to isolate C2 and phishing frames directly in Wireshark.',
                action: { type: 'copy_text', label: 'Copy Master Filter', text: masterFilter },
              },
              kpis: [
                { label: 'PACKETS PARSED', value: '19', detail: 'PCAP · 3 KB (2 ms)', tone: 'cyan' },
                { label: 'MALICIOUS IOC HITS', value: '2', detail: '1 CRITICAL C2 · 1 Phishing', tone: 'crit' },
                { label: 'EXTERNAL IPs', value: '3', detail: '1 internal host observed', tone: 'warn' },
                { label: 'DNS / TLS / HTTP HOSTS', value: '2', detail: '2 behavioral anomalies', tone: 'warn' },
              ],
              chart: {
                series: [
                  { name: '443/HTTPS', value: 5, detail: 'TCP · 2 hosts' },
                  { name: '53/DNS', value: 2, detail: 'UDP · 1 host' },
                  { name: '80/HTTP', value: 2, detail: 'TCP · 2 hosts' },
                  { name: '445/SMB', value: 1, detail: 'TCP · HIGH-RISK PORT' },
                  { name: '3389/RDP', value: 1, detail: 'TCP · HIGH-RISK PORT' },
                ],
              },
              playbook: [
                {
                  id: 'demo-ws-p0',
                  priority: 'P0',
                  title: 'Inspect 198.51.100.42 (Botnet C2) frames in Wireshark',
                  detail: 'Matched Feodo Tracker QakBot C2 on port 443.',
                  action: {
                    type: 'copy_text',
                    label: 'Copy Wireshark Filter',
                    text: 'ip.addr == 198.51.100.42 && (tcp.port == 443 || udp.port == 443)',
                  },
                },
                {
                  id: 'demo-ws-p1',
                  priority: 'P1',
                  title: 'Investigate SYN port scan & high-entropy DNS tunneling query',
                  detail: '12 destination ports probed alongside suspicious exfil-beacon subdomain.',
                  action: {
                    type: 'copy_text',
                    label: 'Copy Hunt Filter',
                    text: 'ip.src == 198.51.100.42 && tcp.flags.syn == 1 && tcp.flags.ack == 0',
                  },
                },
              ],
            },
          },
          {
            type: 'updateComponents',
            surfaceId,
            components: [
              { id: 'root', component: 'Column', children: ['pcap-banner', 'pcap-kpis', 'pcap-split'] },
              { id: 'pcap-banner', component: 'Banner', props: { data: { '@path': '/banner' } } },
              { id: 'pcap-kpis', component: 'KpiStrip', props: { items: { '@path': '/kpis' } } },
              { id: 'pcap-split', component: 'SplitGrid', children: ['pcap-chart', 'pcap-playbook'] },
              {
                id: 'pcap-chart',
                component: 'BarChart',
                props: {
                  title: 'Top Destination Ports in Capture',
                  subtitle: 'Synthetic RFC-5737 PCAP demo profile',
                  unit: 'pkts',
                  accent: 'red',
                  data: { '@path': '/chart/series' },
                },
              },
              {
                id: 'pcap-playbook',
                component: 'ActionChecklist',
                props: { title: 'Wireshark Incident Containment Checklist', items: { '@path': '/playbook' } },
              },
            ],
          },
        ],
      },
    };
  },

  ackAlert: async (id: string) => {
    const a = demoState.alerts.find((x) => x.id === id);
    if (a) a.acknowledged = true;
    return { ok: true };
  },

  ackAllAlerts: async () => {
    demoState.alerts.forEach((a) => {
      a.acknowledged = true;
    });
    return { ok: true };
  },

  triggerTestAlert: async (): Promise<ThreatAlert> => {
    const alert: ThreatAlert = {
      id: `demo-alert-${Date.now()}`,
      created_at: nowIso(0),
      severity: 'CRITICAL',
      alert_type: 'DEMO_TEST',
      title: '[DEMO TEST] CVE-2026-41001 · Live Alert Pipeline Verification',
      summary: 'Interactive static demo test alert verifying SOC banner, toast, and audio queue.',
      source: 'Demo Watchdog',
      url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-41001',
      cve_ids: ['CVE-2026-41001'],
      matched_reasons: ['Interactive Demo Trigger'],
      ai_risk_score: 96,
      acknowledged: false,
      linked_item_id: 'CVE-2026-41001',
    };
    demoState.alerts.unshift(alert);
    return alert;
  },

  getFeeds: async () => ({
    last_sweep_at: nowIso(0),
    next_sweep_at: new Date(Date.now() + 3600 * 1000).toISOString(),
    sweep_in_progress: false,
    feeds: buildDemoFeedHealth(),
    feed_settings: structuredClone(demoState.feedSettings),
  }),

  updateFeedConfig: async (feed_name: string, enabled: boolean): Promise<FeedSettings> => {
    demoState.feedSettings.disabled_feeds = demoState.feedSettings.disabled_feeds.filter(
      (d) => d !== feed_name
    );
    if (!enabled) demoState.feedSettings.disabled_feeds.push(feed_name);
    return structuredClone(demoState.feedSettings);
  },

  createCustomFeed: async (req: CustomFeedCreateRequest): Promise<CustomFeedConfig> => {
    const cf: CustomFeedConfig = {
      id: `demo-cf-${Date.now()}`,
      name: req.name,
      url: req.url,
      kind: req.kind,
      enabled: req.enabled ?? true,
      last_status: 'Demo Configured',
      last_item_count: 0,
      last_checked: nowIso(0),
    };
    demoState.feedSettings.custom_feeds.push(cf);
    return cf;
  },

  deleteCustomFeed: async (id: string) => {
    demoState.feedSettings.custom_feeds = demoState.feedSettings.custom_feeds.filter((c) => c.id !== id);
    return { ok: true };
  },

  listWebhooks: async (): Promise<WebhookTargetPublic[]> => structuredClone(demoState.webhooks),

  createWebhook: async (req: WebhookCreateRequest): Promise<WebhookTargetPublic> => {
    const hook: WebhookTargetPublic = {
      id: `demo-hook-${Date.now()}`,
      name: req.name,
      kind: req.kind,
      url_masked: 'https://hooks.example.invalid/••••demo',
      enabled: req.enabled ?? true,
      min_severity: req.min_severity ?? 'HIGH',
      kev_only: req.kev_only ?? false,
      stack_only: req.stack_only ?? false,
      has_signing_secret: Boolean(req.signing_secret),
      last_status: 'Configured (Demo)',
      last_sent_at: null,
      failure_count: 0,
    };
    demoState.webhooks.push(hook);
    return hook;
  },

  updateWebhook: async (id: string, req: WebhookUpdateRequest): Promise<WebhookTargetPublic> => {
    const hook = demoState.webhooks.find((h) => h.id === id) || demoState.webhooks[0];
    Object.assign(hook, req);
    return structuredClone(hook);
  },

  deleteWebhook: async (id: string) => {
    demoState.webhooks = demoState.webhooks.filter((h) => h.id !== id);
    return { ok: true };
  },

  testWebhook: async (): Promise<WebhookTestResponse> => ({
    ok: true,
    status_code: 200,
    message: 'Simulated OK (Static Demo Mode makes no outbound webhook calls)',
    latency_ms: 12,
  }),

  ackDelta: async () => {
    demoState.deltaReviewed = true;
    return { ok: true };
  },

  getAiConfig: async (): Promise<AiConfigPublic> => ({
    provider: 'builtin',
    base_url: '',
    model: 'local-threat-graph-v1',
    has_api_key: false,
    api_key_masked: '',
    env_key_present: false,
    keychain_available: false,
    keychain_has_key: false,
    temperature: 0.2,
    max_tokens: 1600,
    timeout_secs: 60,
    system_prompt: 'Built-in local threat correlation prompt.',
    enrich_briefing: false,
    allow_lan_endpoints: false,
    save_key_to_keychain: false,
    active_label: 'Built-in Rust Engine (Demo)',
    presets: DEMO_PRESETS,
  }),

  updateAiConfig: async (_upd: AiConfigUpdate): Promise<AiConfigPublic> => demoApi.getAiConfig(),

  analyzeQuery: async (query: string): Promise<AiQueryResponse> => {
    const surfaceId = `demo-surface-${Date.now()}`;
    const topVulns = demoState.vulns.slice(0, 4);
    const topNews = demoState.news.slice(0, 2);
    return {
      answer_markdown: `### Demo Threat Analysis — "${query}"\n\n- **CVE-2026-41001** (AI Risk **96/100** · CISA KEV · **Stack Match: openssl**) — Upgrade OpenSSL to **3.0.16**.\n- **CVE-2026-39812** (AI Risk **89/100** · EPSS **+18.9% 24h** · **Stack Match: torch**) — Upgrade PyTorch to **2.6.1**.\n\n*Static GitHub Pages Demo Mode uses pre-seeded sanitized synthetic data. Run the single binary locally for live 25-feed & LLM analysis.*`,
      cited_cves: topVulns.map((v) => v.id),
      matched_news_count: topNews.length,
      matched_vuln_count: topVulns.length,
      analysis_mode: 'Built-in Rust Engine (Static Demo)',
      provider_used: 'Static Demo Simulator',
      model_used: 'local-threat-graph-v1',
      latency_ms: 8,
      fallback_reason: null,
      a2ui: {
        version: '1.0',
        surface_id: surfaceId,
        catalog_id: 'aibrainworx.soc.v1',
        intent: 'threat_overview',
        messages: [
          {
            type: 'createSurface',
            surfaceId,
            catalogId: 'aibrainworx.soc.v1',
            rootComponentId: 'root',
            title: 'Interactive Threat Posture Surface (Demo)',
            subtitle: `Query: "${query.slice(0, 68)}" · Synthetic sanitized SOC simulation`,
          },
          {
            type: 'updateDataModel',
            surfaceId,
            path: '/',
            value: {
              kpis: [
                { label: 'THREAT INDEX', value: '82/100', detail: 'CRITICAL (Demo)', tone: 'crit' },
                { label: 'MATCHED CVEs', value: String(topVulns.length), detail: '2 KEV · 2 Stack hits', tone: 'crit' },
                { label: 'PEAK EPSS (30D)', value: '91.4%', detail: 'CVE-2026-41001 (+24.6% 24h)', tone: 'warn' },
                { label: 'CORRELATED INTEL', value: String(topNews.length), detail: '4/4 demo feeds OK', tone: 'mint' },
              ],
              chart: {
                series: topVulns.map((v) => ({
                  name: v.id,
                  value: v.ai_risk_score,
                  detail: `${v.vendor ?? ''} ${v.product ?? ''} · EPSS ${((v.epss_score ?? 0) * 100).toFixed(1)}%`.trim(),
                })),
              },
              vulns: topVulns.map((v) => ({
                id: v.id,
                title: v.title,
                target: `${v.vendor ?? ''} ${v.product ?? ''}`.trim() || 'Demo Package',
                severity: v.severity,
                aiRisk: v.ai_risk_score,
                cvss: v.cvss_score,
                epssPct: v.epss_score != null ? Number((v.epss_score * 100).toFixed(1)) : null,
                isKev: v.is_kev,
                kevDaysRemaining: v.kev_days_remaining ?? null,
                ransomware: v.ransomware_use,
                isAi: v.is_ai_related,
                hasExploit: v.has_public_exploit,
                matchedStack: v.matched_stack ?? [],
                triageStatus: v.triage_status ?? 'new',
              })),
              playbook: [
                {
                  id: 'demo-p0',
                  priority: 'P0',
                  title: 'Patch CVE-2026-41001 (OpenSSL 3.0.16) before CISA KEV deadline',
                  detail: 'Matched local SBOM component openssl with +24.6% 24h EPSS surge.',
                  action: { type: 'open_cve', label: 'Inspect CVE-2026-41001', cveId: 'CVE-2026-41001' },
                },
                {
                  id: 'demo-p1',
                  priority: 'P1',
                  title: 'Upgrade PyTorch to 2.6.1 & disable untrusted pickle loading',
                  detail: 'Mitigates CVE-2026-39812 AI/ML supply-chain deserialization RCE.',
                  action: { type: 'navigate_tab', label: 'Open My Stack', tab: 'mystack' },
                },
                {
                  id: 'demo-p2',
                  priority: 'P2',
                  title: 'Export STIX 2.1 dossier for SIEM / SOAR correlation',
                  detail: 'Share structured threat intelligence across response teams.',
                  action: { type: 'export_stix', label: 'Export STIX 2.1', cveId: 'CVE-2026-41001' },
                },
              ],
            },
          },
          {
            type: 'updateComponents',
            surfaceId,
            components: [
              { id: 'root', component: 'Column', children: ['kpi-strip', 'vuln-table', 'split-mid', 'quick-actions'] },
              { id: 'kpi-strip', component: 'KpiStrip', props: { items: { '@path': '/kpis' } } },
              { id: 'vuln-table', component: 'VulnTable', props: { title: 'Priority Vulnerabilities (Interactive Triage)', rows: { '@path': '/vulns' } } },
              { id: 'split-mid', component: 'SplitGrid', children: ['primary-chart', 'remediation-playbook'] },
              { id: 'primary-chart', component: 'BarChart', props: { title: 'Priority CVE Risk Profile', subtitle: 'AI Risk Score (0–100)', unit: 'pts', accent: 'mint', data: { '@path': '/chart/series' } } },
              { id: 'remediation-playbook', component: 'ActionChecklist', props: { title: 'Recommended Containment Playbook', items: { '@path': '/playbook' } } },
              {
                id: 'quick-actions',
                component: 'ActionBar',
                props: {
                  actions: [
                    { type: 'export_stix', label: 'Export CVE-2026-41001 STIX 2.1', cveId: 'CVE-2026-41001' },
                    { type: 'navigate_tab', label: 'All Vulnerabilities', tab: 'vulnerabilities' },
                    { type: 'navigate_tab', label: 'My Stack Exposure', tab: 'mystack' },
                    { type: 'navigate_tab', label: 'Network IOCs', tab: 'network' },
                  ],
                },
              },
            ],
          },
        ],
      },
    };
  },

  importSnapshot: async (): Promise<SnapshotImportResult> => ({
    vulnerabilities_imported: demoState.vulns.length,
    news_imported: demoState.news.length,
    snapshot_exported_at: nowIso(0),
    sha256_verified: true,
  }),

  getCtiConfig: async (): Promise<CtiConfigPublic> => ({
    save_keys_to_keychain: false,
    keychain_available: false,
    otx_sync_pulses: true,
    otx_pulse_count: 2,
    otx_indicator_count: 148,
    otx_last_synced_at: nowIso(1),
    otx_pulses_preview: [
      {
        id: 'demo-p1',
        name: 'LummaStealer & QakBot C2 Wave (Demo)',
        author: 'AlienVault',
        modified: nowIso(1),
        indicator_count: 92,
        tags: ['qakbot', 'c2'],
      },
      {
        id: 'demo-p2',
        name: 'Enterprise SSO Phishing Campaign (Demo)',
        author: 'LevelBlue Labs',
        modified: nowIso(2),
        indicator_count: 56,
        tags: ['phishing', 'sso'],
      },
    ],
    cached_enrichment_count: 1,
    providers: [
      {
        id: 'otx',
        name: 'AlienVault / LevelBlue OTX',
        enabled: true,
        has_key: true,
        key_masked: '••••••••demo',
        env_var: 'OTX_API_KEY',
        env_key_present: false,
        keychain_has_key: false,
        key_optional: false,
        supports: ['IPv4', 'IPv6', 'Domain', 'Hash', 'Local Pulse Sync'],
        description: 'Free community + LevelBlue Labs threat pulses (Demo simulated).',
        signup_url: 'https://otx.alienvault.com/settings',
      },
      {
        id: 'greynoise',
        name: 'GreyNoise Community',
        enabled: true,
        has_key: false,
        key_masked: '',
        env_var: 'GREYNOISE_API_KEY',
        env_key_present: false,
        keychain_has_key: false,
        key_optional: true,
        supports: ['IPv4'],
        description: 'Separates internet background scanners (noise) and benign services (RIOT) from targeted attackers.',
        signup_url: 'https://viz.greynoise.io/account/api-key',
      },
      {
        id: 'abuseipdb',
        name: 'AbuseIPDB v2',
        enabled: false,
        has_key: false,
        key_masked: '',
        env_var: 'ABUSEIPDB_API_KEY',
        env_key_present: false,
        keychain_has_key: false,
        key_optional: false,
        supports: ['IPv4', 'IPv6'],
        description: 'Crowd-sourced IP abuse confidence scores (0–100%) and report counts.',
        signup_url: 'https://www.abuseipdb.com/account/api',
      },
      {
        id: 'virustotal',
        name: 'VirusTotal v3',
        enabled: false,
        has_key: false,
        key_masked: '',
        env_var: 'VIRUSTOTAL_API_KEY',
        env_key_present: false,
        keychain_has_key: false,
        key_optional: false,
        supports: ['IPv4', 'IPv6', 'Domain', 'Hash'],
        description: 'Multi-engine malware & domain reputation counts.',
        signup_url: 'https://www.virustotal.com/gui/my-apikey',
      },
    ],
  }),

  updateCtiConfig: async (_req: CtiConfigUpdateRequest): Promise<CtiConfigPublic> =>
    demoApi.getCtiConfig(),

  testCtiProvider: async (provider: CtiProviderId): Promise<CtiTestResponse> => ({
    provider,
    ok: true,
    latency_ms: 14,
    message: `Simulated OK for ${provider.toUpperCase()} (Static Demo Mode makes no outbound calls)`,
  }),

  syncOtxPulses: async (): Promise<OtxSyncResponse> => ({
    ok: true,
    pulse_count: 2,
    indicator_count: 148,
    ip_count: 84,
    domain_count: 42,
    hash_count: 22,
    latency_ms: 19,
    message: 'Synced 2 simulated OTX Pulses (148 RFC-5737 / .invalid demo indicators)',
  }),

  enrichIndicator: async (indicator: string): Promise<CtiEnrichmentResponse> => ({
    indicator,
    indicator_type: /^\d{1,3}(\.\d{1,3}){3}$/.test(indicator) ? 'ipv4' : 'domain',
    overall_verdict: 'MALICIOUS',
    enriched_at: nowIso(0),
    cached: false,
    findings: [
      {
        provider: 'otx',
        provider_name: 'AlienVault / LevelBlue OTX',
        ok: true,
        verdict: 'MALICIOUS',
        score: 4,
        summary: 'Found in 4 OTX pulse(s): LummaStealer C2 Wave · QakBot Infrastructure (Demo)',
        tags: ['qakbot', 'c2', 'botnet'],
        reference_url: null,
        latency_ms: 12,
        error: null,
      },
      {
        provider: 'greynoise',
        provider_name: 'GreyNoise Community',
        ok: true,
        verdict: 'SUSPICIOUS',
        score: null,
        summary: 'Internet Background Scanner · classification: malicious (noise=true, riot=false)',
        tags: ['Internet Background Scanner', 'MALICIOUS'],
        reference_url: null,
        latency_ms: 9,
        error: null,
      },
    ],
  }),

  clearCtiCache: async () => ({ ok: true, cleared: 1 }),
};
