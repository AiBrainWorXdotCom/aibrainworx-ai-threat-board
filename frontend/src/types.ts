export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface ScoreFactor {
  label: string;
  points: number;
  detail: string;
}

export type TriageStatus = 'new' | 'investigating' | 'mitigated' | 'false_positive' | 'accepted';

export interface Vulnerability {
  id: string;
  aliases: string[];
  title: string;
  description: string;
  severity: Severity;
  cvss_score: number | null;
  cvss_vector: string | null;
  epss_score: number | null;
  epss_percentile: number | null;
  ai_risk_score: number;
  ai_score_factors: ScoreFactor[];
  ai_summary: string;
  is_kev: boolean;
  kev_date_added: string | null;
  kev_due_date: string | null;
  kev_required_action: string | null;
  forensic_triage: string | null;
  ransomware_use: boolean;
  has_public_exploit: boolean;
  is_ai_related: boolean;
  vendor: string | null;
  product: string | null;
  ecosystem: string | null;
  patched_version: string | null;
  cwes: string[];
  mitre_tactics: string[];
  attack_vectors: string[];
  sources: string[];
  references: string[];
  published_at: string;
  updated_at: string;
  first_seen_at: string;
  epss_delta_24h?: number | null;
  epss_delta_7d?: number | null;
  epss_spike?: boolean;
  kev_days_remaining?: number | null;
  matched_stack?: string[];
  triage_status?: TriageStatus;
  triage_notes?: string;
}

export interface ThreatNewsItem {
  id: string;
  source: string;
  category: string;
  title: string;
  summary: string;
  url: string;
  published_at: string;
  first_seen_at: string;
  extracted_cves: string[];
  severity: Severity;
  ai_risk_score: number;
  tags: string[];
  is_vulnerability_news: boolean;
  is_ai_related: boolean;
  ai_triage_note: string;
}

export interface PortAttack {
  rank: number;
  port: number;
  service_name: string;
  records: number;
  targets: number;
  sources: number;
}

export interface AttackerIp {
  ip: string;
  attacks: number;
  count: number;
  first_seen: string;
  last_seen: string;
}

export interface BotnetC2 {
  ip_address: string;
  port: number;
  status: string;
  hostname: string | null;
  as_number: number | null;
  as_name: string | null;
  country: string | null;
  malware: string;
  first_seen: string | null;
  last_online: string | null;
}

export interface PhishingUrl {
  url: string;
  domain: string;
  suspected_brand: string | null;
}

export interface EpssTopThreat {
  cve: string;
  epss: number;
  percentile: number;
  date: string;
}

export interface NetworkTelemetry {
  infocon_status: string;
  top_attacked_ports: PortAttack[];
  top_attacking_ips: AttackerIp[];
  botnet_c2s: BotnetC2[];
  phishing_urls: PhishingUrl[];
  phishing_total_count: number;
  compromised_ips_sample: string[];
  compromised_ips_total_count: number;
  top_epss_global: EpssTopThreat[];
}

export interface ThreatAlert {
  id: string;
  created_at: string;
  severity: Severity;
  alert_type: string;
  title: string;
  summary: string;
  source: string;
  url: string | null;
  cve_ids: string[];
  matched_reasons: string[];
  ai_risk_score: number;
  acknowledged: boolean;
  linked_item_id: string | null;
}

export interface AlertRules {
  min_severity: Severity;
  alert_on_any_kev: boolean;
  alert_on_vuln_news: boolean;
  alert_on_ai_threats: boolean;
  watchlist_keywords: string[];
  poll_interval_secs: number;
}

export interface FeedHealth {
  id: string;
  name: string;
  category: string;
  url: string;
  status: 'OK' | 'ERROR' | 'PENDING' | string;
  http_status: number | null;
  latency_ms: number;
  items_fetched: number;
  last_success_at: string | null;
  last_error: string | null;
}

export interface LabelCount {
  label: string;
  count: number;
}

export interface RemediationAction {
  cve_id: string;
  vendor_product: string;
  reason: string;
  urgency: string;
  due_date: string | null;
  ai_risk_score: number;
}

export interface DailyVelocityPoint {
  date: string;
  cves: number;
  kev: number;
  news: number;
  exploits: number;
  critical: number;
}

export interface AiThreatBrief {
  generated_at: string;
  global_threat_index: number;
  threat_level_label: string;
  executive_summary: string;
  key_findings: string[];
  top_attack_vectors: LabelCount[];
  top_mitre_tactics: LabelCount[];
  top_targeted_vendors: LabelCount[];
  remediation_priorities: RemediationAction[];
  velocity_7d: DailyVelocityPoint[];
}

export interface DashboardKpis {
  total_vulnerabilities: number;
  critical_count_7d: number;
  high_count_7d: number;
  kev_total_catalog: number;
  kev_tracked: number;
  kev_added_7d: number;
  kev_overdue_count: number;
  high_epss_count: number;
  max_epss_pct: number;
  ai_related_vulns: number;
  news_count_24h: number;
  news_count_7d: number;
  exploit_poc_count: number;
  botnet_c2_count: number;
  phishing_total_count: number;
  compromised_ips_count: number;
  unacknowledged_alerts: number;
  feeds_ok: number;
  feeds_total: number;
  stack_exposed_count: number;
  epss_spike_count: number;
  triage_investigating_count: number;
}

export type AiProviderKind =
  | 'builtin'
  | 'ollama'
  | 'lm_studio'
  | 'llama_cpp'
  | 'open_ai'
  | 'anthropic'
  | 'gemini'
  | 'open_router'
  | 'groq'
  | 'deep_seek'
  | 'mistral'
  | 'xai'
  | 'custom_open_ai';

export interface AiProviderPreset {
  id: AiProviderKind;
  name: string;
  group: 'local' | 'cloud';
  default_base_url: string;
  default_model: string;
  suggested_models: string[];
  requires_api_key: boolean;
  env_var_name: string | null;
  env_key_present: boolean;
  description: string;
}

export interface AiConfigPublic {
  provider: AiProviderKind;
  base_url: string;
  model: string;
  has_api_key: boolean;
  api_key_masked: string;
  env_key_present: boolean;
  keychain_available: boolean;
  keychain_has_key: boolean;
  temperature: number;
  max_tokens: number;
  timeout_secs: number;
  system_prompt: string;
  enrich_briefing: boolean;
  allow_lan_endpoints: boolean;
  save_key_to_keychain: boolean;
  active_label: string;
  presets: AiProviderPreset[];
}

export interface AiConfigUpdate {
  provider?: AiProviderKind;
  base_url?: string;
  model?: string;
  api_key?: string;
  clear_api_key?: boolean;
  temperature?: number;
  max_tokens?: number;
  timeout_secs?: number;
  system_prompt?: string;
  enrich_briefing?: boolean;
  allow_lan_endpoints?: boolean;
  save_key_to_keychain?: boolean;
}

export interface AiModelsResponse {
  ok: boolean;
  models: string[];
  source: string;
  error: string | null;
}

export interface AiTestResponse {
  ok: boolean;
  latency_ms: number;
  provider_label: string;
  model: string;
  reply: string | null;
  error: string | null;
}

export interface CveTriage {
  cve_id: string;
  status: TriageStatus;
  notes: string;
  updated_at: string;
}

export interface StackComponent {
  name: string;
  version: string;
  ecosystem: string;
  source_file: string;
}

export interface MyStackConfig {
  vendors: string[];
  products: string[];
  keywords: string[];
  components: StackComponent[];
  updated_at: string | null;
}

export interface MyStackUpdateRequest {
  vendors?: string[];
  products?: string[];
  keywords?: string[];
  components?: StackComponent[];
}

export interface StackMatchSummary {
  configured: boolean;
  component_count: number;
  vendor_watch_count: number;
  matched_vuln_count: number;
  matched_kev_count: number;
  top_matched_cves: string[];
}

export interface MyStackPayload {
  config: MyStackConfig;
  summary: StackMatchSummary;
  matched_vulnerabilities: Vulnerability[];
}

export interface StackImportResponse {
  format_detected: string;
  imported_components: number;
  total_components: number;
  matched_vulnerabilities: number;
  config: MyStackConfig;
}

export type WebhookKind = 'slack' | 'discord' | 'teams' | 'generic';

export interface WebhookTargetPublic {
  id: string;
  name: string;
  kind: WebhookKind;
  url_masked: string;
  enabled: boolean;
  min_severity: Severity;
  kev_only: boolean;
  stack_only: boolean;
  has_signing_secret: boolean;
  last_status: string | null;
  last_sent_at: string | null;
  failure_count: number;
}

export interface WebhookCreateRequest {
  name: string;
  kind: WebhookKind;
  url: string;
  enabled?: boolean;
  min_severity?: Severity;
  kev_only?: boolean;
  stack_only?: boolean;
  signing_secret?: string;
}

export interface WebhookUpdateRequest {
  enabled?: boolean;
  min_severity?: Severity;
  kev_only?: boolean;
  stack_only?: boolean;
}

export interface WebhookTestResponse {
  ok: boolean;
  status_code: number | null;
  message: string;
  latency_ms: number;
}

export type CustomFeedKind = 'rss_atom' | 'ioc_text' | 'stix21' | 'misp_json';

export interface CustomFeedConfig {
  id: string;
  name: string;
  url: string;
  kind: CustomFeedKind;
  enabled: boolean;
  last_status: string | null;
  last_item_count: number;
  last_checked: string | null;
}

export interface CustomFeedCreateRequest {
  name: string;
  url: string;
  kind: CustomFeedKind;
  enabled?: boolean;
}

export interface FeedSettings {
  disabled_feeds: string[];
  custom_feeds: CustomFeedConfig[];
}

export interface EpssSpike {
  cve_id: string;
  title: string;
  severity: Severity;
  current_epss_pct: number;
  delta_24h_pct: number;
  is_kev: boolean;
  matched_stack: string[];
}

export interface SweepDelta {
  sweep_at: string;
  new_cves: string[];
  new_kevs: string[];
  new_stack_hits: string[];
  epss_spikes: EpssSpike[];
  new_alerts_count: number;
  reviewed: boolean;
}

export interface BulkIocResponse {
  checked: number;
  matched_count: number;
  results: IocLookupResult[];
}

export interface PcapEndpointStat {
  ip: string;
  packets: number;
  bytes: number;
  ports: number[];
  protocols: string[];
  is_flagged: boolean;
  matched_feeds: string[];
  wireshark_filter: string;
}

export interface PcapPortStat {
  port: number;
  protocol: string;
  service_name: string;
  packets: number;
  unique_hosts: number;
  is_high_risk: boolean;
}

export interface PcapHostIndicator {
  host: string;
  kind: string;
  count: number;
  is_flagged: boolean;
  matched_feeds: string[];
  suspicious_reason: string | null;
  wireshark_filter: string;
}

export interface PcapMaliciousHit {
  indicator: string;
  indicator_type: string;
  severity: string;
  feeds: string[];
  detail: string;
  packets: number;
  ports: number[];
  wireshark_filter: string;
}

export interface PcapAnomaly {
  kind: string;
  severity: string;
  title: string;
  detail: string;
  wireshark_filter: string;
}

export interface PcapAnalysisReport {
  filename: string;
  format: string;
  file_bytes: number;
  parse_ms: number;
  packets_parsed: number;
  packets_truncated: boolean;
  total_bytes_observed: number;
  protocol_counts: Record<string, number>;
  unique_external_ips: number;
  unique_internal_ips: number;
  unique_domains: number;
  malicious_hits: PcapMaliciousHit[];
  anomalies: PcapAnomaly[];
  top_external_ips: PcapEndpointStat[];
  top_ports: PcapPortStat[];
  observed_hosts: PcapHostIndicator[];
  http_user_agents: string[];
  master_wireshark_filter: string;
  ai_prompt_summary: string;
  a2ui?: A2uiSurfacePayload | null;
}

export interface SnapshotImportResult {
  vulnerabilities_imported: number;
  news_imported: number;
  snapshot_exported_at: string;
  sha256_verified: boolean;
}

export interface ServerModeInfo {
  version: string;
  wallboard_mode: boolean;
  offline_mode: boolean;
  no_auth_mode: boolean;
  auth_required: boolean;
  setup_required: boolean;
  authenticated: boolean;
  username: string | null;
  totp_enabled: boolean;
  bind_addr: string;
}

export interface AuthStatusResponse {
  auth_required: boolean;
  setup_required: boolean;
  authenticated: boolean;
  username: string | null;
  display_name: string | null;
  totp_enabled: boolean;
  recovery_codes_remaining: number;
  token_auth_enabled: boolean;
  wallboard_mode: boolean;
  offline_mode: boolean;
  no_auth_mode: boolean;
}

export interface AuthLoginPayload {
  username?: string;
  password?: string;
  totp_code?: string;
  remember_me?: boolean;
  token?: string;
}

export interface AuthLoginResponse {
  authenticated: boolean;
  requires_totp?: boolean;
  setup_required?: boolean;
  username?: string;
  display_name?: string;
  totp_enabled?: boolean;
  retry_after_secs?: number;
  error?: string;
}

export interface TotpEnrollResponse {
  secret_b32: string;
  otpauth_uri: string;
  qr_svg_data_uri: string;
}

export interface AuthSessionPublic {
  id_preview: string;
  username: string;
  user_agent: string;
  created_at: string;
  last_seen_at: string;
  expires_at: string;
  is_current: boolean;
}

export interface DashboardPayload {
  ai_brief: AiThreatBrief;
  kpis: DashboardKpis;
  top_vulnerabilities: Vulnerability[];
  recent_news: ThreatNewsItem[];
  telemetry: NetworkTelemetry;
  alerts: ThreatAlert[];
  feed_health: FeedHealth[];
  last_sweep_at: string | null;
  next_sweep_at: string | null;
  poll_interval_secs: number;
  sweep_in_progress: boolean;
  total_sweeps: number;
  active_ai_provider: string;
  active_ai_model: string;
  stack_summary: StackMatchSummary;
  recent_epss_spikes: EpssSpike[];
  latest_delta: SweepDelta | null;
  server_mode: ServerModeInfo;
}

export interface IocLookupResult {
  query: string;
  matched: boolean;
  risk_verdict: string;
  hits: {
    feed: string;
    indicator_type: string;
    detail: string;
  }[];
}

export interface A2uiComponentNode {
  id: string;
  component: string;
  children?: string[];
  props?: Record<string, unknown>;
}

export type A2uiServerMessage =
  | {
      type: 'createSurface';
      surfaceId: string;
      catalogId: string;
      rootComponentId: string;
      title: string;
      subtitle: string;
    }
  | {
      type: 'updateDataModel';
      surfaceId: string;
      path: string;
      value: unknown;
    }
  | {
      type: 'updateComponents';
      surfaceId: string;
      components: A2uiComponentNode[];
    };

export interface A2uiSurfacePayload {
  version: string;
  surface_id: string;
  catalog_id: string;
  intent: string;
  messages: A2uiServerMessage[];
}

export interface AiQueryResponse {
  answer_markdown: string;
  cited_cves: string[];
  matched_news_count: number;
  matched_vuln_count: number;
  analysis_mode: string;
  provider_used: string;
  model_used: string;
  latency_ms: number;
  fallback_reason: string | null;
  a2ui?: A2uiSurfacePayload | null;
}

export type SseEvent =
  | { type: 'NewAlert'; payload: ThreatAlert }
  | { type: 'SweepStarted'; payload: { started_at: string } }
  | {
      type: 'SweepCompleted';
      payload: {
        completed_at: string;
        new_alerts: number;
        total_vulns: number;
        total_news: number;
        next_sweep_at: string;
      };
    }
  | { type: 'Heartbeat'; payload: { server_time: string } };

export type NavTab =
  | 'overview'
  | 'mystack'
  | 'vulnerabilities'
  | 'news'
  | 'network'
  | 'analyst'
  | 'alerts'
  | 'models';
