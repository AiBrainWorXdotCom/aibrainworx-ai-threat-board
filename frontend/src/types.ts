export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface ScoreFactor {
  label: string;
  points: number;
  detail: string;
}

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
  temperature: number;
  max_tokens: number;
  timeout_secs: number;
  system_prompt: string;
  enrich_briefing: boolean;
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
  | 'vulnerabilities'
  | 'news'
  | 'network'
  | 'analyst'
  | 'alerts'
  | 'models';
