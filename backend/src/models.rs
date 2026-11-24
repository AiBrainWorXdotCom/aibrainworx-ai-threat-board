use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn rank(self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }

    pub fn from_str_loose(s: &str) -> Self {
        match s.trim().to_ascii_uppercase().as_str() {
            "CRITICAL" | "CRIT" => Severity::Critical,
            "HIGH" => Severity::High,
            "MEDIUM" | "MODERATE" | "MED" => Severity::Medium,
            "LOW" => Severity::Low,
            _ => Severity::Info,
        }
    }

    pub fn from_cvss(score: f64) -> Self {
        if score >= 9.0 {
            Severity::Critical
        } else if score >= 7.0 {
            Severity::High
        } else if score >= 4.0 {
            Severity::Medium
        } else if score > 0.0 {
            Severity::Low
        } else {
            Severity::Info
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreFactor {
    pub label: String,
    pub points: u8,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub aliases: Vec<String>,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub cvss_score: Option<f64>,
    pub cvss_vector: Option<String>,
    pub epss_score: Option<f64>,
    pub epss_percentile: Option<f64>,
    pub ai_risk_score: u8,
    pub ai_score_factors: Vec<ScoreFactor>,
    pub ai_summary: String,
    pub is_kev: bool,
    pub kev_date_added: Option<String>,
    pub kev_due_date: Option<String>,
    pub kev_required_action: Option<String>,
    pub forensic_triage: Option<String>,
    pub ransomware_use: bool,
    pub has_public_exploit: bool,
    pub is_ai_related: bool,
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub ecosystem: Option<String>,
    pub patched_version: Option<String>,
    pub cwes: Vec<String>,
    pub mitre_tactics: Vec<String>,
    pub attack_vectors: Vec<String>,
    pub sources: Vec<String>,
    pub references: Vec<String>,
    pub published_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub first_seen_at: DateTime<Utc>,
    #[serde(default)]
    pub epss_delta_24h: Option<f64>,
    #[serde(default)]
    pub epss_delta_7d: Option<f64>,
    #[serde(default)]
    pub epss_spike: bool,
    #[serde(default)]
    pub kev_days_remaining: Option<i64>,
    #[serde(default)]
    pub matched_stack: Vec<String>,
    #[serde(default)]
    pub triage_status: TriageStatus,
    #[serde(default)]
    pub triage_notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatNewsItem {
    pub id: String,
    pub source: String,
    pub category: String,
    pub title: String,
    pub summary: String,
    pub url: String,
    pub published_at: DateTime<Utc>,
    pub first_seen_at: DateTime<Utc>,
    pub extracted_cves: Vec<String>,
    pub severity: Severity,
    pub ai_risk_score: u8,
    pub tags: Vec<String>,
    pub is_vulnerability_news: bool,
    pub is_ai_related: bool,
    pub ai_triage_note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PortAttack {
    pub rank: u32,
    pub port: u16,
    pub service_name: String,
    pub records: u64,
    pub targets: u64,
    pub sources: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AttackerIp {
    pub ip: String,
    pub attacks: u64,
    pub count: u64,
    pub first_seen: String,
    pub last_seen: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BotnetC2 {
    pub ip_address: String,
    pub port: u16,
    pub status: String,
    pub hostname: Option<String>,
    pub as_number: Option<u64>,
    pub as_name: Option<String>,
    pub country: Option<String>,
    pub malware: String,
    pub first_seen: Option<String>,
    pub last_online: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PhishingUrl {
    pub url: String,
    pub domain: String,
    pub suspected_brand: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EpssTopThreat {
    pub cve: String,
    pub epss: f64,
    pub percentile: f64,
    pub date: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkTelemetry {
    pub infocon_status: String,
    pub top_attacked_ports: Vec<PortAttack>,
    pub top_attacking_ips: Vec<AttackerIp>,
    pub botnet_c2s: Vec<BotnetC2>,
    pub phishing_urls: Vec<PhishingUrl>,
    pub phishing_total_count: usize,
    pub compromised_ips_sample: Vec<String>,
    pub compromised_ips_total_count: usize,
    pub top_epss_global: Vec<EpssTopThreat>,
}

impl Default for NetworkTelemetry {
    fn default() -> Self {
        Self {
            infocon_status: "green".to_string(),
            top_attacked_ports: Vec::new(),
            top_attacking_ips: Vec::new(),
            botnet_c2s: Vec::new(),
            phishing_urls: Vec::new(),
            phishing_total_count: 0,
            compromised_ips_sample: Vec::new(),
            compromised_ips_total_count: 0,
            top_epss_global: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAlert {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub severity: Severity,
    pub alert_type: String,
    pub title: String,
    pub summary: String,
    pub source: String,
    pub url: Option<String>,
    pub cve_ids: Vec<String>,
    pub matched_reasons: Vec<String>,
    pub ai_risk_score: u8,
    pub acknowledged: bool,
    pub linked_item_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRules {
    pub min_severity: Severity,
    pub alert_on_any_kev: bool,
    pub alert_on_vuln_news: bool,
    pub alert_on_ai_threats: bool,
    pub watchlist_keywords: Vec<String>,
    pub poll_interval_secs: u64,
}

impl Default for AlertRules {
    fn default() -> Self {
        Self {
            min_severity: Severity::High,
            alert_on_any_kev: true,
            alert_on_vuln_news: true,
            alert_on_ai_threats: true,
            watchlist_keywords: vec![
                "zero-day".to_string(),
                "0-day".to_string(),
                "rce".to_string(),
                "actively exploited".to_string(),
                "ransomware".to_string(),
                "ai".to_string(),
                "llm".to_string(),
                "mcp".to_string(),
                "supply chain".to_string(),
                "critical".to_string(),
                "bypass".to_string(),
                "backdoor".to_string(),
            ],
            poll_interval_secs: 3600,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedHealth {
    pub id: String,
    pub name: String,
    pub category: String,
    pub url: String,
    pub status: String,
    pub http_status: Option<u16>,
    pub latency_ms: u64,
    pub items_fetched: usize,
    pub last_success_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelCount {
    pub label: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationAction {
    pub cve_id: String,
    pub vendor_product: String,
    pub reason: String,
    pub urgency: String,
    pub due_date: Option<String>,
    pub ai_risk_score: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailyVelocityPoint {
    pub date: String,
    pub cves: usize,
    pub kev: usize,
    pub news: usize,
    pub exploits: usize,
    pub critical: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiThreatBrief {
    pub generated_at: DateTime<Utc>,
    pub global_threat_index: u8,
    pub threat_level_label: String,
    pub executive_summary: String,
    pub key_findings: Vec<String>,
    pub top_attack_vectors: Vec<LabelCount>,
    pub top_mitre_tactics: Vec<LabelCount>,
    pub top_targeted_vendors: Vec<LabelCount>,
    pub remediation_priorities: Vec<RemediationAction>,
    pub velocity_7d: Vec<DailyVelocityPoint>,
}

impl Default for AiThreatBrief {
    fn default() -> Self {
        Self {
            generated_at: Utc::now(),
            global_threat_index: 0,
            threat_level_label: "GUARDED".to_string(),
            executive_summary:
                "Initializing first intelligence sweep across public cybersecurity feeds..."
                    .to_string(),
            key_findings: Vec::new(),
            top_attack_vectors: Vec::new(),
            top_mitre_tactics: Vec::new(),
            top_targeted_vendors: Vec::new(),
            remediation_priorities: Vec::new(),
            velocity_7d: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum SseEvent {
    NewAlert(ThreatAlert),
    SweepStarted {
        started_at: DateTime<Utc>,
    },
    SweepCompleted {
        completed_at: DateTime<Utc>,
        new_alerts: usize,
        total_vulns: usize,
        total_news: usize,
        next_sweep_at: DateTime<Utc>,
    },
    Heartbeat {
        server_time: DateTime<Utc>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AiProviderKind {
    #[default]
    Builtin,
    Ollama,
    LmStudio,
    LlamaCpp,
    OpenAi,
    Anthropic,
    Gemini,
    OpenRouter,
    Groq,
    DeepSeek,
    Mistral,
    Xai,
    CustomOpenAi,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AiConfig {
    pub provider: AiProviderKind,
    pub base_url: String,
    pub model: String,
    #[serde(skip)]
    pub api_key: String,
    pub temperature: f32,
    pub max_tokens: u32,
    pub timeout_secs: u64,
    pub system_prompt: String,
    pub enrich_briefing: bool,
    pub allow_lan_endpoints: bool,
    pub save_key_to_keychain: bool,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            provider: AiProviderKind::Builtin,
            base_url: String::new(),
            model: "local-threat-graph-v1".to_string(),
            api_key: String::new(),
            temperature: 0.2,
            max_tokens: 1600,
            timeout_secs: 60,
            system_prompt: "You are AiBrainWorX, a senior Cyber Threat Intelligence Analyst. Analyze the live CVE, CISA KEV, EPSS, Exploit-DB, news, and network IOC telemetry provided. Cite exact CVE IDs, highlight active exploitation or AI/ML supply-chain exposure, and give concrete prioritized defensive actions in concise Markdown.".to_string(),
            enrich_briefing: false,
            allow_lan_endpoints: false,
            save_key_to_keychain: false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AiProviderPreset {
    pub id: AiProviderKind,
    pub name: String,
    pub group: String,
    pub default_base_url: String,
    pub default_model: String,
    pub suggested_models: Vec<String>,
    pub requires_api_key: bool,
    pub env_var_name: Option<String>,
    pub env_key_present: bool,
    pub description: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AiConfigPublic {
    pub provider: AiProviderKind,
    pub base_url: String,
    pub model: String,
    pub has_api_key: bool,
    pub api_key_masked: String,
    pub env_key_present: bool,
    pub keychain_available: bool,
    pub keychain_has_key: bool,
    pub temperature: f32,
    pub max_tokens: u32,
    pub timeout_secs: u64,
    pub system_prompt: String,
    pub enrich_briefing: bool,
    pub allow_lan_endpoints: bool,
    pub save_key_to_keychain: bool,
    pub active_label: String,
    pub presets: Vec<AiProviderPreset>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AiConfigUpdate {
    pub provider: Option<AiProviderKind>,
    pub base_url: Option<String>,
    pub model: Option<String>,
    pub api_key: Option<String>,
    pub clear_api_key: Option<bool>,
    pub temperature: Option<f32>,
    pub max_tokens: Option<u32>,
    pub timeout_secs: Option<u64>,
    pub system_prompt: Option<String>,
    pub enrich_briefing: Option<bool>,
    pub allow_lan_endpoints: Option<bool>,
    pub save_key_to_keychain: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AiModelsRequest {
    pub provider: Option<AiProviderKind>,
    pub base_url: Option<String>,
    pub api_key: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AiModelsResponse {
    pub ok: bool,
    pub models: Vec<String>,
    pub source: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AiTestRequest {
    pub provider: Option<AiProviderKind>,
    pub base_url: Option<String>,
    pub model: Option<String>,
    pub api_key: Option<String>,
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AiTestResponse {
    pub ok: bool,
    pub latency_ms: u64,
    pub provider_label: String,
    pub model: String,
    pub reply: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct AiQueryRequest {
    pub query: String,
    pub provider: Option<AiProviderKind>,
    pub base_url: Option<String>,
    pub model: Option<String>,
    pub api_key: Option<String>,
    pub external_api_key: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AiQueryResponse {
    pub answer_markdown: String,
    pub cited_cves: Vec<String>,
    pub matched_news_count: usize,
    pub matched_vuln_count: usize,
    pub analysis_mode: String,
    pub provider_used: String,
    pub model_used: String,
    pub latency_ms: u64,
    pub fallback_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub a2ui: Option<crate::a2ui::A2uiSurfacePayload>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DashboardKpis {
    pub total_vulnerabilities: usize,
    pub critical_count_7d: usize,
    pub high_count_7d: usize,
    pub kev_total_catalog: usize,
    pub kev_tracked: usize,
    pub kev_added_7d: usize,
    pub kev_overdue_count: usize,
    pub high_epss_count: usize,
    pub max_epss_pct: f64,
    pub ai_related_vulns: usize,
    pub news_count_24h: usize,
    pub news_count_7d: usize,
    pub exploit_poc_count: usize,
    pub botnet_c2_count: usize,
    pub phishing_total_count: usize,
    pub compromised_ips_count: usize,
    pub unacknowledged_alerts: usize,
    pub feeds_ok: usize,
    pub feeds_total: usize,
    pub stack_exposed_count: usize,
    pub epss_spike_count: usize,
    pub triage_investigating_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct DashboardPayload {
    pub ai_brief: AiThreatBrief,
    pub kpis: DashboardKpis,
    pub top_vulnerabilities: Vec<Vulnerability>,
    pub recent_news: Vec<ThreatNewsItem>,
    pub telemetry: NetworkTelemetry,
    pub alerts: Vec<ThreatAlert>,
    pub feed_health: Vec<FeedHealth>,
    pub last_sweep_at: Option<DateTime<Utc>>,
    pub next_sweep_at: Option<DateTime<Utc>>,
    pub poll_interval_secs: u64,
    pub sweep_in_progress: bool,
    pub total_sweeps: u64,
    pub active_ai_provider: String,
    pub active_ai_model: String,
    pub stack_summary: StackMatchSummary,
    pub recent_epss_spikes: Vec<EpssSpike>,
    pub latest_delta: Option<SweepDelta>,
    pub server_mode: ServerModeInfo,
}

#[derive(Debug, Clone, Serialize)]
pub struct IocLookupResult {
    pub query: String,
    pub matched: bool,
    pub risk_verdict: String,
    pub hits: Vec<IocHit>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IocHit {
    pub feed: String,
    pub indicator_type: String,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TriageStatus {
    #[default]
    New,
    Investigating,
    Mitigated,
    FalsePositive,
    Accepted,
}

impl TriageStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Investigating => "investigating",
            Self::Mitigated => "mitigated",
            Self::FalsePositive => "false_positive",
            Self::Accepted => "accepted",
        }
    }

    pub fn from_db_str(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "investigating" => Self::Investigating,
            "mitigated" => Self::Mitigated,
            "false_positive" | "falsepositive" => Self::FalsePositive,
            "accepted" => Self::Accepted,
            _ => Self::New,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveTriage {
    pub cve_id: String,
    pub status: TriageStatus,
    pub notes: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CveTriageUpdateRequest {
    pub status: TriageStatus,
    #[serde(default)]
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StackComponent {
    pub name: String,
    pub version: String,
    pub ecosystem: String,
    pub source_file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct MyStackConfig {
    pub vendors: Vec<String>,
    pub products: Vec<String>,
    pub keywords: Vec<String>,
    pub components: Vec<StackComponent>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MyStackUpdateRequest {
    pub vendors: Option<Vec<String>>,
    pub products: Option<Vec<String>>,
    pub keywords: Option<Vec<String>>,
    pub components: Option<Vec<StackComponent>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StackImportRequest {
    pub filename: String,
    pub content: String,
    pub replace: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StackImportResponse {
    pub format_detected: String,
    pub imported_components: usize,
    pub total_components: usize,
    pub matched_vulnerabilities: usize,
    pub config: MyStackConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StackMatchSummary {
    pub configured: bool,
    pub component_count: usize,
    pub vendor_watch_count: usize,
    pub matched_vuln_count: usize,
    pub matched_kev_count: usize,
    pub top_matched_cves: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MyStackPayload {
    pub config: MyStackConfig,
    pub summary: StackMatchSummary,
    pub matched_vulnerabilities: Vec<Vulnerability>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookKind {
    Slack,
    Discord,
    Teams,
    Generic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WebhookTarget {
    pub id: String,
    pub name: String,
    pub kind: WebhookKind,
    pub url: String,
    pub enabled: bool,
    pub min_severity: Severity,
    pub kev_only: bool,
    pub stack_only: bool,
    #[serde(skip)]
    pub signing_secret: String,
    pub has_signing_secret: bool,
    #[serde(default)]
    pub save_secret_to_keychain: bool,
    pub last_status: Option<String>,
    pub last_sent_at: Option<DateTime<Utc>>,
    pub failure_count: u32,
}

impl Default for WebhookTarget {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            kind: WebhookKind::Generic,
            url: String::new(),
            enabled: true,
            min_severity: Severity::High,
            kev_only: false,
            stack_only: false,
            signing_secret: String::new(),
            has_signing_secret: false,
            save_secret_to_keychain: false,
            last_status: None,
            last_sent_at: None,
            failure_count: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct WebhookTargetPublic {
    pub id: String,
    pub name: String,
    pub kind: WebhookKind,
    pub url_masked: String,
    pub enabled: bool,
    pub min_severity: Severity,
    pub kev_only: bool,
    pub stack_only: bool,
    pub has_signing_secret: bool,
    pub save_secret_to_keychain: bool,
    pub last_status: Option<String>,
    pub last_sent_at: Option<DateTime<Utc>>,
    pub failure_count: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WebhookCreateRequest {
    pub name: String,
    pub kind: WebhookKind,
    pub url: String,
    pub enabled: Option<bool>,
    pub min_severity: Option<Severity>,
    pub kev_only: Option<bool>,
    pub stack_only: Option<bool>,
    pub signing_secret: Option<String>,
    pub save_secret_to_keychain: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WebhookUpdateRequest {
    pub enabled: Option<bool>,
    pub min_severity: Option<Severity>,
    pub kev_only: Option<bool>,
    pub stack_only: Option<bool>,
    pub url: Option<String>,
    pub signing_secret: Option<String>,
    pub clear_signing_secret: Option<bool>,
    pub save_secret_to_keychain: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebhookTestResponse {
    pub ok: bool,
    pub status_code: Option<u16>,
    pub message: String,
    pub latency_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustomFeedKind {
    RssAtom,
    IocText,
    Stix21,
    MispJson,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomFeedConfig {
    pub id: String,
    pub name: String,
    pub url: String,
    pub kind: CustomFeedKind,
    pub enabled: bool,
    pub last_status: Option<String>,
    pub last_item_count: usize,
    pub last_checked: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CustomFeedCreateRequest {
    pub name: String,
    pub url: String,
    pub kind: CustomFeedKind,
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct FeedSettings {
    pub disabled_feeds: Vec<String>,
    pub custom_feeds: Vec<CustomFeedConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FeedConfigUpdateRequest {
    pub feed_name: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpssSpike {
    pub cve_id: String,
    pub title: String,
    pub severity: Severity,
    pub current_epss_pct: f64,
    pub delta_24h_pct: f64,
    pub is_kev: bool,
    pub matched_stack: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SweepDelta {
    pub sweep_at: DateTime<Utc>,
    pub new_cves: Vec<String>,
    pub new_kevs: Vec<String>,
    pub new_stack_hits: Vec<String>,
    pub epss_spikes: Vec<EpssSpike>,
    pub new_alerts_count: usize,
    pub reviewed: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BulkIocRequest {
    pub indicators: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BulkIocResponse {
    pub checked: usize,
    pub matched_count: usize,
    pub results: Vec<IocLookupResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotImportResult {
    pub vulnerabilities_imported: usize,
    pub news_imported: usize,
    pub snapshot_exported_at: DateTime<Utc>,
    pub sha256_verified: bool,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ServerModeInfo {
    pub version: String,
    pub wallboard_mode: bool,
    pub offline_mode: bool,
    pub no_auth_mode: bool,
    pub auth_required: bool,
    pub setup_required: bool,
    pub authenticated: bool,
    pub username: Option<String>,
    pub totp_enabled: bool,
    pub bind_addr: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthStatusResponse {
    pub auth_required: bool,
    pub setup_required: bool,
    pub authenticated: bool,
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub totp_enabled: bool,
    pub recovery_codes_remaining: usize,
    pub token_auth_enabled: bool,
    pub wallboard_mode: bool,
    pub offline_mode: bool,
    pub no_auth_mode: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthSetupRequest {
    pub username: String,
    #[serde(default)]
    pub display_name: String,
    pub password: String,
    #[serde(default)]
    pub setup_token: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthLoginRequest {
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub totp_code: String,
    #[serde(default)]
    pub remember_me: bool,
    #[serde(default)]
    pub token: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TotpEnrollResponse {
    pub secret_b32: String,
    pub otpauth_uri: String,
    pub qr_svg_data_uri: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TotpVerifyRequest {
    pub code: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TotpDisableRequest {
    pub password: String,
    #[serde(default)]
    pub code: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthSessionPublic {
    pub id_preview: String,
    pub username: String,
    pub user_agent: String,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub is_current: bool,
}
