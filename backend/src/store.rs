use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Instant;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, RwLock};
use tracing::{info, warn};

use crate::auth::AuthRateLimiter;
use crate::cti::{CtiConfig, CtiEnrichmentResponse, OtxPulseCache};
use crate::models::{
    AiConfig, AiThreatBrief, AlertRules, CveTriage, FeedHealth, FeedSettings, MyStackConfig,
    NetworkTelemetry, SseEvent, SweepDelta, ThreatAlert, ThreatNewsItem, Vulnerability,
    WebhookTarget,
};
use crate::security::{keychain_get, KEYCHAIN_ACCOUNT_AI_API_KEY};
use crate::storage::SqliteStorage;

#[derive(Debug, Clone)]
pub struct ServerModeConfig {
    pub version: String,
    pub wallboard_mode: bool,
    pub offline_mode: bool,
    pub no_auth_mode: bool,
    pub auth_token: Option<String>,
    pub bind_addr: String,
    pub trust_proxy_headers: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ThreatStore {
    pub vulnerabilities: HashMap<String, Vulnerability>,
    pub kev_cve_set: HashSet<String>,
    pub news: HashMap<String, ThreatNewsItem>,
    pub telemetry: NetworkTelemetry,
    pub alerts: Vec<ThreatAlert>,
    pub feed_health: Vec<FeedHealth>,
    pub seen_ids: HashSet<String>,
    pub initialized: bool,
    pub rules: AlertRules,
    #[serde(default)]
    pub ai_config: AiConfig,
    pub ai_brief: AiThreatBrief,
    #[serde(default)]
    pub my_stack: MyStackConfig,
    #[serde(default)]
    pub triage_map: HashMap<String, CveTriage>,
    #[serde(default)]
    pub feed_settings: FeedSettings,
    #[serde(default)]
    pub webhooks: Vec<WebhookTarget>,
    #[serde(default)]
    pub cti_config: CtiConfig,
    #[serde(default)]
    pub otx_pulses: OtxPulseCache,
    #[serde(default)]
    pub cti_enrichment_cache: HashMap<String, CtiEnrichmentResponse>,
    #[serde(default)]
    pub latest_delta: Option<SweepDelta>,
    pub last_sweep_at: Option<DateTime<Utc>>,
    pub next_sweep_at: Option<DateTime<Utc>>,
    pub total_sweeps: u64,
    #[serde(skip)]
    pub compromised_ips_set: HashSet<String>,
}

impl ThreatStore {
    pub fn rebuild_compromised_ip_index(&mut self) {
        self.compromised_ips_set.clear();
        for ip in &self.telemetry.compromised_ips_sample {
            self.compromised_ips_set.insert(ip.clone());
        }
    }

    /// Loads saved secrets from OS Keychain into memory if opted in. Never panics in headless environments.
    pub fn hydrate_secrets_from_keychain(&mut self) {
        if self.ai_config.save_key_to_keychain && self.ai_config.api_key.is_empty() {
            match keychain_get(KEYCHAIN_ACCOUNT_AI_API_KEY) {
                Ok(Some(secret)) if !secret.is_empty() => {
                    self.ai_config.api_key = secret;
                    info!("Loaded AI provider API key from OS Keychain into RAM");
                }
                Ok(_) => {}
                Err(e) => warn!("OS Keychain read skipped for AI key: {e}"),
            }
        }

        for hook in &mut self.webhooks {
            if hook.has_signing_secret && hook.signing_secret.is_empty() {
                let acct = format!("webhook_secret_{}", hook.id);
                if let Ok(Some(sec)) = keychain_get(&acct) {
                    hook.signing_secret = sec;
                }
            }
        }

        crate::cti::hydrate_cti_keys_from_keychain(&mut self.cti_config);
    }

    #[allow(dead_code)]
    pub fn load_from_disk(path: &Path) -> Self {
        if !path.exists() {
            return Self::default();
        }
        match std::fs::read_to_string(path) {
            Ok(raw) => match serde_json::from_str::<ThreatStore>(&raw) {
                Ok(mut store) => {
                    store.rebuild_compromised_ip_index();
                    info!(
                        "Loaded persisted threat store from {} ({} vulns, {} news, {} alerts)",
                        path.display(),
                        store.vulnerabilities.len(),
                        store.news.len(),
                        store.alerts.len()
                    );
                    store
                }
                Err(err) => {
                    warn!(
                        "Failed to parse {}: {}; starting fresh",
                        path.display(),
                        err
                    );
                    Self::default()
                }
            },
            Err(err) => {
                warn!("Failed to read {}: {}; starting fresh", path.display(), err);
                Self::default()
            }
        }
    }

    #[allow(dead_code)]
    pub fn save_to_disk(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create_dir_all {}: {}", parent.display(), e))?;
        }
        let tmp_path = path.with_extension("json.tmp");
        let serialized =
            serde_json::to_string(self).map_err(|e| format!("serialize threat store: {}", e))?;
        std::fs::write(&tmp_path, serialized)
            .map_err(|e| format!("write tmp {}: {}", tmp_path.display(), e))?;
        #[cfg(windows)]
        if path.exists() {
            let _ = std::fs::remove_file(path);
        }
        std::fs::rename(&tmp_path, path)
            .map_err(|e| format!("rename tmp to {}: {}", path.display(), e))?;
        Ok(())
    }

    /// Cap stored records so DB stays fast while keeping recent/high-priority/stack/triaged items.
    pub fn prune(&mut self) {
        if self.alerts.len() > 250 {
            self.alerts.sort_by_key(|a| std::cmp::Reverse(a.created_at));
            self.alerts.truncate(250);
        }
        if self.vulnerabilities.len() > 1600 {
            let mut entries: Vec<(String, DateTime<Utc>, bool, bool, u8)> = self
                .vulnerabilities
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        v.published_at,
                        v.is_kev || !v.matched_stack.is_empty(),
                        v.triage_status != crate::models::TriageStatus::New,
                        v.ai_risk_score,
                    )
                })
                .collect();
            entries.sort_by(|a, b| {
                b.2.cmp(&a.2)
                    .then_with(|| b.3.cmp(&a.3))
                    .then_with(|| b.1.cmp(&a.1))
                    .then_with(|| b.4.cmp(&a.4))
            });
            let keep: HashSet<String> = entries.into_iter().take(1500).map(|e| e.0).collect();
            self.vulnerabilities.retain(|k, _| keep.contains(k));
        }
        if self.news.len() > 900 {
            let mut entries: Vec<(String, DateTime<Utc>)> = self
                .news
                .iter()
                .map(|(k, v)| (k.clone(), v.published_at))
                .collect();
            entries.sort_by_key(|a| std::cmp::Reverse(a.1));
            let keep: HashSet<String> = entries.into_iter().take(800).map(|e| e.0).collect();
            self.news.retain(|k, _| keep.contains(k));
        }
        if self.seen_ids.len() > 15000 {
            let mut keep: HashSet<String> = HashSet::new();
            for k in self.vulnerabilities.keys() {
                keep.insert(k.clone());
            }
            for k in self.news.keys() {
                keep.insert(k.clone());
            }
            for a in &self.alerts {
                if let Some(lid) = &a.linked_item_id {
                    keep.insert(lid.clone());
                }
            }
            self.seen_ids = keep;
        }
        if self.cti_enrichment_cache.len() > 500 {
            let mut entries: Vec<(String, DateTime<Utc>)> = self
                .cti_enrichment_cache
                .iter()
                .map(|(k, v)| (k.clone(), v.enriched_at))
                .collect();
            entries.sort_by_key(|a| std::cmp::Reverse(a.1));
            let keep: HashSet<String> = entries.into_iter().take(400).map(|e| e.0).collect();
            self.cti_enrichment_cache.retain(|k, _| keep.contains(k));
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<RwLock<ThreatStore>>,
    pub db: Arc<SqliteStorage>,
    pub auth_limiter: Arc<AuthRateLimiter>,
    pub sweep_in_progress: Arc<AtomicBool>,
    pub sse_tx: broadcast::Sender<SseEvent>,
    pub http: reqwest::Client,
    pub ai_http: reqwest::Client,
    pub server_mode: ServerModeConfig,
    pub started_at: Instant,
}

impl AppState {
    pub fn persist_store(&self, store: &ThreatStore) -> Result<(), String> {
        self.db.save_store(store)
    }
}
