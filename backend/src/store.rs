use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Instant;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, RwLock};
use tracing::{info, warn};

use crate::models::{
    AiConfig, AiThreatBrief, AlertRules, FeedHealth, NetworkTelemetry, SseEvent, ThreatAlert,
    ThreatNewsItem, Vulnerability,
};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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
    pub last_sweep_at: Option<DateTime<Utc>>,
    pub next_sweep_at: Option<DateTime<Utc>>,
    pub total_sweeps: u64,
    #[serde(skip)]
    pub compromised_ips_set: HashSet<String>,
}

impl ThreatStore {
    pub fn load_from_disk(path: &Path) -> Self {
        if !path.exists() {
            return Self::default();
        }
        match std::fs::read_to_string(path) {
            Ok(raw) => match serde_json::from_str::<ThreatStore>(&raw) {
                Ok(mut store) => {
                    for ip in &store.telemetry.compromised_ips_sample {
                        store.compromised_ips_set.insert(ip.clone());
                    }
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
                    warn!("Failed to parse {}: {}; starting fresh", path.display(), err);
                    Self::default()
                }
            },
            Err(err) => {
                warn!("Failed to read {}: {}; starting fresh", path.display(), err);
                Self::default()
            }
        }
    }

    pub fn save_to_disk(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create_dir_all {}: {}", parent.display(), e))?;
        }
        let tmp_path = path.with_extension("json.tmp");
        let serialized = serde_json::to_string(self)
            .map_err(|e| format!("serialize threat store: {}", e))?;
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

    /// Cap stored records so disk JSON stays fast while keeping recent/high-priority items
    pub fn prune(&mut self) {
        if self.alerts.len() > 250 {
            self.alerts.sort_by(|a, b| b.created_at.cmp(&a.created_at));
            self.alerts.truncate(250);
        }
        if self.vulnerabilities.len() > 1600 {
            let mut entries: Vec<(String, DateTime<Utc>, bool, u8)> = self
                .vulnerabilities
                .iter()
                .map(|(k, v)| (k.clone(), v.published_at, v.is_kev, v.ai_risk_score))
                .collect();
            entries.sort_by(|a, b| {
                b.2.cmp(&a.2)
                    .then_with(|| b.1.cmp(&a.1))
                    .then_with(|| b.3.cmp(&a.3))
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
            entries.sort_by(|a, b| b.1.cmp(&a.1));
            let keep: HashSet<String> = entries.into_iter().take(800).map(|e| e.0).collect();
            self.news.retain(|k, _| keep.contains(k));
        }
        if self.seen_ids.len() > 15000 {
            // Keep all currently active item IDs plus recent entries
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
    }
}

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<RwLock<ThreatStore>>,
    pub sweep_in_progress: Arc<AtomicBool>,
    pub sse_tx: broadcast::Sender<SseEvent>,
    pub http: reqwest::Client,
    pub ai_http: reqwest::Client,
    pub data_path: PathBuf,
    pub started_at: Instant,
}
