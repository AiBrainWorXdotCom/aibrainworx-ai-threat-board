use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::{DateTime, Duration, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::models::{
    AiConfig, AiThreatBrief, AlertRules, CveTriage, FeedHealth, FeedSettings, MyStackConfig,
    NetworkTelemetry, SweepDelta, ThreatAlert, ThreatNewsItem, TriageStatus, Vulnerability,
    WebhookTarget,
};
use crate::store::ThreatStore;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct StoreMeta {
    pub initialized: bool,
    pub last_sweep_at: Option<DateTime<Utc>>,
    pub next_sweep_at: Option<DateTime<Utc>>,
    pub total_sweeps: u64,
}

pub struct SqliteStorage {
    db_path: PathBuf,
    conn: Mutex<Connection>,
}

impl SqliteStorage {
    /// Opens (or creates) the embedded SQLite database with WAL journaling and 0600 permissions.
    pub fn open(db_path: PathBuf) -> Result<Self, String> {
        if let Some(parent) = db_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("Failed creating data directory: {e}"))?;
            }
        }

        let conn = Connection::open(&db_path)
            .map_err(|e| format!("Failed opening SQLite database {}: {e}", db_path.display()))?;

        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;",
        )
        .map_err(|e| format!("Failed setting SQLite pragmas: {e}"))?;

        restrict_db_permissions(&db_path);

        let storage = Self {
            db_path,
            conn: Mutex::new(conn),
        };
        storage.init_schema()?;
        Ok(storage)
    }

    fn init_schema(&self) -> Result<(), String> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| "DB mutex poisoned".to_string())?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS store_state (
                key TEXT PRIMARY KEY,
                value_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS vulnerabilities (
                cve_id TEXT PRIMARY KEY,
                severity TEXT NOT NULL,
                cvss_score REAL,
                epss_score REAL,
                ai_risk_score REAL NOT NULL,
                is_kev INTEGER NOT NULL,
                is_ai_related INTEGER NOT NULL,
                is_ransomware INTEGER NOT NULL,
                has_exploit_poc INTEGER NOT NULL,
                published_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_vulns_risk ON vulnerabilities(ai_risk_score DESC);
            CREATE INDEX IF NOT EXISTS idx_vulns_pub ON vulnerabilities(published_at DESC);

            CREATE VIRTUAL TABLE IF NOT EXISTS vulnerabilities_fts USING fts5(
                cve_id UNINDEXED,
                title,
                description,
                vendor_product,
                keywords
            );

            CREATE TABLE IF NOT EXISTS news_items (
                id TEXT PRIMARY KEY,
                published_at TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_news_pub ON news_items(published_at DESC);

            CREATE TABLE IF NOT EXISTS cve_triage (
                cve_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                notes TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS epss_history (
                cve_id TEXT NOT NULL,
                epss_score REAL NOT NULL,
                recorded_at TEXT NOT NULL,
                PRIMARY KEY (cve_id, recorded_at)
            );
            CREATE INDEX IF NOT EXISTS idx_epss_hist_cve_time
                ON epss_history(cve_id, recorded_at DESC);

            CREATE TABLE IF NOT EXISTS sweep_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sweep_at TEXT NOT NULL,
                new_cves_json TEXT NOT NULL,
                new_kevs_json TEXT NOT NULL,
                epss_spikes_json TEXT NOT NULL,
                new_stack_hits_json TEXT NOT NULL,
                new_alerts_count INTEGER NOT NULL,
                reviewed INTEGER NOT NULL DEFAULT 0
            );",
        )
        .map_err(|e| format!("Failed creating SQLite schema: {e}"))?;

        Ok(())
    }

    /// Migrates legacy `threat_store.json` into SQLite once on upgrade, preserving a `.migrated.bak` backup.
    pub fn migrate_legacy_json_if_needed(&self, legacy_json_path: &Path) -> Result<bool, String> {
        if !legacy_json_path.exists() {
            return Ok(false);
        }

        let already_has_state = {
            let conn = self
                .conn
                .lock()
                .map_err(|_| "DB mutex poisoned".to_string())?;
            let count: i64 = conn
                .query_row("SELECT COUNT(*) FROM store_state", [], |row| row.get(0))
                .unwrap_or(0);
            count > 0
        };

        if already_has_state {
            return Ok(false);
        }

        let raw = std::fs::read_to_string(legacy_json_path)
            .map_err(|e| format!("Failed reading legacy {}: {e}", legacy_json_path.display()))?;
        let store: ThreatStore = serde_json::from_str(&raw)
            .map_err(|e| format!("Failed parsing legacy {}: {e}", legacy_json_path.display()))?;

        self.save_store(&store)?;

        let backup_path = legacy_json_path.with_extension("json.migrated.bak");
        let _ = std::fs::rename(legacy_json_path, &backup_path);
        tracing::info!(
            "Migrated legacy JSON store to SQLite (backup: {})",
            backup_path.display()
        );
        Ok(true)
    }

    /// Loads the complete application state from SQLite.
    pub fn load_store(&self) -> Result<ThreatStore, String> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| "DB mutex poisoned".to_string())?;
        let mut store = ThreatStore::default();

        if let Some(meta) = load_kv_json::<StoreMeta>(&conn, "meta")? {
            store.initialized = meta.initialized;
            store.last_sweep_at = meta.last_sweep_at;
            store.next_sweep_at = meta.next_sweep_at;
            store.total_sweeps = meta.total_sweeps;
        }
        if let Some(rules) = load_kv_json::<AlertRules>(&conn, "rules")? {
            store.rules = rules;
        }
        if let Some(ai_cfg) = load_kv_json::<AiConfig>(&conn, "ai_config")? {
            store.ai_config = ai_cfg;
        }
        if let Some(brief) = load_kv_json::<AiThreatBrief>(&conn, "ai_brief")? {
            store.ai_brief = brief;
        }
        if let Some(stack) = load_kv_json::<MyStackConfig>(&conn, "my_stack")? {
            store.my_stack = stack;
        }
        if let Some(fs) = load_kv_json::<FeedSettings>(&conn, "feed_settings")? {
            store.feed_settings = fs;
        }
        if let Some(hooks) = load_kv_json::<Vec<WebhookTarget>>(&conn, "webhooks")? {
            store.webhooks = hooks;
        }
        if let Some(tele) = load_kv_json::<NetworkTelemetry>(&conn, "telemetry")? {
            store.telemetry = tele;
        }
        if let Some(alerts) = load_kv_json::<Vec<ThreatAlert>>(&conn, "alerts")? {
            store.alerts = alerts;
        }
        if let Some(health) = load_kv_json::<Vec<FeedHealth>>(&conn, "feed_health")? {
            store.feed_health = health;
        }
        if let Some(seen) = load_kv_json::<HashSet<String>>(&conn, "seen_ids")? {
            store.seen_ids = seen;
        }
        if let Some(kevs) = load_kv_json::<HashSet<String>>(&conn, "kev_cve_set")? {
            store.kev_cve_set = kevs;
        }

        // Load triage table
        {
            let mut stmt = conn
                .prepare("SELECT cve_id, status, notes, updated_at FROM cve_triage")
                .map_err(|e| format!("Failed preparing triage query: {e}"))?;
            let rows = stmt
                .query_map([], |row| {
                    let cve_id: String = row.get(0)?;
                    let status_raw: String = row.get(1)?;
                    let notes: String = row.get(2)?;
                    let updated_str: String = row.get(3)?;
                    let updated_at = DateTime::parse_from_rfc3339(&updated_str)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now());
                    Ok((
                        cve_id.clone(),
                        CveTriage {
                            cve_id,
                            status: TriageStatus::from_db_str(&status_raw),
                            notes,
                            updated_at,
                        },
                    ))
                })
                .map_err(|e| format!("Failed querying triage: {e}"))?;

            for row in rows.flatten() {
                store.triage_map.insert(row.0, row.1);
            }
        }

        // Load vulnerabilities and apply any saved triage status
        {
            let mut stmt = conn
                .prepare("SELECT payload_json FROM vulnerabilities")
                .map_err(|e| format!("Failed preparing vulnerabilities query: {e}"))?;
            let rows = stmt
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(|e| format!("Failed querying vulnerabilities: {e}"))?;

            for json_str in rows.flatten() {
                if let Ok(mut vuln) = serde_json::from_str::<Vulnerability>(&json_str) {
                    if let Some(t) = store.triage_map.get(&vuln.id) {
                        vuln.triage_status = t.status;
                        vuln.triage_notes = t.notes.clone();
                    }
                    store.vulnerabilities.insert(vuln.id.clone(), vuln);
                }
            }
        }

        // Load news items
        {
            let mut stmt = conn
                .prepare("SELECT payload_json FROM news_items")
                .map_err(|e| format!("Failed preparing news query: {e}"))?;
            let rows = stmt
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(|e| format!("Failed querying news: {e}"))?;

            for json_str in rows.flatten() {
                if let Ok(item) = serde_json::from_str::<ThreatNewsItem>(&json_str) {
                    store.news.insert(item.id.clone(), item);
                }
            }
        }

        // Load latest sweep delta if recorded
        store.latest_delta = load_latest_sweep_delta_locked(&conn);

        store.rebuild_compromised_ip_index();
        Ok(store)
    }

    /// Atomically persists the full ThreatStore into SQLite inside a single transaction.
    pub fn save_store(&self, store: &ThreatStore) -> Result<(), String> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| "DB mutex poisoned".to_string())?;
        let tx = conn
            .transaction()
            .map_err(|e| format!("Failed starting SQLite transaction: {e}"))?;
        let now_str = Utc::now().to_rfc3339();

        let meta = StoreMeta {
            initialized: store.initialized,
            last_sweep_at: store.last_sweep_at,
            next_sweep_at: store.next_sweep_at,
            total_sweeps: store.total_sweeps,
        };

        save_kv_json(&tx, "meta", &meta, &now_str)?;
        save_kv_json(&tx, "rules", &store.rules, &now_str)?;
        save_kv_json(&tx, "ai_config", &store.ai_config, &now_str)?;
        save_kv_json(&tx, "ai_brief", &store.ai_brief, &now_str)?;
        save_kv_json(&tx, "my_stack", &store.my_stack, &now_str)?;
        save_kv_json(&tx, "feed_settings", &store.feed_settings, &now_str)?;
        save_kv_json(&tx, "webhooks", &store.webhooks, &now_str)?;
        save_kv_json(&tx, "telemetry", &store.telemetry, &now_str)?;
        save_kv_json(&tx, "alerts", &store.alerts, &now_str)?;
        save_kv_json(&tx, "feed_health", &store.feed_health, &now_str)?;
        save_kv_json(&tx, "seen_ids", &store.seen_ids, &now_str)?;
        save_kv_json(&tx, "kev_cve_set", &store.kev_cve_set, &now_str)?;

        // Sync vulnerabilities table & FTS5 index cleanly
        tx.execute("DELETE FROM vulnerabilities", [])
            .map_err(|e| format!("Failed clearing vulnerabilities table: {e}"))?;
        tx.execute("DELETE FROM vulnerabilities_fts", [])
            .map_err(|e| format!("Failed clearing FTS index: {e}"))?;

        {
            let mut ins_vuln = tx
                .prepare_cached(
                    "INSERT INTO vulnerabilities (
                        cve_id, severity, cvss_score, epss_score, ai_risk_score,
                        is_kev, is_ai_related, is_ransomware, has_exploit_poc,
                        published_at, updated_at, payload_json
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                )
                .map_err(|e| format!("Failed preparing vulnerability insert: {e}"))?;

            let mut ins_fts = tx
                .prepare_cached(
                    "INSERT INTO vulnerabilities_fts (
                        cve_id, title, description, vendor_product, keywords
                    ) VALUES (?1, ?2, ?3, ?4, ?5)",
                )
                .map_err(|e| format!("Failed preparing FTS insert: {e}"))?;

            for v in store.vulnerabilities.values() {
                let payload_json = serde_json::to_string(v)
                    .map_err(|e| format!("Failed serializing {}: {e}", v.id))?;
                let sev_str = v.severity.as_str();

                ins_vuln
                    .execute(params![
                        v.id,
                        sev_str,
                        v.cvss_score,
                        v.epss_score,
                        v.ai_risk_score as f64,
                        i64::from(v.is_kev),
                        i64::from(v.is_ai_related),
                        i64::from(v.ransomware_use),
                        i64::from(v.has_public_exploit),
                        v.published_at.to_rfc3339(),
                        v.updated_at.to_rfc3339(),
                        payload_json,
                    ])
                    .map_err(|e| format!("Failed inserting vuln {}: {e}", v.id))?;

                let vendor_product = format!(
                    "{} {} {} {}",
                    v.vendor.as_deref().unwrap_or(""),
                    v.product.as_deref().unwrap_or(""),
                    v.ecosystem.as_deref().unwrap_or(""),
                    v.matched_stack.join(" ")
                );
                let keywords = format!(
                    "{} {} {} {} {}",
                    v.aliases.join(" "),
                    v.cwes.join(" "),
                    v.mitre_tactics.join(" "),
                    v.attack_vectors.join(" "),
                    v.sources.join(" ")
                );

                ins_fts
                    .execute(params![
                        v.id,
                        v.title,
                        v.description,
                        vendor_product,
                        keywords
                    ])
                    .map_err(|e| format!("Failed inserting FTS {}: {e}", v.id))?;
            }
        }

        // Sync news_items
        tx.execute("DELETE FROM news_items", [])
            .map_err(|e| format!("Failed clearing news_items: {e}"))?;
        {
            let mut ins_news = tx
                .prepare_cached(
                    "INSERT INTO news_items (id, published_at, payload_json) VALUES (?1, ?2, ?3)",
                )
                .map_err(|e| format!("Failed preparing news insert: {e}"))?;

            for n in store.news.values() {
                let payload_json = serde_json::to_string(n)
                    .map_err(|e| format!("Failed serializing news {}: {e}", n.id))?;
                ins_news
                    .execute(params![n.id, n.published_at.to_rfc3339(), payload_json])
                    .map_err(|e| format!("Failed inserting news {}: {e}", n.id))?;
            }
        }

        // Sync cve_triage entries
        {
            let mut ins_triage = tx
                .prepare_cached(
                    "INSERT INTO cve_triage (cve_id, status, notes, updated_at)
                     VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(cve_id) DO UPDATE SET
                        status = excluded.status,
                        notes = excluded.notes,
                        updated_at = excluded.updated_at",
                )
                .map_err(|e| format!("Failed preparing triage upsert: {e}"))?;

            for t in store.triage_map.values() {
                ins_triage
                    .execute(params![
                        t.cve_id,
                        t.status.as_str(),
                        t.notes,
                        t.updated_at.to_rfc3339()
                    ])
                    .map_err(|e| format!("Failed upserting triage {}: {e}", t.cve_id))?;
            }
        }

        tx.commit()
            .map_err(|e| format!("Failed committing SQLite transaction: {e}"))?;
        restrict_db_permissions(&self.db_path);
        Ok(())
    }

    pub fn upsert_triage(&self, triage: &CveTriage) -> Result<(), String> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| "DB mutex poisoned".to_string())?;
        conn.execute(
            "INSERT INTO cve_triage (cve_id, status, notes, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(cve_id) DO UPDATE SET
                status = excluded.status,
                notes = excluded.notes,
                updated_at = excluded.updated_at",
            params![
                triage.cve_id,
                triage.status.as_str(),
                triage.notes,
                triage.updated_at.to_rfc3339()
            ],
        )
        .map_err(|e| format!("Failed saving CVE triage: {e}"))?;
        Ok(())
    }

    /// Records EPSS score samples for tracked CVEs and prunes history older than 14 days.
    pub fn record_epss_samples(
        &self,
        samples: &[(String, f64, DateTime<Utc>)],
    ) -> Result<(), String> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| "DB mutex poisoned".to_string())?;
        let tx = conn
            .transaction()
            .map_err(|e| format!("Failed starting EPSS transaction: {e}"))?;

        {
            let mut ins = tx
                .prepare_cached(
                    "INSERT OR IGNORE INTO epss_history (cve_id, epss_score, recorded_at)
                     VALUES (?1, ?2, ?3)",
                )
                .map_err(|e| format!("Failed preparing EPSS insert: {e}"))?;
            for (cve_id, score, ts) in samples {
                let _ = ins.execute(params![cve_id, score, ts.to_rfc3339()]);
            }
        }

        let cutoff = (Utc::now() - Duration::days(14)).to_rfc3339();
        let _ = tx.execute(
            "DELETE FROM epss_history WHERE recorded_at < ?1",
            params![cutoff],
        );

        tx.commit()
            .map_err(|e| format!("Failed committing EPSS history: {e}"))
    }

    /// Computes EPSS 24h and 7d deltas (in raw 0..1 EPSS score space) relative to prior recorded samples.
    pub fn compute_epss_deltas(
        &self,
        current_scores: &HashMap<String, f64>,
        now: DateTime<Utc>,
    ) -> HashMap<String, (Option<f64>, Option<f64>)> {
        let mut out = HashMap::new();
        let Ok(conn) = self.conn.lock() else {
            return out;
        };

        let target_24h = (now - Duration::hours(24)).to_rfc3339();
        let min_24h_age = (now - Duration::hours(1)).to_rfc3339();
        let target_7d = (now - Duration::days(7)).to_rfc3339();

        let mut stmt = match conn.prepare(
            "SELECT epss_score, recorded_at FROM epss_history
             WHERE cve_id = ?1 ORDER BY recorded_at ASC",
        ) {
            Ok(s) => s,
            Err(_) => return out,
        };

        for (cve_id, current) in current_scores {
            let mut rows = match stmt.query_map(params![cve_id], |r| {
                Ok((r.get::<_, f64>(0)?, r.get::<_, String>(1)?))
            }) {
                Ok(r) => r.flatten().collect::<Vec<_>>(),
                Err(_) => continue,
            };

            if rows.is_empty() {
                continue;
            }
            rows.sort_by(|a, b| a.1.cmp(&b.1));

            // 24h baseline: prefer most recent sample <= 24h ago; otherwise earliest sample at least 1h old
            let baseline_24h = rows
                .iter()
                .rev()
                .find(|(_, ts)| ts <= &target_24h)
                .or_else(|| rows.iter().find(|(_, ts)| ts <= &min_24h_age))
                .map(|(s, _)| *s);

            let baseline_7d = rows
                .iter()
                .rev()
                .find(|(_, ts)| ts <= &target_7d)
                .or_else(|| rows.first())
                .map(|(s, _)| *s);

            let d24 = baseline_24h.map(|b| *current - b);
            let d7 = baseline_7d.map(|b| *current - b);
            if d24.is_some() || d7.is_some() {
                out.insert(cve_id.clone(), (d24, d7));
            }
        }

        out
    }

    pub fn record_sweep_delta(&self, delta: &SweepDelta) -> Result<(), String> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| "DB mutex poisoned".to_string())?;
        let cves_json = serde_json::to_string(&delta.new_cves).unwrap_or_else(|_| "[]".into());
        let kevs_json = serde_json::to_string(&delta.new_kevs).unwrap_or_else(|_| "[]".into());
        let spikes_json = serde_json::to_string(&delta.epss_spikes).unwrap_or_else(|_| "[]".into());
        let stack_json =
            serde_json::to_string(&delta.new_stack_hits).unwrap_or_else(|_| "[]".into());

        conn.execute(
            "INSERT INTO sweep_snapshots (
                sweep_at, new_cves_json, new_kevs_json, epss_spikes_json,
                new_stack_hits_json, new_alerts_count, reviewed
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                delta.sweep_at.to_rfc3339(),
                cves_json,
                kevs_json,
                spikes_json,
                stack_json,
                delta.new_alerts_count as i64,
                i64::from(delta.reviewed),
            ],
        )
        .map_err(|e| format!("Failed recording sweep snapshot: {e}"))?;

        // Retain the latest 90 sweep snapshots
        let _ = conn.execute(
            "DELETE FROM sweep_snapshots
             WHERE id NOT IN (SELECT id FROM sweep_snapshots ORDER BY id DESC LIMIT 90)",
            [],
        );
        Ok(())
    }

    pub fn mark_latest_delta_reviewed(&self) -> Result<(), String> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| "DB mutex poisoned".to_string())?;
        conn.execute(
            "UPDATE sweep_snapshots SET reviewed = 1
             WHERE id = (SELECT MAX(id) FROM sweep_snapshots)",
            [],
        )
        .map_err(|e| format!("Failed marking delta reviewed: {e}"))?;
        Ok(())
    }

    /// Full-text search across CVEs using FTS5, safely sanitizing user input to prevent syntax errors.
    pub fn search_cve_ids_fts(&self, raw_query: &str, limit: usize) -> Option<HashSet<String>> {
        let tokens: Vec<String> = raw_query
            .split(|c: char| !c.is_alphanumeric() && c != '-' && c != '_')
            .filter(|tok| {
                tok.len() >= 2
                    && !matches!(
                        tok.to_ascii_uppercase().as_str(),
                        "AND" | "OR" | "NOT" | "NEAR"
                    )
            })
            .take(8)
            .map(|tok| format!("\"{}\"*", tok.replace('"', "")))
            .collect();

        if tokens.is_empty() {
            return None;
        }
        let match_expr = tokens.join(" AND ");

        let conn = self.conn.lock().ok()?;
        let mut stmt = conn
            .prepare(
                "SELECT cve_id FROM vulnerabilities_fts
                 WHERE vulnerabilities_fts MATCH ?1 LIMIT ?2",
            )
            .ok()?;

        let ids: HashSet<String> = stmt
            .query_map(params![match_expr, limit as i64], |r| r.get::<_, String>(0))
            .ok()?
            .flatten()
            .collect();

        Some(ids)
    }
}

fn load_kv_json<T: for<'de> Deserialize<'de>>(
    conn: &Connection,
    key: &str,
) -> Result<Option<T>, String> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT value_json FROM store_state WHERE key = ?1",
            params![key],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| format!("Failed querying store_state[{key}]: {e}"))?;

    match raw {
        Some(json_str) => serde_json::from_str::<T>(&json_str)
            .map(Some)
            .map_err(|e| format!("Failed deserializing store_state[{key}]: {e}")),
        None => Ok(None),
    }
}

fn save_kv_json<T: Serialize>(
    tx: &rusqlite::Transaction<'_>,
    key: &str,
    val: &T,
    now_str: &str,
) -> Result<(), String> {
    let json_str = serde_json::to_string(val)
        .map_err(|e| format!("Failed serializing store_state[{key}]: {e}"))?;
    tx.execute(
        "INSERT INTO store_state (key, value_json, updated_at)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(key) DO UPDATE SET
            value_json = excluded.value_json,
            updated_at = excluded.updated_at",
        params![key, json_str, now_str],
    )
    .map_err(|e| format!("Failed storing store_state[{key}]: {e}"))?;
    Ok(())
}

fn load_latest_sweep_delta_locked(conn: &Connection) -> Option<SweepDelta> {
    conn.query_row(
        "SELECT sweep_at, new_cves_json, new_kevs_json, epss_spikes_json,
                new_stack_hits_json, new_alerts_count, reviewed
         FROM sweep_snapshots ORDER BY id DESC LIMIT 1",
        [],
        |row| {
            let sweep_at_str: String = row.get(0)?;
            let cves_json: String = row.get(1)?;
            let kevs_json: String = row.get(2)?;
            let spikes_json: String = row.get(3)?;
            let stack_json: String = row.get(4)?;
            let alerts_cnt: i64 = row.get(5)?;
            let reviewed: i64 = row.get(6)?;

            Ok(SweepDelta {
                sweep_at: DateTime::parse_from_rfc3339(&sweep_at_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                new_cves: serde_json::from_str(&cves_json).unwrap_or_default(),
                new_kevs: serde_json::from_str(&kevs_json).unwrap_or_default(),
                epss_spikes: serde_json::from_str(&spikes_json).unwrap_or_default(),
                new_stack_hits: serde_json::from_str(&stack_json).unwrap_or_default(),
                new_alerts_count: alerts_cnt.max(0) as usize,
                reviewed: reviewed != 0,
            })
        },
    )
    .ok()
}

fn restrict_db_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o600);
            let _ = std::fs::set_permissions(path, perms);
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Severity;

    fn temp_db_path() -> PathBuf {
        std::env::temp_dir().join(format!("abw_test_{}.db", uuid::Uuid::new_v4()))
    }

    #[test]
    fn sqlite_roundtrip_triage_fts_and_epss_deltas() {
        let db_path = temp_db_path();
        let storage = SqliteStorage::open(db_path.clone()).unwrap();

        let now = Utc::now();
        let mut store = ThreatStore {
            initialized: true,
            total_sweeps: 2,
            ..Default::default()
        };
        store.vulnerabilities.insert(
            "CVE-2026-9999".to_string(),
            Vulnerability {
                id: "CVE-2026-9999".to_string(),
                aliases: vec![],
                title: "Critical OpenSSL Buffer Overflow".to_string(),
                description: "Heap overflow in TLS handshake parsing.".to_string(),
                severity: Severity::Critical,
                cvss_score: Some(9.8),
                cvss_vector: None,
                epss_score: Some(0.45),
                epss_percentile: Some(0.95),
                ai_risk_score: 92,
                ai_score_factors: vec![],
                ai_summary: String::new(),
                is_kev: true,
                kev_date_added: None,
                kev_due_date: None,
                kev_required_action: None,
                forensic_triage: None,
                ransomware_use: true,
                has_public_exploit: true,
                is_ai_related: false,
                vendor: Some("openssl".to_string()),
                product: Some("openssl".to_string()),
                ecosystem: Some("c".to_string()),
                patched_version: None,
                cwes: vec!["CWE-122".to_string()],
                mitre_tactics: vec![],
                attack_vectors: vec![],
                sources: vec!["NVD".to_string()],
                references: vec![],
                published_at: now,
                updated_at: now,
                first_seen_at: now,
                epss_delta_24h: None,
                epss_delta_7d: None,
                epss_spike: false,
                kev_days_remaining: None,
                matched_stack: vec!["openssl".to_string()],
                triage_status: TriageStatus::New,
                triage_notes: String::new(),
            },
        );
        store.triage_map.insert(
            "CVE-2026-9999".to_string(),
            CveTriage {
                cve_id: "CVE-2026-9999".to_string(),
                status: TriageStatus::Investigating,
                notes: "Patching edge ingress".to_string(),
                updated_at: now,
            },
        );

        storage.save_store(&store).unwrap();

        // Check FTS5 search handles punctuation & FTS keywords safely and finds the CVE
        let ids = storage.search_cve_ids_fts("OpenSSL OR \"", 20).unwrap();
        assert!(ids.contains("CVE-2026-9999"));

        // Verify EPSS delta tracking
        storage
            .record_epss_samples(&[("CVE-2026-9999".to_string(), 0.12, now - Duration::hours(25))])
            .unwrap();
        let mut current = HashMap::new();
        current.insert("CVE-2026-9999".to_string(), 0.45);
        let deltas = storage.compute_epss_deltas(&current, now);
        let (d24, _) = deltas.get("CVE-2026-9999").unwrap();
        assert!((d24.unwrap() - 0.33).abs() < 1e-6);

        // Reload and verify triage persisted cleanly
        let loaded = storage.load_store().unwrap();
        let v = loaded.vulnerabilities.get("CVE-2026-9999").unwrap();
        assert_eq!(v.triage_status, TriageStatus::Investigating);
        assert_eq!(v.triage_notes, "Patching edge ingress");

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(db_path.with_extension("db-wal"));
        let _ = std::fs::remove_file(db_path.with_extension("db-shm"));
    }
}
