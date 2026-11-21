use std::convert::Infallible;
use std::sync::atomic::Ordering;
use std::time::Duration;

use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use futures::stream::Stream;
use serde::Deserialize;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use uuid::Uuid;

use crate::ai_providers::{
    apply_config_update, default_base_url, default_model, effective_base_url, effective_model,
    list_models, provider_display_name, test_connection, to_public_config,
};
use crate::analyzer::{answer_analyst_query, triage_vulnerability_with_ai};
use crate::feeds::run_sweep;
use crate::models::{
    AiConfig, AiConfigUpdate, AiModelsRequest, AiProviderKind, AiQueryRequest, AiTestRequest,
    AlertRules, DashboardKpis, DashboardPayload, IocHit, IocLookupResult, Severity, SseEvent,
    ThreatAlert, ThreatNewsItem, Vulnerability,
};
use crate::store::AppState;

pub fn api_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/dashboard", get(dashboard))
        .route("/vulnerabilities", get(list_vulnerabilities))
        .route("/vulnerabilities/{id}", get(get_vulnerability))
        .route("/news", get(list_news))
        .route("/iocs", get(get_iocs))
        .route("/alerts", get(list_alerts))
        .route("/alerts/ack-all", post(ack_all_alerts))
        .route("/alerts/test", post(trigger_test_alert))
        .route("/alerts/{id}/ack", post(ack_alert))
        .route("/feeds", get(list_feeds))
        .route("/refresh", post(trigger_refresh))
        .route("/rules", get(get_rules).put(update_rules))
        .route("/ai/config", get(get_ai_config).put(update_ai_config))
        .route("/ai/models", post(list_ai_models))
        .route("/ai/test", post(test_ai_connection))
        .route("/ai/analyze", post(ai_analyze))
        .route("/ai/triage/{id}", post(ai_triage_vuln))
        .route("/events", get(sse_events))
        .layer(DefaultBodyLimit::max(256 * 1024))
        .with_state(state)
}

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let store = state.store.read().await;
    let sweep_in_progress = state.sweep_in_progress.load(Ordering::SeqCst);
    Json(serde_json::json!({
        "status": "ok",
        "service": "AiBrainWorX CyberThreat Engine (Rust)",
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_secs": state.started_at.elapsed().as_secs(),
        "total_sweeps": store.total_sweeps,
        "last_sweep_at": store.last_sweep_at,
        "next_sweep_at": store.next_sweep_at,
        "sweep_in_progress": sweep_in_progress,
        "poll_interval_secs": store.rules.poll_interval_secs,
        "tracked_vulnerabilities": store.vulnerabilities.len(),
        "tracked_news": store.news.len(),
        "feeds_ok": store.feed_health.iter().filter(|f| f.status == "OK").count(),
        "feeds_total": store.feed_health.len(),
    }))
}

async fn dashboard(State(state): State<AppState>) -> impl IntoResponse {
    let store = state.store.read().await;
    let now = Utc::now();
    let cutoff_24h = now - chrono::Duration::hours(24);
    let cutoff_7d = now - chrono::Duration::days(7);

    let mut vulns: Vec<Vulnerability> = store.vulnerabilities.values().cloned().collect();
    vulns.sort_by(|a, b| {
        b.ai_risk_score
            .cmp(&a.ai_risk_score)
            .then_with(|| b.published_at.cmp(&a.published_at))
    });

    let critical_count_7d = vulns
        .iter()
        .filter(|v| v.published_at >= cutoff_7d && v.severity == Severity::Critical)
        .count();
    let high_count_7d = vulns
        .iter()
        .filter(|v| v.published_at >= cutoff_7d && v.severity == Severity::High)
        .count();
    let kev_tracked = vulns.iter().filter(|v| v.is_kev).count();
    let kev_added_7d = vulns
        .iter()
        .filter(|v| v.is_kev && v.published_at >= cutoff_7d)
        .count();
    let high_epss_count = vulns
        .iter()
        .filter(|v| v.epss_score.unwrap_or(0.0) >= 0.5)
        .count();
    let max_epss_pct = vulns
        .iter()
        .filter_map(|v| v.epss_score)
        .fold(0.0_f64, f64::max)
        * 100.0;
    let ai_related_vulns = vulns.iter().filter(|v| v.is_ai_related).count();

    let mut news: Vec<ThreatNewsItem> = store.news.values().cloned().collect();
    news.sort_by(|a, b| b.published_at.cmp(&a.published_at));

    let news_count_24h = news.iter().filter(|n| n.published_at >= cutoff_24h).count();
    let news_count_7d = news.iter().filter(|n| n.published_at >= cutoff_7d).count();
    let exploit_poc_count = news
        .iter()
        .filter(|n| n.category == "Exploit PoC" || n.tags.iter().any(|t| t == "Exploit PoC"))
        .count();

    let unacknowledged_alerts = store.alerts.iter().filter(|a| !a.acknowledged).count();
    let feeds_ok = store.feed_health.iter().filter(|f| f.status == "OK").count();

    let kpis = DashboardKpis {
        total_vulnerabilities: vulns.len(),
        critical_count_7d,
        high_count_7d,
        kev_total_catalog: store.kev_cve_set.len().max(kev_tracked),
        kev_tracked,
        kev_added_7d,
        high_epss_count,
        max_epss_pct,
        ai_related_vulns,
        news_count_24h,
        news_count_7d,
        exploit_poc_count,
        botnet_c2_count: store.telemetry.botnet_c2s.len(),
        phishing_total_count: store.telemetry.phishing_total_count,
        compromised_ips_count: store.telemetry.compromised_ips_total_count,
        unacknowledged_alerts,
        feeds_ok,
        feeds_total: store.feed_health.len(),
    };

    let payload = DashboardPayload {
        ai_brief: store.ai_brief.clone(),
        kpis,
        top_vulnerabilities: vulns.into_iter().take(35).collect(),
        recent_news: news.into_iter().take(35).collect(),
        telemetry: store.telemetry.clone(),
        alerts: store.alerts.iter().take(50).cloned().collect(),
        feed_health: store.feed_health.clone(),
        last_sweep_at: store.last_sweep_at,
        next_sweep_at: store.next_sweep_at,
        poll_interval_secs: store.rules.poll_interval_secs,
        sweep_in_progress: state.sweep_in_progress.load(Ordering::SeqCst),
        total_sweeps: store.total_sweeps,
        active_ai_provider: provider_display_name(store.ai_config.provider).to_string(),
        active_ai_model: effective_model(&store.ai_config),
    };

    Json(payload)
}

#[derive(Debug, Deserialize)]
struct VulnQuery {
    q: Option<String>,
    severity: Option<String>,
    kev_only: Option<bool>,
    ai_only: Option<bool>,
    ransomware_only: Option<bool>,
    exploit_only: Option<bool>,
    days: Option<i64>,
    sort: Option<String>,
    limit: Option<usize>,
}

async fn list_vulnerabilities(
    State(state): State<AppState>,
    Query(params): Query<VulnQuery>,
) -> impl IntoResponse {
    let store = state.store.read().await;
    let now = Utc::now();
    let q_lower = params.q.as_deref().unwrap_or("").trim().to_ascii_lowercase();
    let sev_filter = params
        .severity
        .as_deref()
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("ALL"))
        .map(Severity::from_str_loose);

    let mut list: Vec<Vulnerability> = store
        .vulnerabilities
        .values()
        .filter(|v| {
            if let Some(sev) = sev_filter {
                if v.severity != sev {
                    return false;
                }
            }
            if params.kev_only.unwrap_or(false) && !v.is_kev {
                return false;
            }
            if params.ai_only.unwrap_or(false) && !v.is_ai_related {
                return false;
            }
            if params.ransomware_only.unwrap_or(false) && !v.ransomware_use {
                return false;
            }
            if params.exploit_only.unwrap_or(false) && !v.has_public_exploit {
                return false;
            }
            if let Some(days) = params.days {
                if days > 0 && (now - v.published_at).num_days() > days {
                    return false;
                }
            }
            if !q_lower.is_empty() {
                let hay = format!(
                    "{} {} {} {} {} {} {}",
                    v.id,
                    v.aliases.join(" "),
                    v.title,
                    v.description,
                    v.vendor.as_deref().unwrap_or(""),
                    v.product.as_deref().unwrap_or(""),
                    v.ecosystem.as_deref().unwrap_or("")
                )
                .to_ascii_lowercase();
                if !hay.contains(&q_lower) {
                    return false;
                }
            }
            true
        })
        .cloned()
        .collect();

    match params.sort.as_deref().unwrap_or("ai_score") {
        "cvss" => list.sort_by(|a, b| {
            b.cvss_score
                .unwrap_or(0.0)
                .partial_cmp(&a.cvss_score.unwrap_or(0.0))
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| b.ai_risk_score.cmp(&a.ai_risk_score))
        }),
        "epss" => list.sort_by(|a, b| {
            b.epss_score
                .unwrap_or(0.0)
                .partial_cmp(&a.epss_score.unwrap_or(0.0))
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| b.ai_risk_score.cmp(&a.ai_risk_score))
        }),
        "published" => list.sort_by(|a, b| b.published_at.cmp(&a.published_at)),
        _ => list.sort_by(|a, b| {
            b.ai_risk_score
                .cmp(&a.ai_risk_score)
                .then_with(|| b.published_at.cmp(&a.published_at))
        }),
    }

    let total_matched = list.len();
    let limit = params.limit.unwrap_or(200).min(500);
    list.truncate(limit);

    Json(serde_json::json!({
        "total_matched": total_matched,
        "items": list
    }))
}

async fn get_vulnerability(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let store = state.store.read().await;
    let id_upper = id.trim().to_ascii_uppercase();

    let vuln = store
        .vulnerabilities
        .get(&id_upper)
        .or_else(|| store.vulnerabilities.get(id.trim()))
        .or_else(|| {
            store
                .vulnerabilities
                .values()
                .find(|v| v.aliases.iter().any(|a| a.eq_ignore_ascii_case(id.trim())))
        })
        .cloned();

    match vuln {
        Some(v) => {
            let related_news: Vec<ThreatNewsItem> = store
                .news
                .values()
                .filter(|n| {
                    n.extracted_cves.iter().any(|c| c == &v.id || v.aliases.contains(c))
                        || n.title.to_ascii_uppercase().contains(&v.id)
                })
                .cloned()
                .collect();

            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "vulnerability": v,
                    "related_news": related_news,
                })),
            )
                .into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": format!("Vulnerability {} not found in current store", id) })),
        )
            .into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct NewsQuery {
    q: Option<String>,
    source: Option<String>,
    category: Option<String>,
    vuln_only: Option<bool>,
    ai_only: Option<bool>,
    days: Option<i64>,
    limit: Option<usize>,
}

async fn list_news(
    State(state): State<AppState>,
    Query(params): Query<NewsQuery>,
) -> impl IntoResponse {
    let store = state.store.read().await;
    let now = Utc::now();
    let q_lower = params.q.as_deref().unwrap_or("").trim().to_ascii_lowercase();

    let mut list: Vec<ThreatNewsItem> = store
        .news
        .values()
        .filter(|n| {
            if let Some(src) = params.source.as_deref().filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("ALL")) {
                if !n.source.eq_ignore_ascii_case(src) {
                    return false;
                }
            }
            if let Some(cat) = params.category.as_deref().filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("ALL")) {
                if !n.category.eq_ignore_ascii_case(cat) {
                    return false;
                }
            }
            if params.vuln_only.unwrap_or(false) && !n.is_vulnerability_news {
                return false;
            }
            if params.ai_only.unwrap_or(false) && !n.is_ai_related {
                return false;
            }
            if let Some(days) = params.days {
                if days > 0 && (now - n.published_at).num_days() > days {
                    return false;
                }
            }
            if !q_lower.is_empty() {
                let hay = format!(
                    "{} {} {} {} {}",
                    n.title,
                    n.summary,
                    n.source,
                    n.extracted_cves.join(" "),
                    n.tags.join(" ")
                )
                .to_ascii_lowercase();
                if !hay.contains(&q_lower) {
                    return false;
                }
            }
            true
        })
        .cloned()
        .collect();

    list.sort_by(|a, b| b.published_at.cmp(&a.published_at));
    let total_matched = list.len();
    let limit = params.limit.unwrap_or(150).min(400);
    list.truncate(limit);

    let mut sources: Vec<String> = store
        .news
        .values()
        .map(|n| n.source.clone())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    sources.sort();

    Json(serde_json::json!({
        "total_matched": total_matched,
        "sources": sources,
        "items": list
    }))
}

#[derive(Debug, Deserialize)]
struct IocQuery {
    lookup: Option<String>,
}

async fn get_iocs(
    State(state): State<AppState>,
    Query(params): Query<IocQuery>,
) -> impl IntoResponse {
    let store = state.store.read().await;
    let lookup_result = params.lookup.as_deref().and_then(|raw| {
        let q = raw.trim();
        if q.is_empty() {
            return None;
        }
        let q_lower = q.to_ascii_lowercase();
        let mut hits = Vec::new();

        for ip in &store.telemetry.top_attacking_ips {
            if ip.ip == q {
                hits.push(IocHit {
                    feed: "SANS ISC Top Attackers".to_string(),
                    indicator_type: "IPv4 Scanner".to_string(),
                    detail: format!("{} attacks ({} packets, last seen {})", ip.attacks, ip.count, ip.last_seen),
                });
            }
        }
        for c2 in &store.telemetry.botnet_c2s {
            if c2.ip_address == q
                || c2
                    .hostname
                    .as_deref()
                    .map(|h| h.to_ascii_lowercase().contains(&q_lower))
                    .unwrap_or(false)
            {
                hits.push(IocHit {
                    feed: "abuse.ch Feodo Tracker".to_string(),
                    indicator_type: "Botnet C2".to_string(),
                    detail: format!(
                        "{}:{} ({} · {} · status: {})",
                        c2.ip_address,
                        c2.port,
                        c2.malware,
                        c2.country.as_deref().unwrap_or("--"),
                        c2.status
                    ),
                });
            }
        }
        if store.compromised_ips_set.contains(q) {
            hits.push(IocHit {
                feed: "Emerging Threats Blocklist".to_string(),
                indicator_type: "Compromised Host IP".to_string(),
                detail: "Present in Emerging Threats compromised-ips blocklist".to_string(),
            });
        }
        for ph in &store.telemetry.phishing_urls {
            if ph.domain.to_ascii_lowercase().contains(&q_lower)
                || ph.url.to_ascii_lowercase().contains(&q_lower)
            {
                hits.push(IocHit {
                    feed: "OpenPhish".to_string(),
                    indicator_type: "Phishing URL".to_string(),
                    detail: format!(
                        "{} (brand: {})",
                        ph.url,
                        ph.suspected_brand.as_deref().unwrap_or("Unclassified")
                    ),
                });
                if hits.len() >= 10 {
                    break;
                }
            }
        }

        let matched = !hits.is_empty();
        let risk_verdict = if matched { "MALICIOUS / FLAGGED" } else { "NO MATCH IN LIVE FEEDS" }.to_string();
        Some(IocLookupResult {
            query: q.to_string(),
            matched,
            risk_verdict,
            hits,
        })
    });

    Json(serde_json::json!({
        "telemetry": store.telemetry,
        "lookup_result": lookup_result
    }))
}

async fn list_alerts(State(state): State<AppState>) -> impl IntoResponse {
    let store = state.store.read().await;
    let unack = store.alerts.iter().filter(|a| !a.acknowledged).count();
    Json(serde_json::json!({
        "unacknowledged_count": unack,
        "alerts": store.alerts,
    }))
}

async fn ack_alert(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let mut store = state.store.write().await;
    if let Some(a) = store.alerts.iter_mut().find(|a| a.id == id) {
        a.acknowledged = true;
        let _ = store.save_to_disk(&state.data_path);
        return Json(serde_json::json!({ "ok": true })).into_response();
    }
    (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "Alert not found" }))).into_response()
}

async fn ack_all_alerts(State(state): State<AppState>) -> impl IntoResponse {
    let mut store = state.store.write().await;
    for a in &mut store.alerts {
        a.acknowledged = true;
    }
    let _ = store.save_to_disk(&state.data_path);
    Json(serde_json::json!({ "ok": true }))
}

async fn trigger_test_alert(State(state): State<AppState>) -> impl IntoResponse {
    let now = Utc::now();
    let sample_cve = {
        let store = state.store.read().await;
        store
            .vulnerabilities
            .values()
            .filter(|v| v.severity == Severity::Critical || v.is_kev)
            .max_by_key(|v| v.ai_risk_score)
            .map(|v| (v.id.clone(), v.title.clone(), v.ai_risk_score))
    };

    let (cve, title, score) = sample_cve.unwrap_or_else(|| {
        (
            "CVE-2026-90001".to_string(),
            "Simulated Zero-Day Remote Code Execution Alert".to_string(),
            96,
        )
    });

    let alert = ThreatAlert {
        id: Uuid::new_v4().to_string(),
        created_at: now,
        severity: Severity::Critical,
        alert_type: "TEST_ALERT".to_string(),
        title: format!("[LIVE TEST] {}: {}", cve, title),
        summary: "Simulated real-time breaking vulnerability alert verifying SSE push, SOC banner, toast, and audio alert pipeline.".to_string(),
        source: "AiBrainWorX Alert Watchdog".to_string(),
        url: Some(format!("https://nvd.nist.gov/vuln/detail/{}", cve)),
        cve_ids: vec![cve.clone()],
        matched_reasons: vec![
            "Watchlist Simulation Trigger".to_string(),
            "Severity CRITICAL >= rule threshold".to_string(),
        ],
        ai_risk_score: score,
        acknowledged: false,
        linked_item_id: Some(cve),
    };

    {
        let mut store = state.store.write().await;
        store.alerts.insert(0, alert.clone());
        store.prune();
        let _ = store.save_to_disk(&state.data_path);
    }

    let _ = state.sse_tx.send(SseEvent::NewAlert(alert.clone()));
    Json(alert)
}

async fn list_feeds(State(state): State<AppState>) -> impl IntoResponse {
    let store = state.store.read().await;
    Json(serde_json::json!({
        "last_sweep_at": store.last_sweep_at,
        "next_sweep_at": store.next_sweep_at,
        "sweep_in_progress": state.sweep_in_progress.load(Ordering::SeqCst),
        "feeds": store.feed_health,
    }))
}

async fn trigger_refresh(State(state): State<AppState>) -> impl IntoResponse {
    if state.sweep_in_progress.load(Ordering::SeqCst) {
        return (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({ "status": "already_running" })),
        );
    }
    let state_clone = state.clone();
    tokio::spawn(async move {
        run_sweep(state_clone).await;
    });
    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({ "status": "started" })),
    )
}

async fn get_rules(State(state): State<AppState>) -> impl IntoResponse {
    let store = state.store.read().await;
    Json(store.rules.clone())
}

async fn update_rules(
    State(state): State<AppState>,
    Json(mut new_rules): Json<AlertRules>,
) -> impl IntoResponse {
    new_rules.poll_interval_secs = new_rules.poll_interval_secs.clamp(60, 86400);
    new_rules.watchlist_keywords = new_rules
        .watchlist_keywords
        .into_iter()
        .map(|s| s.trim().chars().take(100).collect::<String>())
        .filter(|s| !s.is_empty())
        .take(100)
        .collect();

    let mut store = state.store.write().await;
    store.rules = new_rules.clone();
    if let Some(last) = store.last_sweep_at {
        store.next_sweep_at = Some(last + chrono::Duration::seconds(new_rules.poll_interval_secs as i64));
    }
    let _ = store.save_to_disk(&state.data_path);
    Json(new_rules)
}

async fn get_ai_config(State(state): State<AppState>) -> impl IntoResponse {
    let store = state.store.read().await;
    Json(to_public_config(&store.ai_config))
}

async fn update_ai_config(
    State(state): State<AppState>,
    Json(upd): Json<AiConfigUpdate>,
) -> impl IntoResponse {
    let mut store = state.store.write().await;
    if let Err(msg) = apply_config_update(&mut store.ai_config, upd) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": msg })),
        )
            .into_response();
    }
    let _ = store.save_to_disk(&state.data_path);
    (StatusCode::OK, Json(to_public_config(&store.ai_config))).into_response()
}

fn apply_ephemeral_ai_overrides(
    cfg: &mut AiConfig,
    provider: Option<AiProviderKind>,
    base_url: Option<String>,
    model: Option<String>,
    api_key: Option<String>,
    promote_builtin_on_key: bool,
) {
    if let Some(p) = provider {
        if p != cfg.provider {
            cfg.api_key.clear();
            cfg.base_url = default_base_url(p).to_string();
            cfg.model = default_model(p).to_string();
        }
        cfg.provider = p;
    }
    if let Some(url) = base_url {
        let t = url.trim().trim_end_matches('/');
        if !t.is_empty() {
            let prev_base = effective_base_url(cfg);
            if !t.eq_ignore_ascii_case(&prev_base) {
                cfg.api_key.clear();
            }
            cfg.base_url = t.to_string();
        }
    }
    if let Some(m) = model {
        let t = m.trim();
        if !t.is_empty() {
            cfg.model = t.to_string();
        }
    }
    if let Some(key) = api_key {
        let t = key.trim();
        if !t.is_empty() {
            if promote_builtin_on_key && cfg.provider == AiProviderKind::Builtin {
                cfg.provider = AiProviderKind::Gemini;
                cfg.base_url = default_base_url(AiProviderKind::Gemini).to_string();
                cfg.model = default_model(AiProviderKind::Gemini).to_string();
            }
            cfg.api_key = t.to_string();
        }
    }
}

async fn list_ai_models(
    State(state): State<AppState>,
    Json(req): Json<AiModelsRequest>,
) -> impl IntoResponse {
    let mut cfg = { state.store.read().await.ai_config.clone() };
    apply_ephemeral_ai_overrides(&mut cfg, req.provider, req.base_url, None, req.api_key, false);
    Json(list_models(&state.ai_http, &cfg).await)
}

async fn test_ai_connection(
    State(state): State<AppState>,
    Json(req): Json<AiTestRequest>,
) -> impl IntoResponse {
    let mut cfg = { state.store.read().await.ai_config.clone() };
    apply_ephemeral_ai_overrides(
        &mut cfg,
        req.provider,
        req.base_url,
        req.model,
        req.api_key,
        false,
    );
    if let Some(to) = req.timeout_secs {
        cfg.timeout_secs = to.clamp(5, 300);
    }
    Json(test_connection(&state.ai_http, &cfg).await)
}

async fn ai_analyze(
    State(state): State<AppState>,
    Json(req): Json<AiQueryRequest>,
) -> impl IntoResponse {
    let q_trimmed = req.query.trim();
    if q_trimmed.is_empty() || q_trimmed.chars().count() > 4000 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Query must be between 1 and 4000 characters" })),
        )
            .into_response();
    }

    let store_snapshot = { state.store.read().await.clone() };
    let mut cfg = store_snapshot.ai_config.clone();
    apply_ephemeral_ai_overrides(
        &mut cfg,
        req.provider,
        req.base_url,
        req.model,
        req.api_key.or(req.external_api_key),
        true,
    );

    let resp = answer_analyst_query(&store_snapshot, &state.ai_http, q_trimmed, &cfg).await;
    (StatusCode::OK, Json(resp)).into_response()
}

async fn ai_triage_vuln(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let store_snapshot = { state.store.read().await.clone() };
    let cfg = store_snapshot.ai_config.clone();
    match triage_vulnerability_with_ai(&store_snapshot, &state.ai_http, &cfg, &id).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err(msg) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": msg })),
        )
            .into_response(),
    }
}

async fn sse_events(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.sse_tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|msg| match msg {
        Ok(evt) => match serde_json::to_string(&evt) {
            Ok(json) => Some(Ok(Event::default().data(json))),
            Err(_) => None,
        },
        Err(_) => None,
    });

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(20))
            .text("keepalive"),
    )
}
