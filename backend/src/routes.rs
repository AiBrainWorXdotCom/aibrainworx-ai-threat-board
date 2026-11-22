use std::collections::HashSet;
use std::convert::Infallible;
use std::sync::atomic::Ordering;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
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
use crate::analyzer::{answer_analyst_query, generate_ai_brief, triage_vulnerability_with_ai};
use crate::export::{
    build_offline_snapshot, export_iocs_blocklist, export_stix_bundle, export_vulnerabilities_csv,
    export_vulnerability_markdown, verify_offline_snapshot,
};
use crate::feeds::run_sweep;
use crate::models::{
    AiConfig, AiConfigUpdate, AiModelsRequest, AiProviderKind, AiQueryRequest, AiTestRequest,
    AlertRules, AuthLoginRequest, AuthStatusResponse, BulkIocRequest, BulkIocResponse,
    CustomFeedConfig, CustomFeedCreateRequest, CveTriage, CveTriageUpdateRequest, DashboardKpis,
    DashboardPayload, EpssSpike, FeedConfigUpdateRequest, IocHit, IocLookupResult, MyStackConfig,
    MyStackPayload, MyStackUpdateRequest, ServerModeInfo, Severity, SnapshotImportResult, SseEvent,
    StackImportRequest, StackImportResponse, StackMatchSummary, ThreatAlert, ThreatNewsItem,
    TriageStatus, Vulnerability, WebhookCreateRequest, WebhookKind, WebhookTarget,
    WebhookUpdateRequest,
};
use crate::security::{
    constant_time_eq, extract_bearer_token, extract_session_cookie, keychain_delete, keychain_set,
    strip_invisible_unicode, validate_outbound_url, OutboundUrlPolicy, SESSION_COOKIE_NAME,
};
use crate::stack::{correlate_stack, parse_stack_manifest};
use crate::store::{AppState, ThreatStore};
use crate::webhooks::{
    build_webhook_payload, send_webhook_payload, to_public_webhook, WebhookDispatchItem,
};

pub fn api_router(state: AppState) -> Router {
    let standard = Router::new()
        .route("/health", get(health))
        .route("/auth/status", get(auth_status))
        .route("/auth/login", post(auth_login))
        .route("/auth/logout", post(auth_logout))
        .route("/dashboard", get(dashboard))
        .route("/vulnerabilities", get(list_vulnerabilities))
        .route("/vulnerabilities/{id}", get(get_vulnerability))
        .route("/vulnerabilities/{id}/triage", put(update_vuln_triage))
        .route("/vulnerabilities/{id}/export", get(export_single_vuln))
        .route("/export/vulnerabilities", get(export_vulnerabilities_list))
        .route(
            "/stack",
            get(get_stack).put(update_stack).delete(clear_stack),
        )
        .route("/news", get(list_news))
        .route("/iocs", get(get_iocs))
        .route("/iocs/bulk", post(bulk_lookup_iocs))
        .route("/iocs/export", get(export_iocs))
        .route("/alerts", get(list_alerts))
        .route("/alerts/ack-all", post(ack_all_alerts))
        .route("/alerts/test", post(trigger_test_alert))
        .route("/alerts/{id}/ack", post(ack_alert))
        .route("/feeds", get(list_feeds))
        .route("/feeds/config", put(update_feed_config))
        .route(
            "/feeds/custom",
            get(list_custom_feeds).post(create_custom_feed),
        )
        .route(
            "/feeds/custom/{id}",
            axum::routing::delete(delete_custom_feed),
        )
        .route("/webhooks", get(list_webhooks).post(create_webhook))
        .route("/webhooks/{id}", put(update_webhook).delete(delete_webhook))
        .route("/webhooks/{id}/test", post(test_webhook))
        .route("/delta", get(get_delta))
        .route("/delta/ack", post(ack_delta))
        .route("/snapshot/export", get(export_snapshot))
        .route("/refresh", post(trigger_refresh))
        .route("/rules", get(get_rules).put(update_rules))
        .route("/ai/config", get(get_ai_config).put(update_ai_config))
        .route("/ai/models", post(list_ai_models))
        .route("/ai/test", post(test_ai_connection))
        .route("/ai/analyze", post(ai_analyze))
        .route("/ai/triage/{id}", post(ai_triage_vuln))
        .route("/events", get(sse_events))
        .layer(DefaultBodyLimit::max(256 * 1024));

    let large_uploads = Router::new()
        .route(
            "/stack/import",
            post(import_stack).layer(DefaultBodyLimit::max(2 * 1024 * 1024)),
        )
        .route(
            "/snapshot/import",
            post(import_snapshot).layer(DefaultBodyLimit::max(10 * 1024 * 1024)),
        );

    standard.merge(large_uploads).with_state(state)
}

fn require_writable(state: &AppState) -> Result<(), Box<Response>> {
    if state.server_mode.wallboard_mode {
        return Err(Box::new(
            (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "Read-only Wallboard Mode is active; mutations and configuration changes are disabled."
                })),
            )
                .into_response(),
        ));
    }
    Ok(())
}

pub fn is_request_authenticated(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(expected) = state.server_mode.auth_token.as_deref() else {
        return true;
    };
    if let Some(bearer) = extract_bearer_token(headers) {
        if constant_time_eq(bearer, expected) {
            return true;
        }
    }
    if let Some(cookie) = extract_session_cookie(headers, SESSION_COOKIE_NAME) {
        if constant_time_eq(cookie, expected) {
            return true;
        }
    }
    false
}

fn build_server_mode_info(state: &AppState, headers: &HeaderMap) -> ServerModeInfo {
    ServerModeInfo {
        version: state.server_mode.version.clone(),
        wallboard_mode: state.server_mode.wallboard_mode,
        offline_mode: state.server_mode.offline_mode,
        auth_required: state.server_mode.auth_token.is_some(),
        authenticated: is_request_authenticated(state, headers),
        bind_addr: state.server_mode.bind_addr.clone(),
    }
}

async fn auth_status(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    Json(AuthStatusResponse {
        auth_required: state.server_mode.auth_token.is_some(),
        authenticated: is_request_authenticated(&state, &headers),
        wallboard_mode: state.server_mode.wallboard_mode,
        offline_mode: state.server_mode.offline_mode,
    })
}

async fn auth_login(
    State(state): State<AppState>,
    req_headers: HeaderMap,
    Json(body): Json<AuthLoginRequest>,
) -> impl IntoResponse {
    let Some(expected) = state.server_mode.auth_token.as_deref() else {
        return (
            StatusCode::OK,
            Json(serde_json::json!({ "authenticated": true, "auth_required": false })),
        )
            .into_response();
    };

    if !constant_time_eq(body.token.trim(), expected) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "Invalid access token" })),
        )
            .into_response();
    }

    let is_https = req_headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|p| p.eq_ignore_ascii_case("https"));
    let secure_attr = if is_https { "; Secure" } else { "" };
    let cookie_val = format!(
        "{SESSION_COOKIE_NAME}={expected}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200{secure_attr}"
    );

    let mut resp = (
        StatusCode::OK,
        Json(serde_json::json!({ "authenticated": true, "auth_required": true })),
    )
        .into_response();
    if let Ok(hv) = HeaderValue::from_str(&cookie_val) {
        resp.headers_mut().insert(header::SET_COOKIE, hv);
    }
    resp
}

async fn auth_logout() -> impl IntoResponse {
    let mut resp = (
        StatusCode::OK,
        Json(serde_json::json!({ "authenticated": false })),
    )
        .into_response();
    resp.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static("abw_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"),
    );
    resp
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
        "wallboard_mode": state.server_mode.wallboard_mode,
        "offline_mode": state.server_mode.offline_mode,
        "auth_required": state.server_mode.auth_token.is_some(),
    }))
}

fn compute_stack_summary(store: &ThreatStore) -> StackMatchSummary {
    let watch_count = store.my_stack.vendors.len()
        + store.my_stack.products.len()
        + store.my_stack.keywords.len();
    let configured = watch_count > 0 || !store.my_stack.components.is_empty();
    let mut matched: Vec<(u8, bool, String)> = store
        .vulnerabilities
        .values()
        .filter(|v| !v.matched_stack.is_empty())
        .map(|v| (v.ai_risk_score, v.is_kev, v.id.clone()))
        .collect();
    let matched_vuln_count = matched.len();
    let matched_kev_count = matched.iter().filter(|(_, kev, _)| *kev).count();
    matched.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.2.cmp(&b.2)));
    let top_matched_cves = matched.into_iter().take(12).map(|(_, _, id)| id).collect();

    StackMatchSummary {
        configured,
        component_count: store.my_stack.components.len(),
        vendor_watch_count: watch_count,
        matched_vuln_count,
        matched_kev_count,
        top_matched_cves,
    }
}

async fn dashboard(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let store = state.store.read().await;
    let now = Utc::now();
    let cutoff_24h = now - chrono::Duration::hours(24);
    let cutoff_7d = now - chrono::Duration::days(7);

    let mut vulns: Vec<Vulnerability> = store.vulnerabilities.values().cloned().collect();
    vulns.sort_by(|a, b| {
        (!b.matched_stack.is_empty())
            .cmp(&!a.matched_stack.is_empty())
            .then_with(|| b.ai_risk_score.cmp(&a.ai_risk_score))
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
    let kev_overdue_count = vulns
        .iter()
        .filter(|v| v.is_kev && v.kev_days_remaining.is_some_and(|d| d < 0))
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
    let stack_exposed_count = vulns.iter().filter(|v| !v.matched_stack.is_empty()).count();
    let epss_spike_count = vulns.iter().filter(|v| v.epss_spike).count();
    let triage_investigating_count = vulns
        .iter()
        .filter(|v| v.triage_status == TriageStatus::Investigating)
        .count();

    let mut recent_epss_spikes: Vec<EpssSpike> = vulns
        .iter()
        .filter(|v| v.epss_spike)
        .map(|v| EpssSpike {
            cve_id: v.id.clone(),
            title: v.title.clone(),
            severity: v.severity,
            current_epss_pct: v.epss_score.unwrap_or(0.0) * 100.0,
            delta_24h_pct: v.epss_delta_24h.unwrap_or(0.0) * 100.0,
            is_kev: v.is_kev,
            matched_stack: v.matched_stack.clone(),
        })
        .collect();
    recent_epss_spikes.sort_by(|a, b| {
        b.delta_24h_pct
            .partial_cmp(&a.delta_24h_pct)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    recent_epss_spikes.truncate(12);

    let mut news: Vec<ThreatNewsItem> = store.news.values().cloned().collect();
    news.sort_by_key(|a| std::cmp::Reverse(a.published_at));

    let news_count_24h = news.iter().filter(|n| n.published_at >= cutoff_24h).count();
    let news_count_7d = news.iter().filter(|n| n.published_at >= cutoff_7d).count();
    let exploit_poc_count = news
        .iter()
        .filter(|n| n.category == "Exploit PoC" || n.tags.iter().any(|t| t == "Exploit PoC"))
        .count();

    let unacknowledged_alerts = store.alerts.iter().filter(|a| !a.acknowledged).count();
    let feeds_ok = store
        .feed_health
        .iter()
        .filter(|f| f.status == "OK")
        .count();

    let kpis = DashboardKpis {
        total_vulnerabilities: vulns.len(),
        critical_count_7d,
        high_count_7d,
        kev_total_catalog: store.kev_cve_set.len().max(kev_tracked),
        kev_tracked,
        kev_added_7d,
        kev_overdue_count,
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
        stack_exposed_count,
        epss_spike_count,
        triage_investigating_count,
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
        stack_summary: compute_stack_summary(&store),
        recent_epss_spikes,
        latest_delta: store.latest_delta.clone(),
        server_mode: build_server_mode_info(&state, &headers),
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
    stack_only: Option<bool>,
    epss_spike: Option<bool>,
    triage: Option<String>,
    days: Option<i64>,
    sort: Option<String>,
    limit: Option<usize>,
}

fn filter_vulns(
    store: &ThreatStore,
    params: &VulnQuery,
    fts_hits: Option<&HashSet<String>>,
) -> Vec<Vulnerability> {
    let now = Utc::now();
    let q_lower = params
        .q
        .as_deref()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let sev_filter = params
        .severity
        .as_deref()
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("ALL"))
        .map(Severity::from_str_loose);
    let triage_filter = params
        .triage
        .as_deref()
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("all"))
        .map(TriageStatus::from_db_str);

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
            if params.stack_only.unwrap_or(false) && v.matched_stack.is_empty() {
                return false;
            }
            if params.epss_spike.unwrap_or(false) && !v.epss_spike {
                return false;
            }
            if let Some(t_status) = triage_filter {
                if v.triage_status != t_status {
                    return false;
                }
            }
            if let Some(days) = params.days {
                if days > 0 && (now - v.published_at).num_days() > days {
                    return false;
                }
            }
            if !q_lower.is_empty() {
                let in_fts = fts_hits.is_some_and(|set| set.contains(&v.id));
                if !in_fts {
                    let hay = format!(
                        "{} {} {} {} {} {} {} {}",
                        v.id,
                        v.aliases.join(" "),
                        v.title,
                        v.description,
                        v.vendor.as_deref().unwrap_or(""),
                        v.product.as_deref().unwrap_or(""),
                        v.ecosystem.as_deref().unwrap_or(""),
                        v.matched_stack.join(" ")
                    )
                    .to_ascii_lowercase();
                    if !hay.contains(&q_lower) {
                        return false;
                    }
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
        "epss_delta" => list.sort_by(|a, b| {
            b.epss_delta_24h
                .unwrap_or(-99.0)
                .partial_cmp(&a.epss_delta_24h.unwrap_or(-99.0))
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| b.ai_risk_score.cmp(&a.ai_risk_score))
        }),
        "published" => list.sort_by_key(|a| std::cmp::Reverse(a.published_at)),
        _ => list.sort_by(|a, b| {
            b.ai_risk_score
                .cmp(&a.ai_risk_score)
                .then_with(|| b.published_at.cmp(&a.published_at))
        }),
    }

    list
}

async fn list_vulnerabilities(
    State(state): State<AppState>,
    Query(params): Query<VulnQuery>,
) -> impl IntoResponse {
    let fts_hits = params
        .q
        .as_deref()
        .map(str::trim)
        .filter(|q| q.len() >= 2)
        .and_then(|q| state.db.search_cve_ids_fts(q, 500));

    let store = state.store.read().await;
    let mut list = filter_vulns(&store, &params, fts_hits.as_ref());
    let total_matched = list.len();
    let limit = params.limit.unwrap_or(200).min(500);
    list.truncate(limit);

    Json(serde_json::json!({
        "total_matched": total_matched,
        "items": list
    }))
}

fn find_vuln<'a>(store: &'a ThreatStore, raw_id: &str) -> Option<&'a Vulnerability> {
    let trimmed = raw_id.trim();
    let upper = trimmed.to_ascii_uppercase();
    store
        .vulnerabilities
        .get(&upper)
        .or_else(|| store.vulnerabilities.get(trimmed))
        .or_else(|| {
            store
                .vulnerabilities
                .values()
                .find(|v| v.aliases.iter().any(|a| a.eq_ignore_ascii_case(trimmed)))
        })
}

async fn get_vulnerability(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let store = state.store.read().await;
    match find_vuln(&store, &id).cloned() {
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

async fn update_vuln_triage(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<CveTriageUpdateRequest>,
) -> impl IntoResponse {
    if let Err(resp) = require_writable(&state) {
        return *resp;
    }

    let cleaned_notes: String = strip_invisible_unicode(req.notes.trim())
        .chars()
        .take(4000)
        .collect();
    let now = Utc::now();

    let mut store = state.store.write().await;
    let canonical_id = match find_vuln(&store, &id) {
        Some(v) => v.id.clone(),
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": format!("Vulnerability {} not found", id) })),
            )
                .into_response();
        }
    };

    if let Some(v) = store.vulnerabilities.get_mut(&canonical_id) {
        v.triage_status = req.status;
        v.triage_notes = cleaned_notes.clone();
    }

    let triage = CveTriage {
        cve_id: canonical_id.clone(),
        status: req.status,
        notes: cleaned_notes,
        updated_at: now,
    };
    store.triage_map.insert(canonical_id, triage.clone());

    let _ = state.db.upsert_triage(&triage);
    let _ = state.persist_store(&store);

    (StatusCode::OK, Json(triage)).into_response()
}

#[derive(Debug, Deserialize)]
struct ExportFormatQuery {
    format: Option<String>,
}

fn sanitize_filename_token(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
        .take(48)
        .collect()
}

async fn export_single_vuln(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(params): Query<ExportFormatQuery>,
) -> impl IntoResponse {
    let store = state.store.read().await;
    let Some(v) = find_vuln(&store, &id).cloned() else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": format!("Vulnerability {} not found", id) })),
        )
            .into_response();
    };
    let related_news: Vec<ThreatNewsItem> = store
        .news
        .values()
        .filter(|n| {
            n.extracted_cves
                .iter()
                .any(|c| c == &v.id || v.aliases.contains(c))
                || n.title.to_ascii_uppercase().contains(&v.id)
        })
        .cloned()
        .collect();
    drop(store);

    let safe_id = sanitize_filename_token(&v.id);
    let fmt = params
        .format
        .as_deref()
        .unwrap_or("markdown")
        .to_ascii_lowercase();
    let (body, content_type, ext) = match fmt.as_str() {
        "stix" => {
            let bundle = export_stix_bundle(&[v], &[], &[], &[]);
            (
                serde_json::to_string_pretty(&bundle).unwrap_or_default(),
                "application/json; charset=utf-8",
                "stix21.json",
            )
        }
        "json" => {
            let doc = serde_json::json!({
                "vulnerability": v,
                "related_news": related_news,
            });
            (
                serde_json::to_string_pretty(&doc).unwrap_or_default(),
                "application/json; charset=utf-8",
                "json",
            )
        }
        _ => (
            export_vulnerability_markdown(&v, &related_news),
            "text/markdown; charset=utf-8",
            "md",
        ),
    };

    let disp = format!("attachment; filename=\"{safe_id}.{ext}\"");
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type.to_string()),
            (header::CONTENT_DISPOSITION, disp),
        ],
        body,
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
struct BulkVulnExportQuery {
    format: Option<String>,
    q: Option<String>,
    severity: Option<String>,
    kev_only: Option<bool>,
    ai_only: Option<bool>,
    ransomware_only: Option<bool>,
    exploit_only: Option<bool>,
    stack_only: Option<bool>,
    epss_spike: Option<bool>,
    triage: Option<String>,
}

async fn export_vulnerabilities_list(
    State(state): State<AppState>,
    Query(q): Query<BulkVulnExportQuery>,
) -> impl IntoResponse {
    let vuln_query = VulnQuery {
        q: q.q,
        severity: q.severity,
        kev_only: q.kev_only,
        ai_only: q.ai_only,
        ransomware_only: q.ransomware_only,
        exploit_only: q.exploit_only,
        stack_only: q.stack_only,
        epss_spike: q.epss_spike,
        triage: q.triage,
        days: None,
        sort: Some("ai_score".to_string()),
        limit: Some(500),
    };
    let fts_hits = vuln_query
        .q
        .as_deref()
        .map(str::trim)
        .filter(|s| s.len() >= 2)
        .and_then(|s| state.db.search_cve_ids_fts(s, 500));

    let store = state.store.read().await;
    let mut vulns = filter_vulns(&store, &vuln_query, fts_hits.as_ref());
    vulns.truncate(500);

    let fmt = q.format.as_deref().unwrap_or("csv").to_ascii_lowercase();
    let (body, content_type, filename) = match fmt.as_str() {
        "stix" => {
            let bundle = export_stix_bundle(
                &vulns,
                &store.telemetry.botnet_c2s,
                &store.telemetry.top_attacking_ips,
                &store.telemetry.phishing_urls,
            );
            (
                serde_json::to_string_pretty(&bundle).unwrap_or_default(),
                "application/json; charset=utf-8",
                "aibrainworx-stix21-bundle.json",
            )
        }
        "json" => (
            serde_json::to_string_pretty(&vulns).unwrap_or_default(),
            "application/json; charset=utf-8",
            "aibrainworx-vulnerabilities.json",
        ),
        _ => (
            export_vulnerabilities_csv(&vulns),
            "text/csv; charset=utf-8",
            "aibrainworx-vulnerabilities.csv",
        ),
    };

    let disp = format!("attachment; filename=\"{filename}\"");
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type.to_string()),
            (header::CONTENT_DISPOSITION, disp),
        ],
        body,
    )
        .into_response()
}

fn build_my_stack_payload(store: &ThreatStore) -> MyStackPayload {
    let summary = compute_stack_summary(store);
    let mut matched_vulnerabilities: Vec<Vulnerability> = store
        .vulnerabilities
        .values()
        .filter(|v| !v.matched_stack.is_empty())
        .cloned()
        .collect();
    matched_vulnerabilities.sort_by(|a, b| {
        b.is_kev
            .cmp(&a.is_kev)
            .then_with(|| b.ai_risk_score.cmp(&a.ai_risk_score))
            .then_with(|| b.published_at.cmp(&a.published_at))
    });
    matched_vulnerabilities.truncate(250);

    MyStackPayload {
        config: store.my_stack.clone(),
        summary,
        matched_vulnerabilities,
    }
}

async fn get_stack(State(state): State<AppState>) -> impl IntoResponse {
    let store = state.store.read().await;
    Json(build_my_stack_payload(&store))
}

fn clean_watchlist_terms(items: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for raw in items {
        let clean: String = strip_invisible_unicode(raw.trim())
            .chars()
            .take(80)
            .collect();
        if clean.len() >= 2 && seen.insert(clean.to_ascii_lowercase()) {
            out.push(clean);
            if out.len() >= 100 {
                break;
            }
        }
    }
    out
}

async fn update_stack(
    State(state): State<AppState>,
    Json(req): Json<MyStackUpdateRequest>,
) -> impl IntoResponse {
    if let Err(resp) = require_writable(&state) {
        return *resp;
    }

    let mut store = state.store.write().await;
    if let Some(vendors) = req.vendors {
        store.my_stack.vendors = clean_watchlist_terms(vendors);
    }
    if let Some(products) = req.products {
        store.my_stack.products = clean_watchlist_terms(products);
    }
    if let Some(keywords) = req.keywords {
        store.my_stack.keywords = clean_watchlist_terms(keywords);
    }
    if let Some(mut comps) = req.components {
        comps.truncate(5000);
        store.my_stack.components = comps;
    }
    store.my_stack.updated_at = Some(Utc::now());

    let my_stack_snapshot = store.my_stack.clone();
    correlate_stack(&mut store.vulnerabilities, &my_stack_snapshot);
    store.ai_brief = generate_ai_brief(&store, Utc::now());
    let _ = state.persist_store(&store);

    Json(build_my_stack_payload(&store)).into_response()
}

async fn import_stack(
    State(state): State<AppState>,
    Json(req): Json<StackImportRequest>,
) -> impl IntoResponse {
    if let Err(resp) = require_writable(&state) {
        return *resp;
    }

    let (format_detected, parsed_components) =
        match parse_stack_manifest(&req.filename, &req.content) {
            Ok(res) => res,
            Err(msg) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": msg })),
                )
                    .into_response();
            }
        };

    let imported_components = parsed_components.len();
    let mut store = state.store.write().await;

    if req.replace.unwrap_or(true) {
        store.my_stack.components = parsed_components;
    } else {
        let mut seen: HashSet<(String, String, String)> = store
            .my_stack
            .components
            .iter()
            .map(|c| {
                (
                    c.ecosystem.to_ascii_lowercase(),
                    c.name.to_ascii_lowercase(),
                    c.version.to_ascii_lowercase(),
                )
            })
            .collect();
        for c in parsed_components {
            let key = (
                c.ecosystem.to_ascii_lowercase(),
                c.name.to_ascii_lowercase(),
                c.version.to_ascii_lowercase(),
            );
            if seen.insert(key) && store.my_stack.components.len() < 5000 {
                store.my_stack.components.push(c);
            }
        }
    }
    store.my_stack.updated_at = Some(Utc::now());

    let stack_cfg = store.my_stack.clone();
    let summary = correlate_stack(&mut store.vulnerabilities, &stack_cfg);
    store.ai_brief = generate_ai_brief(&store, Utc::now());
    let _ = state.persist_store(&store);

    Json(StackImportResponse {
        format_detected,
        imported_components,
        total_components: store.my_stack.components.len(),
        matched_vulnerabilities: summary.matched_vuln_count,
        config: store.my_stack.clone(),
    })
    .into_response()
}

async fn clear_stack(State(state): State<AppState>) -> impl IntoResponse {
    if let Err(resp) = require_writable(&state) {
        return *resp;
    }

    let mut store = state.store.write().await;
    store.my_stack = MyStackConfig::default();
    let empty_cfg = store.my_stack.clone();
    correlate_stack(&mut store.vulnerabilities, &empty_cfg);
    store.ai_brief = generate_ai_brief(&store, Utc::now());
    let _ = state.persist_store(&store);
    Json(build_my_stack_payload(&store)).into_response()
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
    let q_lower = params
        .q
        .as_deref()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let src_filter = params
        .source
        .as_deref()
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("ALL"));
    let cat_filter = params
        .category
        .as_deref()
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("ALL"));

    let mut list: Vec<ThreatNewsItem> = store
        .news
        .values()
        .filter(|n| {
            if let Some(src) = src_filter {
                if !n.source.eq_ignore_ascii_case(src) {
                    return false;
                }
            }
            if let Some(cat) = cat_filter {
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

    list.sort_by_key(|a| std::cmp::Reverse(a.published_at));

    let total_matched = list.len();
    let limit = params.limit.unwrap_or(180).min(400);
    list.truncate(limit);

    Json(serde_json::json!({
        "total_matched": total_matched,
        "items": list
    }))
}

#[derive(Debug, Deserialize)]
struct IocQuery {
    lookup: Option<String>,
}

fn refang_ioc_query(raw: &str) -> String {
    let s = raw
        .trim()
        .replace("[.]", ".")
        .replace("(.)", ".")
        .replace("[:]", ":");
    if s.len() >= 8 && s[..8].eq_ignore_ascii_case("hxxps://") {
        format!("https://{}", &s[8..])
    } else if s.len() >= 7 && s[..7].eq_ignore_ascii_case("hxxp://") {
        format!("http://{}", &s[7..])
    } else {
        s
    }
}

fn lookup_single_ioc(store: &ThreatStore, raw: &str) -> IocLookupResult {
    let q = refang_ioc_query(raw);
    let q_lower = q.to_ascii_lowercase();
    let mut hits = Vec::new();

    for ip in &store.telemetry.top_attacking_ips {
        if ip.ip == q {
            hits.push(IocHit {
                feed: "SANS ISC Top Attackers".to_string(),
                indicator_type: "IPv4 Scanner".to_string(),
                detail: format!(
                    "{} attacks ({} packets, last seen {})",
                    ip.attacks, ip.count, ip.last_seen
                ),
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
    if store.compromised_ips_set.contains(&q) {
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
    let risk_verdict = if matched {
        "MALICIOUS / FLAGGED"
    } else {
        "NO MATCH IN LIVE FEEDS"
    }
    .to_string();
    IocLookupResult {
        query: q,
        matched,
        risk_verdict,
        hits,
    }
}

async fn get_iocs(
    State(state): State<AppState>,
    Query(params): Query<IocQuery>,
) -> impl IntoResponse {
    let store = state.store.read().await;
    let lookup_result = params
        .lookup
        .as_deref()
        .map(str::trim)
        .filter(|q| !q.is_empty())
        .map(|q| lookup_single_ioc(&store, q));

    Json(serde_json::json!({
        "telemetry": store.telemetry,
        "lookup_result": lookup_result
    }))
}

async fn bulk_lookup_iocs(
    State(state): State<AppState>,
    Json(req): Json<BulkIocRequest>,
) -> impl IntoResponse {
    let store = state.store.read().await;
    let mut results = Vec::new();
    let mut seen = HashSet::new();

    for raw in req.indicators {
        let q = raw.trim();
        if q.is_empty() || !seen.insert(q.to_ascii_lowercase()) {
            continue;
        }
        results.push(lookup_single_ioc(&store, q));
        if results.len() >= 200 {
            break;
        }
    }

    let matched_count = results.iter().filter(|r| r.matched).count();
    Json(BulkIocResponse {
        checked: results.len(),
        matched_count,
        results,
    })
}

async fn export_iocs(
    State(state): State<AppState>,
    Query(params): Query<ExportFormatQuery>,
) -> impl IntoResponse {
    let store = state.store.read().await;
    let fmt = params.format.as_deref().unwrap_or("edl");
    match export_iocs_blocklist(fmt, &store.telemetry) {
        Ok((body, content_type, filename)) => {
            let disp = format!("attachment; filename=\"{filename}\"");
            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, content_type.to_string()),
                    (header::CONTENT_DISPOSITION, disp),
                ],
                body,
            )
                .into_response()
        }
        Err(msg) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": msg })),
        )
            .into_response(),
    }
}

async fn list_alerts(State(state): State<AppState>) -> impl IntoResponse {
    let store = state.store.read().await;
    let unack = store.alerts.iter().filter(|a| !a.acknowledged).count();
    Json(serde_json::json!({
        "unacknowledged_count": unack,
        "alerts": store.alerts,
    }))
}

async fn ack_alert(State(state): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    if let Err(resp) = require_writable(&state) {
        return *resp;
    }

    let mut store = state.store.write().await;
    if let Some(a) = store.alerts.iter_mut().find(|a| a.id == id) {
        a.acknowledged = true;
        let _ = state.persist_store(&store);
        return Json(serde_json::json!({ "ok": true })).into_response();
    }
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({ "error": "Alert not found" })),
    )
        .into_response()
}

async fn ack_all_alerts(State(state): State<AppState>) -> impl IntoResponse {
    if let Err(resp) = require_writable(&state) {
        return *resp;
    }

    let mut store = state.store.write().await;
    for a in &mut store.alerts {
        a.acknowledged = true;
    }
    let _ = state.persist_store(&store);
    Json(serde_json::json!({ "ok": true })).into_response()
}

async fn trigger_test_alert(State(state): State<AppState>) -> impl IntoResponse {
    if let Err(resp) = require_writable(&state) {
        return *resp;
    }

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
        let _ = state.persist_store(&store);
    }

    let _ = state.sse_tx.send(SseEvent::NewAlert(alert.clone()));
    Json(alert).into_response()
}

async fn list_feeds(State(state): State<AppState>) -> impl IntoResponse {
    let store = state.store.read().await;
    Json(serde_json::json!({
        "last_sweep_at": store.last_sweep_at,
        "next_sweep_at": store.next_sweep_at,
        "sweep_in_progress": state.sweep_in_progress.load(Ordering::SeqCst),
        "feeds": store.feed_health,
        "feed_settings": store.feed_settings,
    }))
}

async fn update_feed_config(
    State(state): State<AppState>,
    Json(req): Json<FeedConfigUpdateRequest>,
) -> impl IntoResponse {
    if let Err(resp) = require_writable(&state) {
        return *resp;
    }

    let feed_id = req.feed_name.trim().to_string();
    if feed_id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "feed_name cannot be empty" })),
        )
            .into_response();
    }

    let mut store = state.store.write().await;
    // Update custom feed toggle if matching custom ID
    if let Some(cf) = store
        .feed_settings
        .custom_feeds
        .iter_mut()
        .find(|f| f.id == feed_id)
    {
        cf.enabled = req.enabled;
    } else {
        store
            .feed_settings
            .disabled_feeds
            .retain(|d| !d.eq_ignore_ascii_case(&feed_id));
        if !req.enabled {
            store.feed_settings.disabled_feeds.push(feed_id);
        }
    }

    let _ = state.persist_store(&store);
    Json(store.feed_settings.clone()).into_response()
}

async fn list_custom_feeds(State(state): State<AppState>) -> impl IntoResponse {
    let store = state.store.read().await;
    Json(store.feed_settings.custom_feeds.clone())
}

async fn create_custom_feed(
    State(state): State<AppState>,
    Json(req): Json<CustomFeedCreateRequest>,
) -> impl IntoResponse {
    if let Err(resp) = require_writable(&state) {
        return *resp;
    }

    let name: String = strip_invisible_unicode(req.name.trim())
        .chars()
        .take(80)
        .collect();
    if name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Custom feed name is required" })),
        )
            .into_response();
    }

    let validated =
        match validate_outbound_url(&req.url, OutboundUrlPolicy::StrictPublicHttps).await {
            Ok(v) => v,
            Err(reason) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": reason })),
                )
                    .into_response();
            }
        };

    let mut store = state.store.write().await;
    if store.feed_settings.custom_feeds.len() >= 25 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Maximum 25 custom feeds allowed" })),
        )
            .into_response();
    }

    let cfg = CustomFeedConfig {
        id: format!("custom-{}", Uuid::new_v4()),
        name,
        url: validated.url.to_string(),
        kind: req.kind,
        enabled: req.enabled.unwrap_or(true),
        last_status: None,
        last_item_count: 0,
        last_checked: None,
    };
    store.feed_settings.custom_feeds.push(cfg.clone());
    let _ = state.persist_store(&store);

    (StatusCode::CREATED, Json(cfg)).into_response()
}

async fn delete_custom_feed(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Err(resp) = require_writable(&state) {
        return *resp;
    }

    let mut store = state.store.write().await;
    let prev = store.feed_settings.custom_feeds.len();
    store.feed_settings.custom_feeds.retain(|f| f.id != id);
    if store.feed_settings.custom_feeds.len() == prev {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Custom feed not found" })),
        )
            .into_response();
    }
    let _ = state.persist_store(&store);
    Json(serde_json::json!({ "ok": true })).into_response()
}

async fn list_webhooks(State(state): State<AppState>) -> impl IntoResponse {
    let store = state.store.read().await;
    let public_hooks: Vec<_> = store.webhooks.iter().map(to_public_webhook).collect();
    Json(public_hooks)
}

async fn create_webhook(
    State(state): State<AppState>,
    Json(req): Json<WebhookCreateRequest>,
) -> impl IntoResponse {
    if let Err(resp) = require_writable(&state) {
        return *resp;
    }

    let name: String = strip_invisible_unicode(req.name.trim())
        .chars()
        .take(80)
        .collect();
    if name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Webhook name is required" })),
        )
            .into_response();
    }

    let validated =
        match validate_outbound_url(&req.url, OutboundUrlPolicy::StrictPublicHttps).await {
            Ok(v) => v,
            Err(reason) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": reason })),
                )
                    .into_response();
            }
        };

    let id = Uuid::new_v4().to_string();
    let secret = req
        .signing_secret
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_default();
    let has_secret = !secret.is_empty();
    if has_secret {
        let _ = keychain_set(&format!("webhook_secret_{id}"), &secret);
    }

    let target = WebhookTarget {
        id,
        name,
        kind: req.kind,
        url: validated.url.to_string(),
        enabled: req.enabled.unwrap_or(true),
        min_severity: req.min_severity.unwrap_or(Severity::High),
        kev_only: req.kev_only.unwrap_or(false),
        stack_only: req.stack_only.unwrap_or(false),
        signing_secret: secret,
        has_signing_secret: has_secret,
        last_status: None,
        last_sent_at: None,
        failure_count: 0,
    };

    let mut store = state.store.write().await;
    if store.webhooks.len() >= 20 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Maximum 20 webhook targets allowed" })),
        )
            .into_response();
    }
    let public_view = to_public_webhook(&target);
    store.webhooks.push(target);
    let _ = state.persist_store(&store);

    (StatusCode::CREATED, Json(public_view)).into_response()
}

async fn update_webhook(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<WebhookUpdateRequest>,
) -> impl IntoResponse {
    if let Err(resp) = require_writable(&state) {
        return *resp;
    }

    let mut store = state.store.write().await;
    let Some(hook) = store.webhooks.iter_mut().find(|w| w.id == id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Webhook target not found" })),
        )
            .into_response();
    };
    if let Some(enabled) = req.enabled {
        hook.enabled = enabled;
    }
    if let Some(min_sev) = req.min_severity {
        hook.min_severity = min_sev;
    }
    if let Some(kev_only) = req.kev_only {
        hook.kev_only = kev_only;
    }
    if let Some(stack_only) = req.stack_only {
        hook.stack_only = stack_only;
    }
    let public_view = to_public_webhook(hook);
    let _ = state.persist_store(&store);
    Json(public_view).into_response()
}

async fn delete_webhook(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Err(resp) = require_writable(&state) {
        return *resp;
    }

    let mut store = state.store.write().await;
    let prev = store.webhooks.len();
    store.webhooks.retain(|w| w.id != id);
    if store.webhooks.len() == prev {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Webhook target not found" })),
        )
            .into_response();
    }
    let _ = keychain_delete(&format!("webhook_secret_{id}"));
    let _ = state.persist_store(&store);
    Json(serde_json::json!({ "ok": true })).into_response()
}

async fn test_webhook(State(state): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    if let Err(resp) = require_writable(&state) {
        return *resp;
    }

    let target = {
        let store = state.store.read().await;
        store.webhooks.iter().find(|w| w.id == id).cloned()
    };
    let Some(target) = target else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Webhook target not found" })),
        )
            .into_response();
    };

    let sample = WebhookDispatchItem {
        alert_title: format!(
            "AiBrainWorX Webhook Connectivity Test ({})",
            match target.kind {
                WebhookKind::Slack => "Slack",
                WebhookKind::Discord => "Discord",
                WebhookKind::Teams => "Microsoft Teams",
                WebhookKind::Generic => "Generic JSON",
            }
        ),
        alert_summary: "Verifying SSRF-validated outbound alert delivery pipeline and optional HMAC-SHA256 signing.".to_string(),
        severity: Severity::High,
        is_kev: false,
        matched_stack: vec!["openssl".to_string()],
        cve_id: Some("CVE-2026-0000".to_string()),
        ai_risk_score: Some(85),
    };
    let payload = build_webhook_payload(target.kind, &sample);
    let res = send_webhook_payload(&target, &payload).await;

    {
        let mut store = state.store.write().await;
        if let Some(hook) = store.webhooks.iter_mut().find(|w| w.id == id) {
            hook.last_sent_at = Some(Utc::now());
            hook.last_status = Some(res.message.clone());
            if res.ok {
                hook.failure_count = 0;
            } else {
                hook.failure_count = hook.failure_count.saturating_add(1);
            }
            let _ = state.persist_store(&store);
        }
    }

    Json(res).into_response()
}

async fn get_delta(State(state): State<AppState>) -> impl IntoResponse {
    let store = state.store.read().await;
    Json(store.latest_delta.clone())
}

async fn ack_delta(State(state): State<AppState>) -> impl IntoResponse {
    if let Err(resp) = require_writable(&state) {
        return *resp;
    }

    let mut store = state.store.write().await;
    if let Some(delta) = &mut store.latest_delta {
        delta.reviewed = true;
    }
    let _ = state.db.mark_latest_delta_reviewed();
    let _ = state.persist_store(&store);
    Json(serde_json::json!({ "ok": true })).into_response()
}

async fn export_snapshot(State(state): State<AppState>) -> impl IntoResponse {
    let store = state.store.read().await;
    match build_offline_snapshot(&store) {
        Ok(env) => {
            let body = serde_json::to_string_pretty(&env).unwrap_or_default();
            (
                StatusCode::OK,
                [
                    (
                        header::CONTENT_TYPE,
                        "application/json; charset=utf-8".to_string(),
                    ),
                    (
                        header::CONTENT_DISPOSITION,
                        "attachment; filename=\"aibrainworx-offline-snapshot.json\"".to_string(),
                    ),
                ],
                body,
            )
                .into_response()
        }
        Err(msg) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": msg })),
        )
            .into_response(),
    }
}

async fn import_snapshot(State(state): State<AppState>, body: Bytes) -> impl IntoResponse {
    if let Err(resp) = require_writable(&state) {
        return *resp;
    }

    let env = match verify_offline_snapshot(&body) {
        Ok(parsed) => parsed,
        Err(msg) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": msg })),
            )
                .into_response();
        }
    };

    let now = Utc::now();
    let vuln_count = env.data.vulnerabilities.len();
    let news_count = env.data.news.len();

    let (total_vulns, total_news, next_sweep_at) = {
        let mut store = state.store.write().await;
        for mut v in env.data.vulnerabilities {
            if let Some(t) = store.triage_map.get(&v.id) {
                v.triage_status = t.status;
                v.triage_notes = t.notes.clone();
            }
            v.kev_days_remaining =
                crate::analyzer::compute_kev_days_remaining(v.kev_due_date.as_deref(), now);
            store.vulnerabilities.insert(v.id.clone(), v);
        }
        for n in env.data.news {
            store.news.insert(n.id.clone(), n);
        }
        for cve in env.data.kev_cve_set {
            store.kev_cve_set.insert(cve);
        }
        store.telemetry = env.data.telemetry;
        store.rebuild_compromised_ip_index();
        store.initialized = true;
        store.last_sweep_at = Some(env.exported_at);

        let stack_cfg = store.my_stack.clone();
        correlate_stack(&mut store.vulnerabilities, &stack_cfg);
        store.ai_brief = generate_ai_brief(&store, now);
        store.prune();
        let _ = state.persist_store(&store);

        (
            store.vulnerabilities.len(),
            store.news.len(),
            store.next_sweep_at.unwrap_or(now),
        )
    };

    let _ = state.sse_tx.send(SseEvent::SweepCompleted {
        completed_at: now,
        new_alerts: 0,
        total_vulns,
        total_news,
        next_sweep_at,
    });

    Json(SnapshotImportResult {
        vulnerabilities_imported: vuln_count,
        news_imported: news_count,
        snapshot_exported_at: env.exported_at,
        sha256_verified: true,
    })
    .into_response()
}

async fn trigger_refresh(State(state): State<AppState>) -> impl IntoResponse {
    if let Err(resp) = require_writable(&state) {
        return *resp;
    }
    if state.server_mode.offline_mode {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Offline Mode is active (--offline); live remote feeds are disabled. Import an offline snapshot instead."
            })),
        )
            .into_response();
    }

    if state.sweep_in_progress.load(Ordering::SeqCst) {
        return (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({ "status": "already_running" })),
        )
            .into_response();
    }
    let state_clone = state.clone();
    tokio::spawn(async move {
        run_sweep(state_clone).await;
    });
    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({ "status": "started" })),
    )
        .into_response()
}

async fn get_rules(State(state): State<AppState>) -> impl IntoResponse {
    let store = state.store.read().await;
    Json(store.rules.clone())
}

async fn update_rules(
    State(state): State<AppState>,
    Json(mut new_rules): Json<AlertRules>,
) -> impl IntoResponse {
    if let Err(resp) = require_writable(&state) {
        return *resp;
    }

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
        store.next_sweep_at =
            Some(last + chrono::Duration::seconds(new_rules.poll_interval_secs as i64));
    }
    let _ = state.persist_store(&store);
    Json(new_rules).into_response()
}

async fn get_ai_config(State(state): State<AppState>) -> impl IntoResponse {
    let store = state.store.read().await;
    Json(to_public_config(&store.ai_config))
}

async fn update_ai_config(
    State(state): State<AppState>,
    Json(upd): Json<AiConfigUpdate>,
) -> impl IntoResponse {
    if let Err(resp) = require_writable(&state) {
        return *resp;
    }

    let mut store = state.store.write().await;
    if let Err(msg) = apply_config_update(&mut store.ai_config, upd) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": msg })),
        )
            .into_response();
    }
    let _ = state.persist_store(&store);
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
    if let Err(resp) = require_writable(&state) {
        return *resp;
    }

    let mut cfg = { state.store.read().await.ai_config.clone() };
    apply_ephemeral_ai_overrides(
        &mut cfg,
        req.provider,
        req.base_url,
        None,
        req.api_key,
        false,
    );
    Json(list_models(&state.ai_http, &cfg).await).into_response()
}

async fn test_ai_connection(
    State(state): State<AppState>,
    Json(req): Json<AiTestRequest>,
) -> impl IntoResponse {
    if let Err(resp) = require_writable(&state) {
        return *resp;
    }

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
    Json(test_connection(&state.ai_http, &cfg).await).into_response()
}

async fn ai_analyze(
    State(state): State<AppState>,
    Json(req): Json<AiQueryRequest>,
) -> impl IntoResponse {
    if let Err(resp) = require_writable(&state) {
        return *resp;
    }

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
    if let Err(resp) = require_writable(&state) {
        return *resp;
    }

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
