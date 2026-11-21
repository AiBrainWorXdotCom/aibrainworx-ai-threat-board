mod ai_providers;
mod analyzer;
mod feeds;
mod models;
mod routes;
mod store;

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use chrono::Utc;
use tokio::sync::{broadcast, RwLock};
use tower_http::compression::CompressionLayer;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::services::{ServeDir, ServeFile};
use tracing::info;

use crate::feeds::run_sweep;
use crate::models::SseEvent;
use crate::routes::api_router;
use crate::store::{AppState, ThreatStore};

#[derive(Clone)]
struct SecurityConfig {
    allowed_origins: Vec<String>,
    dev_mode: bool,
}

fn extract_host_without_port(raw_host: &str) -> Option<&str> {
    let h = raw_host.trim();
    if h.is_empty() || h.contains('@') {
        return None;
    }
    if h.starts_with('[') {
        let end = h.find(']')?;
        let rest = &h[end + 1..];
        if !rest.is_empty() && !rest.starts_with(':') {
            return None;
        }
        Some(&h[..=end])
    } else {
        Some(h.split(':').next().unwrap_or(""))
    }
}

fn is_loopback_host(headers: &HeaderMap) -> bool {
    let Some(raw) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let Some(host) = extract_host_without_port(raw) else {
        return false;
    };
    matches!(
        host.to_ascii_lowercase().as_str(),
        "127.0.0.1" | "localhost" | "[::1]" | "::1"
    )
}

fn forbidden_json(msg: &str) -> Response {
    (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": msg }))).into_response()
}

fn apply_security_headers(resp: &mut Response, no_store: bool) {
    let headers = resp.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("geolocation=(), microphone=(), camera=(), payment=()"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
        ),
    );
    if no_store {
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        );
    }
}

async fn security_middleware(
    State(sec): State<SecurityConfig>,
    req: Request,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();
    let is_api = path.starts_with("/api");

    if !is_loopback_host(req.headers()) {
        let mut resp = forbidden_json("Forbidden: non-loopback Host header rejected");
        apply_security_headers(&mut resp, true);
        return resp;
    }

    if is_api {
        let origin_opt = req
            .headers()
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
            .map(str::trim);

        let origin_allowed = match origin_opt {
            Some(origin) => sec
                .allowed_origins
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(origin)),
            None => false,
        };

        if origin_opt.is_some() && !origin_allowed {
            let mut resp = forbidden_json("Forbidden: cross-origin API request rejected");
            apply_security_headers(&mut resp, true);
            return resp;
        }

        if let Some(sfs) = req
            .headers()
            .get("sec-fetch-site")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_ascii_lowercase())
        {
            if sfs == "cross-site" || (sfs == "same-site" && !(sec.dev_mode && origin_allowed)) {
                let mut resp = forbidden_json("Forbidden: cross-site API request rejected");
                apply_security_headers(&mut resp, true);
                return resp;
            }
        }
    }

    let mut resp = next.run(req).await;
    apply_security_headers(&mut resp, path == "/api/ai/config");
    resp
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "aibrainworx_threat_board=info,tower_http=warn".into()),
        )
        .init();

    let (data_path, dist_dir) = resolve_paths();
    let initial_store = ThreatStore::load_from_disk(&data_path);

    let http = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::limited(5))
        .gzip(true)
        .deflate(true)
        .build()
        .expect("Failed to construct feed HTTP client");

    let ai_http = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(300))
        .redirect(reqwest::redirect::Policy::none())
        .gzip(true)
        .deflate(true)
        .build()
        .expect("Failed to construct AI HTTP client");

    let (sse_tx, _) = broadcast::channel::<SseEvent>(128);

    let state = AppState {
        store: Arc::new(RwLock::new(initial_store)),
        sweep_in_progress: Arc::new(AtomicBool::new(false)),
        sse_tx: sse_tx.clone(),
        http,
        ai_http,
        data_path: data_path.clone(),
        started_at: Instant::now(),
    };

    // Background hourly threat intelligence sweep scheduler
    let sched_state = state.clone();
    tokio::spawn(async move {
        // Immediate startup sweep
        run_sweep(sched_state.clone()).await;

        loop {
            let poll_secs = {
                let s = sched_state.store.read().await;
                s.rules.poll_interval_secs.max(60)
            };
            tokio::time::sleep(Duration::from_secs(poll_secs)).await;
            run_sweep(sched_state.clone()).await;
        }
    });

    // Periodic SSE heartbeat so dashboards stay fresh
    let hb_tx = sse_tx.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            let _ = hb_tx.send(SseEvent::Heartbeat {
                server_time: Utc::now(),
            });
        }
    });

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);
    let dev_mode = std::env::var("DEV_MODE").as_deref() == Ok("1");

    let mut allowed_origins = vec![
        format!("http://127.0.0.1:{}", port),
        format!("http://localhost:{}", port),
        format!("http://[::1]:{}", port),
    ];
    if dev_mode {
        allowed_origins.push("http://127.0.0.1:5173".to_string());
        allowed_origins.push("http://localhost:5173".to_string());
    }

    let cors_origins: Vec<HeaderValue> = allowed_origins
        .iter()
        .filter_map(|o| HeaderValue::from_str(o).ok())
        .collect();

    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list(cors_origins))
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE, header::ACCEPT]);

    let sec_cfg = SecurityConfig {
        allowed_origins,
        dev_mode,
    };

    let index_html = dist_dir.join("index.html");
    let spa_service = ServeDir::new(&dist_dir).not_found_service(ServeFile::new(index_html));

    let app = Router::new()
        .nest("/api", api_router(state.clone()))
        .fallback_service(spa_service)
        .layer(cors)
        .layer(CompressionLayer::new())
        .layer(middleware::from_fn_with_state(sec_cfg, security_middleware));

    let addr = format!("127.0.0.1:{}", port);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind local server socket");

    info!("================================================================");
    info!("AiBrainWorX AI CyberSecurity Threat Analysis Board (Rust + React/Astryx)");
    info!("Dashboard URL : http://{}", addr);
    info!("Data Store    : {}", data_path.display());
    info!("Frontend Dist : {}", dist_dir.display());
    info!("================================================================");

    axum::serve(listener, app)
        .await
        .expect("Axum server exited unexpectedly");
}

fn resolve_paths() -> (PathBuf, PathBuf) {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    // Locate frontend/dist robustly whether started from workspace root or backend/
    let dist_candidates = [
        cwd.join("frontend").join("dist"),
        cwd.join("..").join("frontend").join("dist"),
        PathBuf::from("frontend/dist"),
    ];
    let dist_dir = dist_candidates
        .into_iter()
        .find(|p| p.join("index.html").exists())
        .unwrap_or_else(|| cwd.join("frontend").join("dist"));

    let data_dir = if cwd.join("backend").exists() {
        cwd.join("data")
    } else if cwd.join("..").join("backend").exists() {
        cwd.join("..").join("data")
    } else {
        cwd.join("data")
    };

    (data_dir.join("threat_store.json"), dist_dir)
}
