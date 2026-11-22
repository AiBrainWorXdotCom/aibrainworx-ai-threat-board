mod ai_providers;
mod analyzer;
mod auth;
mod export;
mod feeds;
mod models;
mod routes;
mod security;
mod stack;
mod storage;
mod store;
mod webhooks;

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use chrono::Utc;
use rust_embed::RustEmbed;
use tokio::sync::{broadcast, RwLock};
use tower_http::compression::CompressionLayer;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing::info;

use crate::analyzer::{compute_kev_days_remaining, generate_ai_brief};
use crate::auth::AuthRateLimiter;
use crate::feeds::run_sweep;
use crate::models::SseEvent;
use crate::routes::{api_router, is_auth_enforced, is_request_authenticated};
use crate::security::generate_random_token;
use crate::stack::correlate_stack;
use crate::storage::SqliteStorage;
use crate::store::{AppState, ServerModeConfig, ThreatStore};

#[derive(RustEmbed)]
#[folder = "../frontend/dist"]
struct EmbeddedAssets;

#[derive(Clone)]
struct SecurityConfig {
    allowed_origins: Vec<String>,
    dev_mode: bool,
    bind_is_loopback: bool,
    bind_ip: String,
    state: AppState,
}

#[derive(Debug, Clone)]
struct CliOptions {
    wallboard: bool,
    offline: bool,
    no_auth: bool,
    reset_auth: bool,
    bind: String,
    port: u16,
    data_dir: Option<PathBuf>,
}

fn parse_cli_and_env() -> CliOptions {
    let mut wallboard = std::env::var("WALLBOARD_MODE").as_deref() == Ok("1");
    let mut offline = std::env::var("OFFLINE_MODE").as_deref() == Ok("1");
    let mut no_auth = std::env::var("NO_AUTH").as_deref() == Ok("1");
    let mut reset_auth = false;
    let mut bind = std::env::var("BIND_ADDR")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let mut port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);
    let mut data_dir = std::env::var("DATA_DIR")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from);

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--wallboard" => wallboard = true,
            "--offline" => offline = true,
            "--no-auth" => no_auth = true,
            "--reset-auth" => reset_auth = true,
            "--bind" => {
                if let Some(val) = args.get(i + 1) {
                    bind = val.trim().to_string();
                    i += 1;
                }
            }
            "--port" => {
                if let Some(val) = args.get(i + 1) {
                    if let Ok(p) = val.trim().parse::<u16>() {
                        port = p;
                    }
                    i += 1;
                }
            }
            "--data-dir" => {
                if let Some(val) = args.get(i + 1) {
                    data_dir = Some(PathBuf::from(val.trim()));
                    i += 1;
                }
            }
            "-h" | "--help" => {
                println!(
                    "AiBrainWorX Threat Board v{}\nUsage: aibrainworx-threat-board [OPTIONS]\n  --wallboard         Read-only kiosk display mode\n  --offline           Air-gapped mode (disable outbound threat feed sweeps)\n  --no-auth           Disable login screen on loopback 127.0.0.1 only (ignored on non-loopback)\n  --reset-auth        Clear local admin password & 2FA to return to first-run setup\n  --bind <IP>         Bind IP address (default: 127.0.0.1; non-loopback enforces auth)\n  --port <PORT>       Listen port (default: 8080)\n  --data-dir <DIR>    Override SQLite data directory (default: ./data)",
                    env!("CARGO_PKG_VERSION")
                );
                std::process::exit(0);
            }
            _ => {}
        }
        i += 1;
    }

    CliOptions {
        wallboard,
        offline,
        no_auth,
        reset_auth,
        bind,
        port,
        data_dir,
    }
}

fn is_loopback_bind(bind_ip: &str) -> bool {
    let clean = bind_ip.trim().trim_start_matches('[').trim_end_matches(']');
    matches!(clean, "127.0.0.1" | "::1" | "localhost")
        || clean
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
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

fn is_allowed_host(headers: &HeaderMap, bind_is_loopback: bool, bind_ip: &str) -> bool {
    let Some(raw) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let Some(host) = extract_host_without_port(raw) else {
        return false;
    };
    let lower = host.to_ascii_lowercase();
    let is_loopback = matches!(lower.as_str(), "127.0.0.1" | "localhost" | "[::1]" | "::1");
    if bind_is_loopback {
        return is_loopback;
    }
    if is_loopback {
        return true;
    }
    let clean_bind = bind_ip.trim().trim_start_matches('[').trim_end_matches(']');
    if clean_bind == "0.0.0.0" || clean_bind == "::" {
        return !lower.is_empty();
    }
    lower == clean_bind.to_ascii_lowercase()
}

fn json_error_response(status: StatusCode, msg: &str, auth_required: bool) -> Response {
    (
        status,
        Json(serde_json::json!({
            "error": msg,
            "auth_required": auth_required,
        })),
    )
        .into_response()
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
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
}

fn is_auth_exempt_api_path(path: &str) -> bool {
    matches!(
        path,
        "/api/health"
            | "/api/auth/status"
            | "/api/auth/setup"
            | "/api/auth/login"
            | "/api/auth/logout"
    )
}

async fn security_middleware(
    State(sec): State<SecurityConfig>,
    req: Request,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();
    let is_api = path.starts_with("/api");

    if !is_allowed_host(req.headers(), sec.bind_is_loopback, &sec.bind_ip) {
        let mut resp = json_error_response(
            StatusCode::FORBIDDEN,
            "Forbidden: Host header rejected by local DNS-rebinding policy",
            false,
        );
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
            Some(origin) => {
                let matches_explicit = sec
                    .allowed_origins
                    .iter()
                    .any(|allowed| allowed.eq_ignore_ascii_case(origin));
                let matches_same_host = if !sec.bind_is_loopback {
                    let host_hdr = req
                        .headers()
                        .get(header::HOST)
                        .and_then(|h| h.to_str().ok())
                        .unwrap_or("");
                    url::Url::parse(origin).ok().is_some_and(|u| {
                        let o_host = u.host_str().unwrap_or("");
                        let o_with_port = match u.port() {
                            Some(p) => format!("{o_host}:{p}"),
                            None => o_host.to_string(),
                        };
                        o_with_port.eq_ignore_ascii_case(host_hdr)
                            || o_host.eq_ignore_ascii_case(host_hdr)
                    })
                } else {
                    false
                };
                matches_explicit || matches_same_host
            }
            None => false,
        };

        if origin_opt.is_some() && !origin_allowed {
            let mut resp = json_error_response(
                StatusCode::FORBIDDEN,
                "Forbidden: cross-origin API request rejected",
                false,
            );
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
                let mut resp = json_error_response(
                    StatusCode::FORBIDDEN,
                    "Forbidden: cross-site API request rejected",
                    false,
                );
                apply_security_headers(&mut resp, true);
                return resp;
            }
        }

        if is_auth_enforced(&sec.state)
            && !is_auth_exempt_api_path(&path)
            && !is_request_authenticated(&sec.state, req.headers())
        {
            let mut resp =
                json_error_response(StatusCode::UNAUTHORIZED, "Authentication required", true);
            apply_security_headers(&mut resp, true);
            return resp;
        }
    }

    let mut resp = next.run(req).await;
    let is_sensitive_no_store = path.starts_with("/api/auth/")
        || path == "/api/ai/config"
        || path == "/api/webhooks"
        || path == "/api/snapshot/export";
    apply_security_headers(&mut resp, is_sensitive_no_store);
    resp
}

async fn serve_spa(uri: Uri, static_dir: Option<PathBuf>) -> Response {
    let raw_path = uri.path().trim_start_matches('/');
    let rel_path = if raw_path.is_empty() {
        "index.html"
    } else {
        raw_path
    };

    if rel_path
        .split('/')
        .any(|seg| seg == ".." || seg.contains('\\'))
    {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Optional disk override (used in DEV_MODE=1 or when FRONTEND_DIST exists on disk)
    if let Some(dir) = &static_dir {
        let candidate = dir.join(rel_path);
        if candidate.is_file() {
            if let Ok(bytes) = tokio::fs::read(&candidate).await {
                return build_asset_response(rel_path, bytes);
            }
        }
    }

    if let Some(asset) = EmbeddedAssets::get(rel_path) {
        return build_asset_response(rel_path, asset.data.into_owned());
    }

    // For unmatched file-like asset paths (e.g. missing .js/.css/.png), return 404 instead of index.html
    let looks_like_file = rel_path
        .rsplit('/')
        .next()
        .is_some_and(|seg| seg.contains('.'));
    if looks_like_file {
        return StatusCode::NOT_FOUND.into_response();
    }

    // Client-side SPA route fallback -> index.html
    if let Some(dir) = &static_dir {
        let idx = dir.join("index.html");
        if idx.is_file() {
            if let Ok(bytes) = tokio::fs::read(&idx).await {
                return build_asset_response("index.html", bytes);
            }
        }
    }

    if let Some(idx) = EmbeddedAssets::get("index.html") {
        return build_asset_response("index.html", idx.data.into_owned());
    }

    (
        StatusCode::SERVICE_UNAVAILABLE,
        "Frontend bundle missing — run `cd frontend && npm run build` before cargo build.",
    )
        .into_response()
}

fn build_asset_response(path: &str, bytes: Vec<u8>) -> Response {
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    let mut resp = Response::new(Body::from(bytes));
    if let Ok(ct) = HeaderValue::from_str(mime.as_ref()) {
        resp.headers_mut().insert(header::CONTENT_TYPE, ct);
    }
    if path == "index.html" {
        resp.headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    } else if path.starts_with("assets/") {
        resp.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=31536000, immutable"),
        );
    }
    resp
}

fn build_app(
    state: AppState,
    allowed_origins: Vec<String>,
    dev_mode: bool,
    bind_ip: String,
    static_dir_override: Option<PathBuf>,
) -> Router {
    let bind_is_loopback = is_loopback_bind(&bind_ip);
    let cors_origins: Vec<HeaderValue> = allowed_origins
        .iter()
        .filter_map(|o| HeaderValue::from_str(o).ok())
        .collect();

    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list(cors_origins))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([header::CONTENT_TYPE, header::ACCEPT, header::AUTHORIZATION]);

    let sec_cfg = SecurityConfig {
        allowed_origins,
        dev_mode,
        bind_is_loopback,
        bind_ip,
        state: state.clone(),
    };

    Router::new()
        .nest("/api", api_router(state))
        .fallback(move |uri: Uri| {
            let dir = static_dir_override.clone();
            async move { serve_spa(uri, dir).await }
        })
        .layer(cors)
        .layer(CompressionLayer::new())
        .layer(middleware::from_fn_with_state(sec_cfg, security_middleware))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "aibrainworx_threat_board=info,tower_http=warn".into()),
        )
        .init();

    let cli = parse_cli_and_env();
    let dev_mode = std::env::var("DEV_MODE").as_deref() == Ok("1");
    let (default_data_dir, discovered_dist) = resolve_paths();
    let data_dir = cli.data_dir.unwrap_or(default_data_dir);
    let db_path = data_dir.join("threat_board.db");
    let legacy_json_path = data_dir.join("threat_store.json");

    let db = Arc::new(
        SqliteStorage::open(db_path.clone()).expect("Failed initializing embedded SQLite storage"),
    );
    if cli.reset_auth {
        db.reset_all_auth()
            .expect("Failed resetting local authentication state");
        info!("================================================================");
        info!("--reset-auth: Cleared local admin account, 2FA secrets, and sessions.");
        info!("Open the dashboard in your browser to run First-Run Admin Setup.");
        info!("================================================================");
    }
    if let Err(e) = db.migrate_legacy_json_if_needed(&legacy_json_path) {
        tracing::warn!("Legacy JSON migration warning: {e}");
    }

    let mut initial_store = db.load_store().unwrap_or_else(|e| {
        tracing::warn!("Failed loading SQLite store ({e}); starting fresh");
        ThreatStore::default()
    });
    initial_store.hydrate_secrets_from_keychain();

    // Recompute KEV countdowns & My Stack matches on boot for immediate freshness even offline
    let now = Utc::now();
    for v in initial_store.vulnerabilities.values_mut() {
        v.kev_days_remaining = compute_kev_days_remaining(v.kev_due_date.as_deref(), now);
    }
    let stack_cfg = initial_store.my_stack.clone();
    correlate_stack(&mut initial_store.vulnerabilities, &stack_cfg);
    if initial_store.initialized {
        initial_store.ai_brief = generate_ai_brief(&initial_store, now);
    }

    let bind_is_loopback = is_loopback_bind(&cli.bind);
    let no_auth_mode = if cli.no_auth && !bind_is_loopback {
        tracing::warn!(
            "--no-auth is restricted to loopback (127.0.0.1 / ::1) and was IGNORED for non-loopback bind {}",
            cli.bind
        );
        false
    } else {
        cli.no_auth
    };
    let explicit_token = std::env::var("AUTH_TOKEN")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let auth_token = if explicit_token.is_some() {
        explicit_token
    } else if !bind_is_loopback && !db.has_any_auth_user() {
        let generated = generate_random_token(24).expect("Failed generating CSPRNG access token");
        info!("================================================================");
        info!(
            "NON-LOOPBACK BIND DETECTED ({}) WITHOUT LOCAL ADMIN OR AUTH_TOKEN",
            cli.bind
        );
        info!("Generated fallback session access token (use Bearer header or UI prompt):");
        info!("AUTH_TOKEN={}", generated);
        info!("================================================================");
        Some(generated)
    } else {
        None
    };

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
        db,
        auth_limiter: Arc::new(AuthRateLimiter::new()),
        sweep_in_progress: Arc::new(AtomicBool::new(false)),
        sse_tx: sse_tx.clone(),
        http,
        ai_http,
        server_mode: ServerModeConfig {
            version: env!("CARGO_PKG_VERSION").to_string(),
            wallboard_mode: cli.wallboard,
            offline_mode: cli.offline,
            no_auth_mode,
            auth_token: auth_token.clone(),
            bind_addr: cli.bind.clone(),
        },
        started_at: Instant::now(),
    };

    // Background hourly threat intelligence sweep scheduler (disabled in --offline mode)
    if !cli.offline {
        let sched_state = state.clone();
        tokio::spawn(async move {
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
    } else {
        info!("Air-gapped --offline mode active: background remote feed sweeps disabled.");
    }

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

    let mut allowed_origins = vec![
        format!("http://127.0.0.1:{}", cli.port),
        format!("http://localhost:{}", cli.port),
        format!("http://[::1]:{}", cli.port),
    ];
    if !bind_is_loopback && cli.bind != "0.0.0.0" && cli.bind != "::" {
        allowed_origins.push(format!("http://{}:{}", cli.bind, cli.port));
    }
    if dev_mode {
        allowed_origins.push("http://127.0.0.1:5173".to_string());
        allowed_origins.push("http://localhost:5173".to_string());
    }

    let static_override = std::env::var("FRONTEND_DIST")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            if dev_mode {
                discovered_dist.clone()
            } else {
                None
            }
        });

    let app = build_app(
        state,
        allowed_origins,
        dev_mode,
        cli.bind.clone(),
        static_override.clone(),
    );

    let addr = format!("{}:{}", cli.bind, cli.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind local server socket");

    let frontend_label = static_override
        .as_ref()
        .map(|p| format!("Disk override ({})", p.display()))
        .unwrap_or_else(|| "Embedded single-binary bundle (rust-embed)".to_string());

    info!("================================================================");
    info!(
        "AiBrainWorX Threat Board v{} (SQLite WAL + Single-Binary)",
        env!("CARGO_PKG_VERSION")
    );
    info!("Dashboard URL : http://{}", addr);
    info!("SQLite Store  : {}", db_path.display());
    info!("Frontend      : {}", frontend_label);
    info!(
        "Modes         : wallboard={} | offline={} | auth={} | no_auth={}",
        cli.wallboard,
        cli.offline,
        !no_auth_mode || auth_token.is_some(),
        no_auth_mode
    );
    info!("================================================================");

    axum::serve(listener, app)
        .await
        .expect("Axum server exited unexpectedly");
}

fn resolve_paths() -> (PathBuf, Option<PathBuf>) {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    let dist_candidates = [
        cwd.join("frontend").join("dist"),
        cwd.join("..").join("frontend").join("dist"),
        PathBuf::from("frontend/dist"),
    ];
    let dist_dir = dist_candidates
        .into_iter()
        .find(|p| p.join("index.html").exists());

    let data_dir = if cwd.join("backend").exists() {
        cwd.join("data")
    } else if cwd.join("..").join("backend").exists() {
        cwd.join("..").join("data")
    } else {
        cwd.join("data")
    };

    (data_dir, dist_dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use tower::ServiceExt;

    fn test_state(wallboard_mode: bool, auth_token: Option<String>) -> (AppState, PathBuf) {
        test_state_with_auth(wallboard_mode, auth_token.is_none(), auth_token)
    }

    fn test_state_with_auth(
        wallboard_mode: bool,
        no_auth_mode: bool,
        auth_token: Option<String>,
    ) -> (AppState, PathBuf) {
        let db_path = std::env::temp_dir().join(format!("abw_http_{}.db", uuid::Uuid::new_v4()));
        let db = Arc::new(SqliteStorage::open(db_path.clone()).unwrap());
        let (sse_tx, _) = broadcast::channel::<SseEvent>(16);
        let state = AppState {
            store: Arc::new(RwLock::new(ThreatStore::default())),
            db,
            auth_limiter: Arc::new(AuthRateLimiter::new()),
            sweep_in_progress: Arc::new(AtomicBool::new(false)),
            sse_tx,
            http: reqwest::Client::new(),
            ai_http: reqwest::Client::new(),
            server_mode: ServerModeConfig {
                version: env!("CARGO_PKG_VERSION").to_string(),
                wallboard_mode,
                offline_mode: true,
                no_auth_mode,
                auth_token,
                bind_addr: "127.0.0.1".to_string(),
            },
            started_at: Instant::now(),
        };
        (state, db_path)
    }

    #[tokio::test]
    async fn blocks_dns_rebinding_host_and_cross_origin_requests() {
        let (state, db_path) = test_state(false, None);
        let app = build_app(
            state,
            vec!["http://127.0.0.1:8080".into()],
            false,
            "127.0.0.1".into(),
            None,
        );

        let bad_host = axum::http::Request::builder()
            .uri("/api/health")
            .header(header::HOST, "evil.attacker.com:8080")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(bad_host).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let bad_origin = axum::http::Request::builder()
            .uri("/api/dashboard")
            .header(header::HOST, "127.0.0.1:8080")
            .header(header::ORIGIN, "https://evil.example")
            .body(Body::empty())
            .unwrap();
        let resp2 = app.oneshot(bad_origin).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::FORBIDDEN);

        let _ = std::fs::remove_file(&db_path);
    }

    #[tokio::test]
    async fn enforces_auth_token_and_wallboard_read_only_mode() {
        let (state, db_path) = test_state(true, Some("secret-token-123".into()));
        let app = build_app(
            state,
            vec!["http://127.0.0.1:8080".into()],
            false,
            "127.0.0.1".into(),
            None,
        );

        // /api/health remains exempt
        let health_req = axum::http::Request::builder()
            .uri("/api/health")
            .header(header::HOST, "127.0.0.1:8080")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(health_req).await.unwrap().status(),
            StatusCode::OK
        );

        // /api/dashboard requires token when configured
        let unauth = axum::http::Request::builder()
            .uri("/api/dashboard")
            .header(header::HOST, "127.0.0.1:8080")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(unauth).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );

        // Bearer token grants read access
        let authed = axum::http::Request::builder()
            .uri("/api/dashboard")
            .header(header::HOST, "127.0.0.1:8080")
            .header(header::AUTHORIZATION, "Bearer secret-token-123")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(authed).await.unwrap().status(),
            StatusCode::OK
        );

        // Cookie login endpoint issues HttpOnly session cookie
        let login_req = axum::http::Request::builder()
            .method(Method::POST)
            .uri("/api/auth/login")
            .header(header::HOST, "127.0.0.1:8080")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"token":"secret-token-123"}"#))
            .unwrap();
        let login_resp = app.clone().oneshot(login_req).await.unwrap();
        assert_eq!(login_resp.status(), StatusCode::OK);
        let set_cookie = login_resp
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(set_cookie.contains("HttpOnly"));
        assert!(set_cookie.contains("abw_session=secret-token-123"));

        // Wallboard mode rejects mutating calls even when authenticated
        let wallboard_write = axum::http::Request::builder()
            .method(Method::POST)
            .uri("/api/alerts/test")
            .header(header::HOST, "127.0.0.1:8080")
            .header(header::AUTHORIZATION, "Bearer secret-token-123")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.oneshot(wallboard_write).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );

        let _ = std::fs::remove_file(&db_path);
    }

    #[tokio::test]
    async fn full_local_auth_setup_sessions_lockout_and_totp_flow() {
        use http_body_util::BodyExt;

        let (state, db_path) = test_state_with_auth(false, false, None);
        let app = build_app(
            state,
            vec!["http://127.0.0.1:8080".into()],
            false,
            "127.0.0.1".into(),
            None,
        );

        // 1. Default mode blocks /api/dashboard until setup + login
        let unauth_dash = axum::http::Request::builder()
            .uri("/api/dashboard")
            .header(header::HOST, "127.0.0.1:8080")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(unauth_dash).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );

        // 2. First-run setup creates Argon2id admin & issues random HttpOnly session cookie
        let setup_req = axum::http::Request::builder()
            .method(Method::POST)
            .uri("/api/auth/setup")
            .header(header::HOST, "127.0.0.1:8080")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"username":"socadmin","display_name":"SOC Admin","password":"UltraStrongPassword!99"}"#,
            ))
            .unwrap();
        let setup_resp = app.clone().oneshot(setup_req).await.unwrap();
        assert_eq!(setup_resp.status(), StatusCode::OK);
        let cookie_hdr = setup_resp
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(cookie_hdr.contains("HttpOnly"));
        assert!(cookie_hdr.contains("SameSite=Strict"));
        let session_cookie = cookie_hdr.split(';').next().unwrap().to_string();

        // 3. Second setup attempt is rejected with 403
        let setup_again = axum::http::Request::builder()
            .method(Method::POST)
            .uri("/api/auth/setup")
            .header(header::HOST, "127.0.0.1:8080")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"username":"attacker","password":"AnotherPassword!99"}"#,
            ))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(setup_again).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );

        // 4. Session cookie accesses protected /api/dashboard
        let authed_dash = axum::http::Request::builder()
            .uri("/api/dashboard")
            .header(header::HOST, "127.0.0.1:8080")
            .header(header::COOKIE, &session_cookie)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(authed_dash).await.unwrap().status(),
            StatusCode::OK
        );

        // 5. TOTP enrollment + verification generates offline SVG QR and 8 recovery codes
        let enroll_req = axum::http::Request::builder()
            .method(Method::POST)
            .uri("/api/auth/totp/enroll")
            .header(header::HOST, "127.0.0.1:8080")
            .header(header::COOKIE, &session_cookie)
            .body(Body::empty())
            .unwrap();
        let enroll_resp = app.clone().oneshot(enroll_req).await.unwrap();
        assert_eq!(enroll_resp.status(), StatusCode::OK);
        let enroll_bytes = enroll_resp.into_body().collect().await.unwrap().to_bytes();
        let enroll_json: serde_json::Value = serde_json::from_slice(&enroll_bytes).unwrap();
        let secret_b32 = enroll_json["secret_b32"].as_str().unwrap().to_string();
        assert!(enroll_json["qr_svg_data_uri"]
            .as_str()
            .unwrap()
            .starts_with("data:image/svg+xml;base64,"));

        let now_step = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            / 30;
        let totp_code = crate::auth::totp_code_at_step(&secret_b32, now_step).unwrap();

        let verify_req = axum::http::Request::builder()
            .method(Method::POST)
            .uri("/api/auth/totp/verify")
            .header(header::HOST, "127.0.0.1:8080")
            .header(header::COOKIE, &session_cookie)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(format!(r#"{{"code":"{totp_code}"}}"#)))
            .unwrap();
        let verify_resp = app.clone().oneshot(verify_req).await.unwrap();
        assert_eq!(verify_resp.status(), StatusCode::OK);
        let verify_bytes = verify_resp.into_body().collect().await.unwrap().to_bytes();
        let verify_json: serde_json::Value = serde_json::from_slice(&verify_bytes).unwrap();
        let recovery_code = verify_json["recovery_codes"][0]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(verify_json["recovery_codes"].as_array().unwrap().len(), 8);

        // 6. Logout immediately revokes session cookie in SQLite
        let logout_req = axum::http::Request::builder()
            .method(Method::POST)
            .uri("/api/auth/logout")
            .header(header::HOST, "127.0.0.1:8080")
            .header(header::COOKIE, &session_cookie)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(logout_req).await.unwrap().status(),
            StatusCode::OK
        );

        let revoked_dash = axum::http::Request::builder()
            .uri("/api/dashboard")
            .header(header::HOST, "127.0.0.1:8080")
            .header(header::COOKIE, &session_cookie)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(revoked_dash).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );

        // 7. Login without TOTP returns requires_totp=true challenge
        let step1_req = axum::http::Request::builder()
            .method(Method::POST)
            .uri("/api/auth/login")
            .header(header::HOST, "127.0.0.1:8080")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"username":"socadmin","password":"UltraStrongPassword!99"}"#,
            ))
            .unwrap();
        let step1_resp = app.clone().oneshot(step1_req).await.unwrap();
        assert_eq!(step1_resp.status(), StatusCode::OK);
        let step1_json: serde_json::Value =
            serde_json::from_slice(&step1_resp.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(step1_json["requires_totp"], true);
        assert_eq!(step1_json["authenticated"], false);

        // 8. Login with one-time recovery code succeeds once and fails on reuse
        let rec_login = axum::http::Request::builder()
            .method(Method::POST)
            .uri("/api/auth/login")
            .header(header::HOST, "127.0.0.1:8080")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(format!(
                r#"{{"username":"socadmin","password":"UltraStrongPassword!99","totp_code":"{recovery_code}"}}"#
            )))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(rec_login).await.unwrap().status(),
            StatusCode::OK
        );

        // 9. Five failed logins trigger 429 brute-force lockout
        for attempt in 1..=5 {
            let bad = axum::http::Request::builder()
                .method(Method::POST)
                .uri("/api/auth/login")
                .header(header::HOST, "127.0.0.1:8080")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"username":"socadmin","password":"WrongPassword!00"}"#,
                ))
                .unwrap();
            let resp = app.clone().oneshot(bad).await.unwrap();
            if attempt < 5 {
                assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
            } else {
                assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
                assert!(resp.headers().contains_key(header::RETRY_AFTER));
            }
        }

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(db_path.with_extension("db-wal"));
        let _ = std::fs::remove_file(db_path.with_extension("db-shm"));
    }
}
