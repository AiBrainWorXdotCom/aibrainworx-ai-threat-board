use std::net::IpAddr;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::models::{
    AiConfig, AiConfigPublic, AiConfigUpdate, AiModelsResponse, AiProviderKind, AiProviderPreset,
    AiTestResponse,
};
use crate::security::{
    build_pinned_http_client, is_ip_allowed, keychain_delete, keychain_get, keychain_is_available,
    keychain_set, sanitize_llm_markdown, validate_outbound_url, OutboundUrlPolicy,
    KEYCHAIN_ACCOUNT_AI_API_KEY,
};

const MAX_AI_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_AI_ERROR_BODY_BYTES: usize = 32 * 1024;

pub fn provider_display_name(kind: AiProviderKind) -> &'static str {
    match kind {
        AiProviderKind::Builtin => "Built-in Rust Engine",
        AiProviderKind::Ollama => "Ollama (Local)",
        AiProviderKind::LmStudio => "LM Studio (Local)",
        AiProviderKind::LlamaCpp => "llama.cpp / vLLM / Local",
        AiProviderKind::OpenAi => "OpenAI",
        AiProviderKind::Anthropic => "Anthropic Claude",
        AiProviderKind::Gemini => "Google Gemini",
        AiProviderKind::OpenRouter => "OpenRouter",
        AiProviderKind::Groq => "Groq",
        AiProviderKind::DeepSeek => "DeepSeek",
        AiProviderKind::Mistral => "Mistral AI",
        AiProviderKind::Xai => "xAI Grok",
        AiProviderKind::CustomOpenAi => "Custom OpenAI-Compatible",
    }
}

pub fn default_base_url(kind: AiProviderKind) -> &'static str {
    match kind {
        AiProviderKind::Builtin => "",
        AiProviderKind::Ollama => "http://127.0.0.1:11434",
        AiProviderKind::LmStudio => "http://127.0.0.1:1234/v1",
        AiProviderKind::LlamaCpp => "http://127.0.0.1:8081/v1",
        AiProviderKind::OpenAi => "https://api.openai.com/v1",
        AiProviderKind::Anthropic => "https://api.anthropic.com/v1",
        AiProviderKind::Gemini => "https://generativelanguage.googleapis.com/v1beta",
        AiProviderKind::OpenRouter => "https://openrouter.ai/api/v1",
        AiProviderKind::Groq => "https://api.groq.com/openai/v1",
        AiProviderKind::DeepSeek => "https://api.deepseek.com/v1",
        AiProviderKind::Mistral => "https://api.mistral.ai/v1",
        AiProviderKind::Xai => "https://api.x.ai/v1",
        AiProviderKind::CustomOpenAi => "http://127.0.0.1:8000/v1",
    }
}

pub fn default_model(kind: AiProviderKind) -> &'static str {
    match kind {
        AiProviderKind::Builtin => "local-threat-graph-v1",
        AiProviderKind::Ollama => "qwen2.5:14b",
        AiProviderKind::LmStudio => "local-model",
        AiProviderKind::LlamaCpp => "local-model",
        AiProviderKind::OpenAi => "gpt-4.1-mini",
        AiProviderKind::Anthropic => "claude-sonnet-4-5",
        AiProviderKind::Gemini => "gemini-2.5-flash",
        AiProviderKind::OpenRouter => "anthropic/claude-sonnet-4-5",
        AiProviderKind::Groq => "llama-3.3-70b-versatile",
        AiProviderKind::DeepSeek => "deepseek-chat",
        AiProviderKind::Mistral => "mistral-large-latest",
        AiProviderKind::Xai => "grok-3-mini",
        AiProviderKind::CustomOpenAi => "default",
    }
}

pub fn env_var_for(kind: AiProviderKind) -> Option<&'static str> {
    match kind {
        AiProviderKind::OpenAi => Some("OPENAI_API_KEY"),
        AiProviderKind::Anthropic => Some("ANTHROPIC_API_KEY"),
        AiProviderKind::Gemini => Some("GEMINI_API_KEY"),
        AiProviderKind::OpenRouter => Some("OPENROUTER_API_KEY"),
        AiProviderKind::Groq => Some("GROQ_API_KEY"),
        AiProviderKind::DeepSeek => Some("DEEPSEEK_API_KEY"),
        AiProviderKind::Mistral => Some("MISTRAL_API_KEY"),
        AiProviderKind::Xai => Some("XAI_API_KEY"),
        AiProviderKind::CustomOpenAi => Some("CUSTOM_AI_API_KEY"),
        _ => None,
    }
}

pub fn requires_api_key(kind: AiProviderKind) -> bool {
    matches!(
        kind,
        AiProviderKind::OpenAi
            | AiProviderKind::Anthropic
            | AiProviderKind::Gemini
            | AiProviderKind::OpenRouter
            | AiProviderKind::Groq
            | AiProviderKind::DeepSeek
            | AiProviderKind::Mistral
            | AiProviderKind::Xai
    )
}

pub fn is_default_base_url(kind: AiProviderKind, base: &str) -> bool {
    let def = default_base_url(kind).trim().trim_end_matches('/');
    let cur = base.trim().trim_end_matches('/');
    !def.is_empty() && def.eq_ignore_ascii_case(cur)
}

fn is_loopback_hostname(host: &str) -> bool {
    let clean = host.trim().trim_start_matches('[').trim_end_matches(']');
    if clean.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Ok(ip) = clean.parse::<IpAddr>() {
        return ip.is_loopback();
    }
    false
}

pub fn validate_ai_base_url_with_policy(
    kind: AiProviderKind,
    raw: &str,
    allow_lan: bool,
) -> Result<String, String> {
    if kind == AiProviderKind::Builtin {
        return Ok(String::new());
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("Endpoint Base URL cannot be empty".to_string());
    }
    if trimmed.len() > 512 {
        return Err("Endpoint Base URL exceeds 512 characters".to_string());
    }

    let parsed = url::Url::parse(trimmed).map_err(|_| "Invalid endpoint Base URL".to_string())?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err("Endpoint Base URL must use http:// or https://".to_string());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("Endpoint Base URL must not contain embedded credentials".to_string());
    }

    let host = parsed
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| "Endpoint Base URL must specify a host".to_string())?;

    let host_lower = host.to_ascii_lowercase();
    if matches!(
        host_lower.as_str(),
        "metadata.google.internal" | "metadata.goog" | "instance-data"
    ) || (!allow_lan && (host_lower.ends_with(".local") || host_lower.ends_with(".internal")))
    {
        return Err(
            "Access to cloud metadata or unpermitted internal hostnames is blocked".to_string(),
        );
    }

    let ip_str = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = ip_str.parse::<IpAddr>() {
        if !is_ip_allowed(ip, OutboundUrlPolicy::AiProvider { allow_lan }) {
            return Err(
                "Target IP is blocked by outbound SSRF policy (enable explicit LAN endpoints if using a private LAN server)"
                    .to_string(),
            );
        }
    }

    let allow_http_local_or_lan = is_loopback_hostname(host) || allow_lan;
    if requires_api_key(kind) && parsed.scheme() != "https" && !allow_http_local_or_lan {
        return Err(format!(
            "{} requires https:// for non-loopback endpoints",
            provider_display_name(kind)
        ));
    }

    Ok(parsed.to_string().trim_end_matches('/').to_string())
}

pub fn validate_model_name(model: &str) -> Result<String, String> {
    let trimmed = model.trim();
    if trimmed.is_empty() {
        return Err("Model identifier cannot be empty".to_string());
    }
    if trimmed.chars().count() > 200 {
        return Err("Model identifier exceeds 200 characters".to_string());
    }
    if trimmed.contains('?')
        || trimmed.contains('#')
        || trimmed.contains("..")
        || trimmed.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err("Model identifier contains invalid characters".to_string());
    }
    Ok(trimmed.to_string())
}

pub fn resolve_effective_key(cfg: &AiConfig) -> Option<String> {
    let trimmed = cfg.api_key.trim();
    if !trimmed.is_empty() {
        return Some(trimmed.to_string());
    }

    let env_name = env_var_for(cfg.provider)?;
    // Host environment keys are never sent to overridden custom URLs for cloud presets.
    if cfg.provider != AiProviderKind::CustomOpenAi
        && !is_default_base_url(cfg.provider, &effective_base_url(cfg))
    {
        return None;
    }

    std::env::var(env_name)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub fn mask_secret(secret: &str) -> String {
    let s = secret.trim();
    if s.is_empty() {
        return String::new();
    }
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= 8 {
        return "****".to_string();
    }
    let prefix: String = chars.iter().take(4).collect();
    let suffix: String = chars.iter().skip(chars.len() - 4).collect();
    format!("{}...{}", prefix, suffix)
}

pub fn active_label(cfg: &AiConfig) -> String {
    if cfg.provider == AiProviderKind::Builtin {
        return "Built-in Rust Engine".to_string();
    }
    let model = if cfg.model.trim().is_empty() {
        default_model(cfg.provider)
    } else {
        cfg.model.trim()
    };
    format!("{} · {}", provider_display_name(cfg.provider), model)
}

pub fn provider_presets() -> Vec<AiProviderPreset> {
    let make = |id: AiProviderKind,
                group: &str,
                suggested: &[&str],
                description: &str|
     -> AiProviderPreset {
        let env_var = env_var_for(id);
        let env_present = env_var
            .and_then(|v| std::env::var(v).ok())
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
        AiProviderPreset {
            id,
            name: provider_display_name(id).to_string(),
            group: group.to_string(),
            default_base_url: default_base_url(id).to_string(),
            default_model: default_model(id).to_string(),
            suggested_models: suggested.iter().map(|s| (*s).to_string()).collect(),
            requires_api_key: requires_api_key(id),
            env_var_name: env_var.map(|s| s.to_string()),
            env_key_present: env_present,
            description: description.to_string(),
        }
    };

    vec![
        make(
            AiProviderKind::Builtin,
            "local",
            &["local-threat-graph-v1"],
            "Zero-latency deterministic Rust threat graph & keyword correlation. Always available as instant fallback.",
        ),
        make(
            AiProviderKind::Ollama,
            "local",
            &["qwen2.5:14b", "qwen3:8b", "llama3.1:8b", "mistral:7b", "deepseek-r1:14b"],
            "Local Ollama daemon (/api/chat & /api/tags). Auto-discovers downloaded GGUF models on your machine.",
        ),
        make(
            AiProviderKind::LmStudio,
            "local",
            &["local-model", "qwen2.5-coder-14b-instruct", "meta-llama-3.1-8b-instruct"],
            "LM Studio local inference server on port 1234 using OpenAI-compatible /v1 endpoints.",
        ),
        make(
            AiProviderKind::LlamaCpp,
            "local",
            &["local-model", "default"],
            "Any local OpenAI-compatible runtime: llama-server, vLLM, SGLang, LocalAI, Jan, or TabbyAPI.",
        ),
        make(
            AiProviderKind::OpenAi,
            "cloud",
            &["gpt-4.1-mini", "gpt-4.1", "o4-mini", "gpt-4o"],
            "OpenAI Chat Completions API (/v1/chat/completions).",
        ),
        make(
            AiProviderKind::Anthropic,
            "cloud",
            &["claude-sonnet-4-5", "claude-opus-4-1", "claude-haiku-4-5"],
            "Anthropic Messages API (/v1/messages) for Claude models.",
        ),
        make(
            AiProviderKind::Gemini,
            "cloud",
            &["gemini-2.5-flash", "gemini-2.5-pro", "gemini-2.5-flash-lite"],
            "Google Gemini Generative Language API.",
        ),
        make(
            AiProviderKind::OpenRouter,
            "cloud",
            &[
                "anthropic/claude-sonnet-4-5",
                "openai/gpt-4.1",
                "google/gemini-2.5-flash",
                "qwen/qwen3-235b-a22b",
            ],
            "Unified router across 300+ cloud and open-weights models via a single API key.",
        ),
        make(
            AiProviderKind::Groq,
            "cloud",
            &["llama-3.3-70b-versatile", "qwen-qwq-32b", "mixtral-8x7b-32768"],
            "Ultra-fast Groq LPU inference for Llama & Qwen models.",
        ),
        make(
            AiProviderKind::DeepSeek,
            "cloud",
            &["deepseek-chat", "deepseek-reasoner"],
            "DeepSeek API for V3 and R1 reasoning models.",
        ),
        make(
            AiProviderKind::Mistral,
            "cloud",
            &["mistral-large-latest", "codestral-latest", "mistral-small-latest"],
            "Mistral AI La Plateforme API.",
        ),
        make(
            AiProviderKind::Xai,
            "cloud",
            &["grok-3-mini", "grok-3", "grok-2-latest"],
            "xAI Grok API.",
        ),
        make(
            AiProviderKind::CustomOpenAi,
            "cloud",
            &["default"],
            "Any private enterprise proxy, Azure OpenAI-compatible gateway, or self-hosted /v1 endpoint.",
        ),
    ]
}

pub fn to_public_config(cfg: &AiConfig) -> AiConfigPublic {
    let base = effective_base_url(cfg);
    let env_present = if cfg.provider == AiProviderKind::CustomOpenAi
        || is_default_base_url(cfg.provider, &base)
    {
        env_var_for(cfg.provider)
            .and_then(|v| std::env::var(v).ok())
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false)
    } else {
        false
    };
    let masked = mask_secret(&cfg.api_key);
    let keychain_available = keychain_is_available();
    let keychain_has_key = cfg.save_key_to_keychain
        && keychain_available
        && matches!(keychain_get(KEYCHAIN_ACCOUNT_AI_API_KEY), Ok(Some(s)) if !s.is_empty());

    AiConfigPublic {
        provider: cfg.provider,
        base_url: base,
        model: effective_model(cfg),
        has_api_key: !cfg.api_key.trim().is_empty(),
        api_key_masked: masked,
        env_key_present: env_present,
        keychain_available,
        keychain_has_key,
        temperature: cfg.temperature,
        max_tokens: cfg.max_tokens,
        timeout_secs: cfg.timeout_secs,
        system_prompt: cfg.system_prompt.clone(),
        enrich_briefing: cfg.enrich_briefing,
        allow_lan_endpoints: cfg.allow_lan_endpoints,
        save_key_to_keychain: cfg.save_key_to_keychain,
        active_label: active_label(cfg),
        presets: provider_presets(),
    }
}

pub fn apply_config_update(cfg: &mut AiConfig, upd: AiConfigUpdate) -> Result<(), String> {
    let prev_provider = cfg.provider;
    let prev_base = effective_base_url(cfg);

    if let Some(lan) = upd.allow_lan_endpoints {
        cfg.allow_lan_endpoints = lan;
    }

    let next_provider = upd.provider.unwrap_or(prev_provider);
    let next_base_raw = match upd.base_url.as_deref().map(str::trim) {
        Some(url) if !url.is_empty() => url.to_string(),
        Some(_) => default_base_url(next_provider).to_string(),
        None if next_provider != prev_provider => default_base_url(next_provider).to_string(),
        None => prev_base.clone(),
    };
    let next_base =
        validate_ai_base_url_with_policy(next_provider, &next_base_raw, cfg.allow_lan_endpoints)?;

    let next_model = match upd.model.as_deref().map(str::trim) {
        Some(m) if !m.is_empty() => validate_model_name(m)?,
        Some(_) => default_model(next_provider).to_string(),
        None if next_provider != prev_provider => default_model(next_provider).to_string(),
        None => effective_model(cfg),
    };

    // Never carry a session API key across a provider or endpoint URL change.
    if next_provider != prev_provider || !next_base.eq_ignore_ascii_case(&prev_base) {
        cfg.api_key.clear();
        let _ = keychain_delete(KEYCHAIN_ACCOUNT_AI_API_KEY);
    }

    cfg.provider = next_provider;
    cfg.base_url = next_base;
    cfg.model = next_model;

    if upd.clear_api_key.unwrap_or(false) {
        cfg.api_key.clear();
        let _ = keychain_delete(KEYCHAIN_ACCOUNT_AI_API_KEY);
    } else if let Some(key) = upd.api_key {
        let t = key.trim();
        if !t.is_empty() {
            cfg.api_key = t.to_string();
        }
    }

    if let Some(save_kc) = upd.save_key_to_keychain {
        cfg.save_key_to_keychain = save_kc;
        if !save_kc {
            let _ = keychain_delete(KEYCHAIN_ACCOUNT_AI_API_KEY);
        }
    }

    if cfg.save_key_to_keychain && !cfg.api_key.trim().is_empty() {
        keychain_set(KEYCHAIN_ACCOUNT_AI_API_KEY, &cfg.api_key)?;
    }

    if let Some(temp) = upd.temperature {
        if temp.is_finite() {
            cfg.temperature = temp.clamp(0.0, 2.0);
        }
    }
    if let Some(mt) = upd.max_tokens {
        cfg.max_tokens = mt.clamp(128, 32768);
    }
    if let Some(to) = upd.timeout_secs {
        cfg.timeout_secs = to.clamp(5, 300);
    }
    if let Some(sp) = upd.system_prompt {
        let t = sp.trim();
        if !t.is_empty() {
            cfg.system_prompt = t.chars().take(8000).collect();
        }
    }
    if let Some(eb) = upd.enrich_briefing {
        cfg.enrich_briefing = eb;
    }

    Ok(())
}

pub fn effective_base_url(cfg: &AiConfig) -> String {
    let t = cfg.base_url.trim().trim_end_matches('/');
    if t.is_empty() {
        default_base_url(cfg.provider).to_string()
    } else {
        t.to_string()
    }
}

pub fn effective_model(cfg: &AiConfig) -> String {
    let t = cfg.model.trim();
    if t.is_empty() {
        default_model(cfg.provider).to_string()
    } else {
        t.to_string()
    }
}

fn ollama_root_url(base_url: &str) -> String {
    let trimmed = base_url.trim().trim_end_matches('/');
    trimmed.strip_suffix("/v1").unwrap_or(trimmed).to_string()
}

fn truncate_err(s: &str, max_chars: usize) -> String {
    let trimmed = s.trim();
    if trimmed.chars().count() <= max_chars {
        return trimmed.to_string();
    }
    let mut out: String = trimmed.chars().take(max_chars.saturating_sub(1)).collect();
    out.push('…');
    out
}

async fn read_bounded_bytes(
    mut resp: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    if let Some(len) = resp.content_length() {
        if len > max_bytes as u64 {
            return Err(format!(
                "Upstream response exceeded {} byte limit",
                max_bytes
            ));
        }
    }
    let mut buf = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| format!("Stream read error: {}", e.without_url()))?
    {
        if buf.len().saturating_add(chunk.len()) > max_bytes {
            return Err(format!(
                "Upstream response exceeded {} byte limit",
                max_bytes
            ));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

async fn read_bounded_error_text(resp: reqwest::Response) -> String {
    match read_bounded_bytes(resp, MAX_AI_ERROR_BODY_BYTES).await {
        Ok(bytes) => truncate_err(&String::from_utf8_lossy(&bytes), 300),
        Err(_) => "<error body omitted>".to_string(),
    }
}

pub async fn list_models(_http: &reqwest::Client, cfg: &AiConfig) -> AiModelsResponse {
    let provider = cfg.provider;
    let base = match validate_ai_base_url_with_policy(
        provider,
        &effective_base_url(cfg),
        cfg.allow_lan_endpoints,
    ) {
        Ok(b) => b,
        Err(msg) => {
            return AiModelsResponse {
                ok: false,
                models: Vec::new(),
                source: String::new(),
                error: Some(msg),
            };
        }
    };
    let key = resolve_effective_key(cfg);

    if provider == AiProviderKind::Builtin {
        return AiModelsResponse {
            ok: true,
            models: vec!["local-threat-graph-v1".to_string()],
            source: provider_display_name(provider).to_string(),
            error: None,
        };
    }

    let validated = match validate_outbound_url(
        &base,
        OutboundUrlPolicy::AiProvider {
            allow_lan: cfg.allow_lan_endpoints,
        },
    )
    .await
    {
        Ok(v) => v,
        Err(msg) => {
            return AiModelsResponse {
                ok: false,
                models: Vec::new(),
                source: base,
                error: Some(msg),
            };
        }
    };
    let base = validated.url.as_str().trim_end_matches('/').to_string();
    let http = match build_pinned_http_client(
        &validated,
        Duration::from_secs(12),
        "AiBrainWorX-ThreatBoard/0.2",
    ) {
        Ok(c) => c,
        Err(msg) => {
            return AiModelsResponse {
                ok: false,
                models: Vec::new(),
                source: base,
                error: Some(msg),
            };
        }
    };

    match provider {
        AiProviderKind::Builtin => AiModelsResponse {
            ok: true,
            models: vec!["local-threat-graph-v1".to_string()],
            source: provider_display_name(provider).to_string(),
            error: None,
        },
        AiProviderKind::Ollama => {
            let root = ollama_root_url(&base);
            let url = format!("{}/api/tags", root);
            match tokio::time::timeout(Duration::from_secs(12), http.get(&url).send()).await {
                Ok(Ok(resp)) => {
                    if !resp.status().is_success() {
                        return AiModelsResponse {
                            ok: false,
                            models: Vec::new(),
                            source: url,
                            error: Some(format!("HTTP {} from Ollama /api/tags", resp.status())),
                        };
                    }
                    let bytes = match read_bounded_bytes(resp, MAX_AI_RESPONSE_BYTES).await {
                        Ok(b) => b,
                        Err(e) => {
                            return AiModelsResponse {
                                ok: false,
                                models: Vec::new(),
                                source: url,
                                error: Some(e),
                            };
                        }
                    };
                    match serde_json::from_slice::<Value>(&bytes) {
                        Ok(val) => {
                            let mut models: Vec<String> = val
                                .get("models")
                                .and_then(|m| m.as_array())
                                .map(|arr| {
                                    arr.iter()
                                        .filter_map(|x| x.get("name").and_then(|n| n.as_str()))
                                        .map(|s| s.to_string())
                                        .collect()
                                })
                                .unwrap_or_default();
                            models.sort();
                            AiModelsResponse {
                                ok: true,
                                models,
                                source: url,
                                error: None,
                            }
                        }
                        Err(e) => AiModelsResponse {
                            ok: false,
                            models: Vec::new(),
                            source: url,
                            error: Some(format!("Invalid JSON from Ollama: {}", e)),
                        },
                    }
                }
                Ok(Err(e)) => AiModelsResponse {
                    ok: false,
                    models: Vec::new(),
                    source: url,
                    error: Some(format!(
                        "Could not reach Ollama at {}: {} (is Ollama running?)",
                        root,
                        e.without_url()
                    )),
                },
                Err(_) => AiModelsResponse {
                    ok: false,
                    models: Vec::new(),
                    source: url,
                    error: Some("Timed out contacting Ollama".to_string()),
                },
            }
        }
        AiProviderKind::Gemini => {
            let Some(k) = key else {
                return AiModelsResponse {
                    ok: false,
                    models: Vec::new(),
                    source: base,
                    error: Some(
                        "Enter a Gemini API key (or set GEMINI_API_KEY) to list models."
                            .to_string(),
                    ),
                };
            };
            let url = format!("{}/models", base);
            match tokio::time::timeout(
                Duration::from_secs(12),
                http.get(&url).header("x-goog-api-key", k).send(),
            )
            .await
            {
                Ok(Ok(resp)) => {
                    if !resp.status().is_success() {
                        let status = resp.status();
                        let txt = read_bounded_error_text(resp).await;
                        return AiModelsResponse {
                            ok: false,
                            models: Vec::new(),
                            source: base,
                            error: Some(format!("Gemini HTTP {}: {}", status, txt)),
                        };
                    }
                    let bytes = match read_bounded_bytes(resp, MAX_AI_RESPONSE_BYTES).await {
                        Ok(b) => b,
                        Err(e) => {
                            return AiModelsResponse {
                                ok: false,
                                models: Vec::new(),
                                source: base,
                                error: Some(e),
                            };
                        }
                    };
                    match serde_json::from_slice::<Value>(&bytes) {
                        Ok(val) => {
                            let models: Vec<String> = val
                                .get("models")
                                .and_then(|m| m.as_array())
                                .map(|arr| {
                                    arr.iter()
                                        .filter(|m| {
                                            m.get("supportedGenerationMethods")
                                                .and_then(|g| g.as_array())
                                                .map(|methods| {
                                                    methods.iter().any(|s| {
                                                        s.as_str() == Some("generateContent")
                                                    })
                                                })
                                                .unwrap_or(false)
                                        })
                                        .filter_map(|m| m.get("name").and_then(|n| n.as_str()))
                                        .map(|s| s.strip_prefix("models/").unwrap_or(s).to_string())
                                        .collect()
                                })
                                .unwrap_or_default();
                            AiModelsResponse {
                                ok: true,
                                models,
                                source: base,
                                error: None,
                            }
                        }
                        Err(e) => AiModelsResponse {
                            ok: false,
                            models: Vec::new(),
                            source: base,
                            error: Some(format!("Invalid JSON: {}", e)),
                        },
                    }
                }
                Ok(Err(e)) => AiModelsResponse {
                    ok: false,
                    models: Vec::new(),
                    source: base,
                    error: Some(format!("Request error: {}", e.without_url())),
                },
                Err(_) => AiModelsResponse {
                    ok: false,
                    models: Vec::new(),
                    source: base,
                    error: Some("Timed out fetching Gemini models".to_string()),
                },
            }
        }
        AiProviderKind::Anthropic => {
            let Some(k) = key else {
                return AiModelsResponse {
                    ok: false,
                    models: Vec::new(),
                    source: base,
                    error: Some(
                        "Enter an Anthropic API key (or set ANTHROPIC_API_KEY) to list models."
                            .to_string(),
                    ),
                };
            };
            let url = format!("{}/models", base);
            match tokio::time::timeout(
                Duration::from_secs(12),
                http.get(&url)
                    .header("x-api-key", k)
                    .header("anthropic-version", "2023-06-01")
                    .send(),
            )
            .await
            {
                Ok(Ok(resp)) => {
                    if !resp.status().is_success() {
                        let status = resp.status();
                        let txt = read_bounded_error_text(resp).await;
                        return AiModelsResponse {
                            ok: false,
                            models: Vec::new(),
                            source: url,
                            error: Some(format!("Anthropic HTTP {}: {}", status, txt)),
                        };
                    }
                    let bytes = match read_bounded_bytes(resp, MAX_AI_RESPONSE_BYTES).await {
                        Ok(b) => b,
                        Err(e) => {
                            return AiModelsResponse {
                                ok: false,
                                models: Vec::new(),
                                source: url,
                                error: Some(e),
                            };
                        }
                    };
                    match serde_json::from_slice::<Value>(&bytes) {
                        Ok(val) => {
                            let models: Vec<String> = val
                                .get("data")
                                .and_then(|d| d.as_array())
                                .map(|arr| {
                                    arr.iter()
                                        .filter_map(|x| x.get("id").and_then(|n| n.as_str()))
                                        .map(|s| s.to_string())
                                        .collect()
                                })
                                .unwrap_or_default();
                            AiModelsResponse {
                                ok: true,
                                models,
                                source: url,
                                error: None,
                            }
                        }
                        Err(e) => AiModelsResponse {
                            ok: false,
                            models: Vec::new(),
                            source: url,
                            error: Some(e.to_string()),
                        },
                    }
                }
                Ok(Err(e)) => AiModelsResponse {
                    ok: false,
                    models: Vec::new(),
                    source: url,
                    error: Some(format!("Request error: {}", e.without_url())),
                },
                Err(_) => AiModelsResponse {
                    ok: false,
                    models: Vec::new(),
                    source: url,
                    error: Some("Timed out fetching Anthropic models".to_string()),
                },
            }
        }
        _ => {
            // OpenAI-compatible /v1/models
            let url = if base.ends_with("/models") {
                base.clone()
            } else {
                format!("{}/models", base)
            };
            let mut req = http.get(&url);
            if let Some(k) = key {
                req = req.bearer_auth(k);
            } else if requires_api_key(provider) {
                return AiModelsResponse {
                    ok: false,
                    models: Vec::new(),
                    source: url,
                    error: Some(format!(
                        "API key required for {}.",
                        provider_display_name(provider)
                    )),
                };
            }

            match tokio::time::timeout(Duration::from_secs(12), req.send()).await {
                Ok(Ok(resp)) => {
                    if !resp.status().is_success() {
                        let status = resp.status();
                        let txt = read_bounded_error_text(resp).await;
                        return AiModelsResponse {
                            ok: false,
                            models: Vec::new(),
                            source: url,
                            error: Some(format!("HTTP {}: {}", status, txt)),
                        };
                    }
                    let bytes = match read_bounded_bytes(resp, MAX_AI_RESPONSE_BYTES).await {
                        Ok(b) => b,
                        Err(e) => {
                            return AiModelsResponse {
                                ok: false,
                                models: Vec::new(),
                                source: url,
                                error: Some(e),
                            };
                        }
                    };
                    match serde_json::from_slice::<Value>(&bytes) {
                        Ok(val) => {
                            let mut models: Vec<String> = val
                                .get("data")
                                .and_then(|d| d.as_array())
                                .or_else(|| val.as_array())
                                .map(|arr| {
                                    arr.iter()
                                        .filter_map(|x| x.get("id").and_then(|n| n.as_str()))
                                        .map(|s| s.to_string())
                                        .collect()
                                })
                                .unwrap_or_default();
                            models.sort();
                            AiModelsResponse {
                                ok: true,
                                models,
                                source: url,
                                error: None,
                            }
                        }
                        Err(e) => AiModelsResponse {
                            ok: false,
                            models: Vec::new(),
                            source: url,
                            error: Some(format!("JSON decode error: {}", e)),
                        },
                    }
                }
                Ok(Err(e)) => AiModelsResponse {
                    ok: false,
                    models: Vec::new(),
                    source: url.clone(),
                    error: Some(format!("Connection failed to {}: {}", url, e.without_url())),
                },
                Err(_) => AiModelsResponse {
                    ok: false,
                    models: Vec::new(),
                    source: url,
                    error: Some("Request timed out".to_string()),
                },
            }
        }
    }
}

pub async fn generate_completion(
    _http: &reqwest::Client,
    cfg: &AiConfig,
    system_prompt: &str,
    user_prompt: &str,
) -> Result<(String, u64), String> {
    if cfg.provider == AiProviderKind::Builtin {
        return Err("Built-in Rust Engine selected".to_string());
    }

    let base = validate_ai_base_url_with_policy(
        cfg.provider,
        &effective_base_url(cfg),
        cfg.allow_lan_endpoints,
    )?;
    let model = validate_model_name(&effective_model(cfg))?;
    let key = resolve_effective_key(cfg);
    let timeout = Duration::from_secs(cfg.timeout_secs.clamp(5, 300));
    let validated = validate_outbound_url(
        &base,
        OutboundUrlPolicy::AiProvider {
            allow_lan: cfg.allow_lan_endpoints,
        },
    )
    .await?;
    let base = validated.url.as_str().trim_end_matches('/').to_string();
    let http = build_pinned_http_client(&validated, timeout, "AiBrainWorX-ThreatBoard/0.2")?;
    let t0 = Instant::now();

    match cfg.provider {
        AiProviderKind::Builtin => Err("Built-in Rust Engine selected".to_string()),
        AiProviderKind::Ollama => {
            let root = ollama_root_url(&base);
            let url = format!("{}/api/chat", root);
            let body = json!({
                "model": model,
                "stream": false,
                "options": {
                    "temperature": cfg.temperature,
                    "num_predict": cfg.max_tokens
                },
                "messages": [
                    { "role": "system", "content": system_prompt },
                    { "role": "user", "content": user_prompt }
                ]
            });

            let resp = tokio::time::timeout(timeout, http.post(&url).json(&body).send())
                .await
                .map_err(|_| {
                    format!(
                        "Timed out after {}s waiting for Ollama at {}",
                        timeout.as_secs(),
                        root
                    )
                })?
                .map_err(|e| {
                    format!(
                        "Connection failed to Ollama at {}: {} (is Ollama running?)",
                        root,
                        e.without_url()
                    )
                })?;

            let status = resp.status();
            if !status.is_success() {
                let err_body = read_bounded_error_text(resp).await;
                return Err(format!("Ollama HTTP {}: {}", status, err_body));
            }
            let bytes = read_bounded_bytes(resp, MAX_AI_RESPONSE_BYTES).await?;
            let val: Value = serde_json::from_slice(&bytes)
                .map_err(|e| format!("Invalid Ollama JSON response: {}", e))?;
            let text = val
                .pointer("/message/content")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "Ollama returned an empty message".to_string())?;
            Ok((text.to_string(), t0.elapsed().as_millis() as u64))
        }
        AiProviderKind::Anthropic => {
            let api_key = key.ok_or_else(|| {
                "Anthropic API key missing (enter key or set ANTHROPIC_API_KEY)".to_string()
            })?;
            let url = format!("{}/messages", base);
            let body = json!({
                "model": model,
                "max_tokens": cfg.max_tokens,
                "temperature": cfg.temperature,
                "system": system_prompt,
                "messages": [
                    { "role": "user", "content": user_prompt }
                ]
            });

            let resp = tokio::time::timeout(
                timeout,
                http.post(&url)
                    .header("x-api-key", api_key)
                    .header("anthropic-version", "2023-06-01")
                    .json(&body)
                    .send(),
            )
            .await
            .map_err(|_| {
                format!(
                    "Timed out after {}s waiting for Anthropic",
                    timeout.as_secs()
                )
            })?
            .map_err(|e| format!("Anthropic request error: {}", e.without_url()))?;

            let status = resp.status();
            if !status.is_success() {
                let err_body = read_bounded_error_text(resp).await;
                return Err(format!("Anthropic HTTP {}: {}", status, err_body));
            }
            let bytes = read_bounded_bytes(resp, MAX_AI_RESPONSE_BYTES).await?;
            let val: Value = serde_json::from_slice(&bytes)
                .map_err(|e| format!("Invalid Anthropic JSON: {}", e))?;
            let text = val
                .pointer("/content/0/text")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "Anthropic returned empty content".to_string())?;
            Ok((text.to_string(), t0.elapsed().as_millis() as u64))
        }
        AiProviderKind::Gemini => {
            let api_key = key.ok_or_else(|| {
                "Gemini API key missing (enter key or set GEMINI_API_KEY)".to_string()
            })?;
            let clean_model = model.strip_prefix("models/").unwrap_or(&model);
            let url = format!("{}/models/{}:generateContent", base, clean_model);
            let body = json!({
                "systemInstruction": {
                    "parts": [{ "text": system_prompt }]
                },
                "contents": [
                    { "role": "user", "parts": [{ "text": user_prompt }] }
                ],
                "generationConfig": {
                    "temperature": cfg.temperature,
                    "maxOutputTokens": cfg.max_tokens
                }
            });

            let resp = tokio::time::timeout(
                timeout,
                http.post(&url)
                    .header("x-goog-api-key", api_key)
                    .json(&body)
                    .send(),
            )
            .await
            .map_err(|_| format!("Timed out after {}s waiting for Gemini", timeout.as_secs()))?
            .map_err(|e| format!("Gemini request error: {}", e.without_url()))?;

            let status = resp.status();
            if !status.is_success() {
                let err_body = read_bounded_error_text(resp).await;
                return Err(format!("Gemini HTTP {}: {}", status, err_body));
            }
            let bytes = read_bounded_bytes(resp, MAX_AI_RESPONSE_BYTES).await?;
            let val: Value = serde_json::from_slice(&bytes)
                .map_err(|e| format!("Invalid Gemini JSON: {}", e))?;
            let text = val
                .pointer("/candidates/0/content/parts/0/text")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "Gemini returned empty candidate text".to_string())?;
            Ok((text.to_string(), t0.elapsed().as_millis() as u64))
        }
        _ => {
            // OpenAI-compatible chat completions
            if requires_api_key(cfg.provider) && key.is_none() {
                return Err(format!(
                    "{} requires an API key (enter key or set {}).",
                    provider_display_name(cfg.provider),
                    env_var_for(cfg.provider).unwrap_or("API key")
                ));
            }
            let url = if base.ends_with("/chat/completions") {
                base.clone()
            } else {
                format!("{}/chat/completions", base)
            };

            let body = json!({
                "model": model,
                "temperature": cfg.temperature,
                "max_tokens": cfg.max_tokens,
                "stream": false,
                "messages": [
                    { "role": "system", "content": system_prompt },
                    { "role": "user", "content": user_prompt }
                ]
            });

            let mut req = http.post(&url).json(&body);
            if let Some(k) = key {
                req = req.bearer_auth(k);
            }
            if cfg.provider == AiProviderKind::OpenRouter {
                req = req
                    .header("HTTP-Referer", "http://127.0.0.1:8080")
                    .header("X-Title", "AiBrainWorX CyberSecurity Board");
            }

            let resp = tokio::time::timeout(timeout, req.send())
                .await
                .map_err(|_| {
                    format!(
                        "Timed out after {}s waiting for {}",
                        timeout.as_secs(),
                        provider_display_name(cfg.provider)
                    )
                })?
                .map_err(|e| format!("Connection failed to {}: {}", url, e.without_url()))?;

            let status = resp.status();
            if !status.is_success() {
                let err_body = read_bounded_error_text(resp).await;
                return Err(format!(
                    "{} HTTP {}: {}",
                    provider_display_name(cfg.provider),
                    status,
                    err_body
                ));
            }
            let bytes = read_bounded_bytes(resp, MAX_AI_RESPONSE_BYTES).await?;
            let val: Value = serde_json::from_slice(&bytes)
                .map_err(|e| format!("Invalid JSON from {}: {}", url, e))?;
            let text = val
                .pointer("/choices/0/message/content")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .or_else(|| {
                    val.pointer("/choices/0/message/reasoning_content")
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                })
                .ok_or_else(|| {
                    format!(
                        "{} returned empty completion content",
                        provider_display_name(cfg.provider)
                    )
                })?;

            Ok((text.to_string(), t0.elapsed().as_millis() as u64))
        }
    }
}

pub async fn test_connection(http: &reqwest::Client, cfg: &AiConfig) -> AiTestResponse {
    let provider_label = provider_display_name(cfg.provider).to_string();
    let model = effective_model(cfg);

    if cfg.provider == AiProviderKind::Builtin {
        return AiTestResponse {
            ok: true,
            latency_ms: 0,
            provider_label,
            model,
            reply: Some(
                "Built-in Local Rust Threat Graph active (zero external dependencies).".to_string(),
            ),
            error: None,
        };
    }

    match generate_completion(
        http,
        cfg,
        "You are verifying connectivity for a CyberSecurity SOC dashboard.",
        "Reply with 'CONNECTED' and state your model name in one concise sentence.",
    )
    .await
    {
        Ok((reply, latency_ms)) => AiTestResponse {
            ok: true,
            latency_ms,
            provider_label,
            model,
            reply: Some(sanitize_llm_markdown(&reply)),
            error: None,
        },
        Err(err) => AiTestResponse {
            ok: false,
            latency_ms: 0,
            provider_label,
            model,
            reply: None,
            error: Some(err),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_url_policy_enforces_lan_opt_in_and_loopback() {
        assert!(validate_ai_base_url_with_policy(
            AiProviderKind::Ollama,
            "http://127.0.0.1:11434/v1",
            false
        )
        .is_ok());
        assert!(validate_ai_base_url_with_policy(
            AiProviderKind::Ollama,
            "http://192.168.1.50:11434/v1",
            false
        )
        .is_err());
        assert!(validate_ai_base_url_with_policy(
            AiProviderKind::Ollama,
            "http://192.168.1.50:11434/v1",
            true
        )
        .is_ok());
        assert!(validate_ai_base_url_with_policy(
            AiProviderKind::OpenAi,
            "https://169.254.169.254/v1",
            true
        )
        .is_err());
    }
}
