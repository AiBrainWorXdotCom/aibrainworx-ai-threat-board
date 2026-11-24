use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::warn;

use crate::security::{
    build_pinned_http_client, keychain_delete, keychain_get, keychain_is_available, keychain_set,
    strip_invisible_unicode, validate_outbound_url, OutboundUrlPolicy,
};

const MAX_OTX_PULSES_STORED: usize = 30;
const MAX_OTX_INDICATORS_TOTAL: usize = 15_000;
const MAX_HTTP_BODY_BYTES: usize = 4 * 1024 * 1024;

pub const KEYCHAIN_CTI_OTX: &str = "cti_key_otx";
pub const KEYCHAIN_CTI_GREYNOISE: &str = "cti_key_greynoise";
pub const KEYCHAIN_CTI_ABUSEIPDB: &str = "cti_key_abuseipdb";
pub const KEYCHAIN_CTI_VIRUSTOTAL: &str = "cti_key_virustotal";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CtiProviderId {
    Otx,
    Greynoise,
    Abuseipdb,
    Virustotal,
}

impl CtiProviderId {
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Otx => "AlienVault / LevelBlue OTX",
            Self::Greynoise => "GreyNoise Community",
            Self::Abuseipdb => "AbuseIPDB v2",
            Self::Virustotal => "VirusTotal v3",
        }
    }

    pub fn env_var(&self) -> &'static str {
        match self {
            Self::Otx => "OTX_API_KEY",
            Self::Greynoise => "GREYNOISE_API_KEY",
            Self::Abuseipdb => "ABUSEIPDB_API_KEY",
            Self::Virustotal => "VIRUSTOTAL_API_KEY",
        }
    }

    pub fn keychain_account(&self) -> &'static str {
        match self {
            Self::Otx => KEYCHAIN_CTI_OTX,
            Self::Greynoise => KEYCHAIN_CTI_GREYNOISE,
            Self::Abuseipdb => KEYCHAIN_CTI_ABUSEIPDB,
            Self::Virustotal => KEYCHAIN_CTI_VIRUSTOTAL,
        }
    }
}

/// Optional BYO CTI provider configuration.
/// SECURITY: All API keys are marked `#[serde(skip)]` so they NEVER serialize to SQLite,
/// disk files, API responses, or offline snapshots.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct CtiConfig {
    pub otx_enabled: bool,
    pub otx_sync_pulses: bool,
    pub greynoise_enabled: bool,
    pub abuseipdb_enabled: bool,
    pub virustotal_enabled: bool,
    pub save_keys_to_keychain: bool,

    #[serde(skip)]
    pub otx_api_key: String,
    #[serde(skip)]
    pub greynoise_api_key: String,
    #[serde(skip)]
    pub abuseipdb_api_key: String,
    #[serde(skip)]
    pub virustotal_api_key: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CtiProviderStatusPublic {
    pub id: CtiProviderId,
    pub name: String,
    pub enabled: bool,
    pub has_key: bool,
    pub key_masked: String,
    pub env_var: String,
    pub env_key_present: bool,
    pub keychain_has_key: bool,
    pub key_optional: bool,
    pub supports: Vec<String>,
    pub description: String,
    pub signup_url: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CtiConfigPublic {
    pub save_keys_to_keychain: bool,
    pub keychain_available: bool,
    pub otx_sync_pulses: bool,
    pub otx_pulse_count: usize,
    pub otx_indicator_count: usize,
    pub otx_last_synced_at: Option<DateTime<Utc>>,
    pub otx_pulses_preview: Vec<OtxPulseSummary>,
    pub cached_enrichment_count: usize,
    pub providers: Vec<CtiProviderStatusPublic>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct CtiConfigUpdateRequest {
    pub otx_enabled: Option<bool>,
    pub otx_sync_pulses: Option<bool>,
    pub greynoise_enabled: Option<bool>,
    pub abuseipdb_enabled: Option<bool>,
    pub virustotal_enabled: Option<bool>,
    pub save_keys_to_keychain: Option<bool>,

    pub otx_api_key: Option<String>,
    pub clear_otx_key: Option<bool>,
    pub greynoise_api_key: Option<String>,
    pub clear_greynoise_key: Option<bool>,
    pub abuseipdb_api_key: Option<String>,
    pub clear_abuseipdb_key: Option<bool>,
    pub virustotal_api_key: Option<String>,
    pub clear_virustotal_key: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtxPulseSummary {
    pub id: String,
    pub name: String,
    pub author: String,
    pub modified: String,
    pub indicator_count: usize,
    pub tags: Vec<String>,
}

/// Locally cached indicators pulled privately from the user's subscribed OTX Pulses.
/// Enables 100% local matching in Network IOCs and Wireshark PCAP triage without sending
/// internal IPs/domains to any third party.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct OtxPulseCache {
    pub last_synced_at: Option<DateTime<Utc>>,
    pub pulse_count: usize,
    pub indicator_count: usize,
    pub pulses: Vec<OtxPulseSummary>,
    pub ip_pulses: HashMap<String, Vec<String>>,
    pub domain_pulses: HashMap<String, Vec<String>>,
    pub hash_pulses: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CtiTestRequest {
    pub provider: CtiProviderId,
    pub api_key: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CtiTestResponse {
    pub provider: CtiProviderId,
    pub ok: bool,
    pub latency_ms: u64,
    pub message: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CtiEnrichRequest {
    pub indicator: String,
    #[serde(default)]
    pub force_refresh: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtiProviderFinding {
    pub provider: CtiProviderId,
    pub provider_name: String,
    pub ok: bool,
    pub verdict: String, // "MALICIOUS" | "SUSPICIOUS" | "BENIGN" | "CLEAN" | "SKIPPED" | "ERROR"
    pub score: Option<u32>,
    pub summary: String,
    pub tags: Vec<String>,
    pub reference_url: Option<String>,
    pub latency_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtiEnrichmentResponse {
    pub indicator: String,
    pub indicator_type: String, // "ipv4" | "ipv6" | "domain" | "file_hash"
    pub overall_verdict: String, // "MALICIOUS" | "SUSPICIOUS" | "BENIGN / NOISE" | "CLEAN / UNKNOWN"
    pub enriched_at: DateTime<Utc>,
    #[serde(default)]
    pub cached: bool,
    pub findings: Vec<CtiProviderFinding>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OtxSyncResponse {
    pub ok: bool,
    pub pulse_count: usize,
    pub indicator_count: usize,
    pub ip_count: usize,
    pub domain_count: usize,
    pub hash_count: usize,
    pub latency_ms: u64,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrichIndicator {
    Ipv4(String),
    Ipv6(String),
    Domain(String),
    FileHash(String),
}

impl EnrichIndicator {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Ipv4(s) | Self::Ipv6(s) | Self::Domain(s) | Self::FileHash(s) => s,
        }
    }

    pub fn kind_str(&self) -> &'static str {
        match self {
            Self::Ipv4(_) => "ipv4",
            Self::Ipv6(_) => "ipv6",
            Self::Domain(_) => "domain",
            Self::FileHash(_) => "file_hash",
        }
    }
}

fn mask_secret(secret: &str) -> String {
    let t = secret.trim();
    if t.is_empty() {
        return String::new();
    }
    let chars: Vec<char> = t.chars().collect();
    if chars.len() <= 6 {
        "••••••".to_string()
    } else {
        let tail: String = chars[chars.len() - 4..].iter().collect();
        format!("••••••••{tail}")
    }
}

fn env_key(provider: CtiProviderId) -> Option<String> {
    std::env::var(provider.env_var())
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub fn effective_cti_key(cfg: &CtiConfig, provider: CtiProviderId) -> Option<String> {
    let mem = match provider {
        CtiProviderId::Otx => &cfg.otx_api_key,
        CtiProviderId::Greynoise => &cfg.greynoise_api_key,
        CtiProviderId::Abuseipdb => &cfg.abuseipdb_api_key,
        CtiProviderId::Virustotal => &cfg.virustotal_api_key,
    };
    if !mem.trim().is_empty() {
        return Some(mem.trim().to_string());
    }
    env_key(provider)
}

pub fn hydrate_cti_keys_from_keychain(cfg: &mut CtiConfig) {
    if !cfg.save_keys_to_keychain {
        return;
    }
    let slots: [(CtiProviderId, &mut String); 4] = [
        (CtiProviderId::Otx, &mut cfg.otx_api_key),
        (CtiProviderId::Greynoise, &mut cfg.greynoise_api_key),
        (CtiProviderId::Abuseipdb, &mut cfg.abuseipdb_api_key),
        (CtiProviderId::Virustotal, &mut cfg.virustotal_api_key),
    ];
    for (prov, slot) in slots {
        if slot.is_empty() {
            match keychain_get(prov.keychain_account()) {
                Ok(Some(sec)) if !sec.is_empty() => *slot = sec,
                Ok(_) => {}
                Err(e) => warn!("OS Keychain read skipped for {}: {e}", prov.display_name()),
            }
        }
    }
}

pub fn to_public_cti_config(
    cfg: &CtiConfig,
    cache: &OtxPulseCache,
    cached_enrichment_count: usize,
) -> CtiConfigPublic {
    let kc_avail = keychain_is_available();
    type ProviderSpec<'a> = (CtiProviderId, bool, bool, &'a [&'a str], &'a str, &'a str);
    let specs: [ProviderSpec<'_>; 4] = [
        (
            CtiProviderId::Otx,
            cfg.otx_enabled,
            false,
            &["IPv4", "IPv6", "Domain", "Hash", "Local Pulse Sync"],
            "Free community + LevelBlue Labs threat pulses (~10k req/hr). Supports 100% private local pulse sync into IOC & Wireshark PCAP matching.",
            "https://otx.alienvault.com/settings",
        ),
        (
            CtiProviderId::Greynoise,
            cfg.greynoise_enabled,
            true,
            &["IPv4"],
            "Separates mass internet background scanners (noise) and benign services (RIOT) from targeted attackers — cuts alert fatigue dramatically.",
            "https://viz.greynoise.io/account/api-key",
        ),
        (
            CtiProviderId::Abuseipdb,
            cfg.abuseipdb_enabled,
            false,
            &["IPv4", "IPv6"],
            "Crowd-sourced IP abuse confidence scores (0–100%), ISP metadata, Tor flags, and report volume (free 1,000 checks/day).",
            "https://www.abuseipdb.com/account/api",
        ),
        (
            CtiProviderId::Virustotal,
            cfg.virustotal_enabled,
            false,
            &["IPv4", "IPv6", "Domain", "Hash"],
            "Multi-engine malware & domain reputation counts (free 4 req/min — great for spot-checking suspicious PCAP hosts or file hashes).",
            "https://www.virustotal.com/gui/my-apikey",
        ),
    ];

    let providers = specs
        .into_iter()
        .map(
            |(id, enabled, key_optional, supports, description, signup_url)| {
                let eff = effective_cti_key(cfg, id);
                let has_env = env_key(id).is_some();
                let kc_has = kc_avail
                    && cfg.save_keys_to_keychain
                    && matches!(keychain_get(id.keychain_account()), Ok(Some(ref s)) if !s.is_empty());
                CtiProviderStatusPublic {
                    id,
                    name: id.display_name().to_string(),
                    enabled,
                    has_key: eff.is_some(),
                    key_masked: eff.as_deref().map(mask_secret).unwrap_or_default(),
                    env_var: id.env_var().to_string(),
                    env_key_present: has_env,
                    keychain_has_key: kc_has,
                    key_optional,
                    supports: supports.iter().map(|s| (*s).to_string()).collect(),
                    description: description.to_string(),
                    signup_url: signup_url.to_string(),
                }
            },
        )
        .collect();

    CtiConfigPublic {
        save_keys_to_keychain: cfg.save_keys_to_keychain,
        keychain_available: kc_avail,
        otx_sync_pulses: cfg.otx_sync_pulses,
        otx_pulse_count: cache.pulse_count,
        otx_indicator_count: cache.indicator_count,
        otx_last_synced_at: cache.last_synced_at,
        otx_pulses_preview: cache.pulses.iter().take(12).cloned().collect(),
        cached_enrichment_count,
        providers,
    }
}

pub fn apply_cti_config_update(cfg: &mut CtiConfig, req: CtiConfigUpdateRequest) {
    if let Some(v) = req.otx_enabled {
        cfg.otx_enabled = v;
    }
    if let Some(v) = req.otx_sync_pulses {
        cfg.otx_sync_pulses = v;
    }
    if let Some(v) = req.greynoise_enabled {
        cfg.greynoise_enabled = v;
    }
    if let Some(v) = req.abuseipdb_enabled {
        cfg.abuseipdb_enabled = v;
    }
    if let Some(v) = req.virustotal_enabled {
        cfg.virustotal_enabled = v;
    }
    if let Some(v) = req.save_keys_to_keychain {
        cfg.save_keys_to_keychain = v;
        if !v {
            // Clear saved keychain items when user opts out back to RAM-only
            for prov in [
                CtiProviderId::Otx,
                CtiProviderId::Greynoise,
                CtiProviderId::Abuseipdb,
                CtiProviderId::Virustotal,
            ] {
                let _ = keychain_delete(prov.keychain_account());
            }
        }
    }

    let updates = [
        (CtiProviderId::Otx, req.otx_api_key, req.clear_otx_key),
        (
            CtiProviderId::Greynoise,
            req.greynoise_api_key,
            req.clear_greynoise_key,
        ),
        (
            CtiProviderId::Abuseipdb,
            req.abuseipdb_api_key,
            req.clear_abuseipdb_key,
        ),
        (
            CtiProviderId::Virustotal,
            req.virustotal_api_key,
            req.clear_virustotal_key,
        ),
    ];

    for (prov, new_key, clear_flag) in updates {
        let slot = match prov {
            CtiProviderId::Otx => &mut cfg.otx_api_key,
            CtiProviderId::Greynoise => &mut cfg.greynoise_api_key,
            CtiProviderId::Abuseipdb => &mut cfg.abuseipdb_api_key,
            CtiProviderId::Virustotal => &mut cfg.virustotal_api_key,
        };
        if clear_flag.unwrap_or(false) {
            slot.clear();
            let _ = keychain_delete(prov.keychain_account());
        } else if let Some(k) = new_key {
            let trimmed = k.trim();
            if !trimmed.is_empty() {
                *slot = trimmed.to_string();
                match prov {
                    CtiProviderId::Otx => cfg.otx_enabled = true,
                    CtiProviderId::Greynoise => cfg.greynoise_enabled = true,
                    CtiProviderId::Abuseipdb => cfg.abuseipdb_enabled = true,
                    CtiProviderId::Virustotal => cfg.virustotal_enabled = true,
                }
            }
        }

        if cfg.save_keys_to_keychain && !slot.is_empty() {
            let _ = keychain_set(prov.keychain_account(), slot);
        }
    }
}

fn is_non_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || (o[0] == 100 && (64..=127).contains(&o[1]))
        }
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unspecified()
                || (segs[0] & 0xfe00) == 0xfc00
                || (segs[0] & 0xffc0) == 0xfe80
        }
    }
}

fn refang(raw: &str) -> String {
    let s = strip_invisible_unicode(raw)
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

/// Validates and classifies an indicator before ANY outbound CTI enrichment call.
/// Strictly refuses RFC1918/private/loopback IPs and internal hostnames (`.local`, `.internal`, `.lan`).
pub fn classify_and_validate_indicator(raw: &str) -> Result<EnrichIndicator, String> {
    let cleaned = refang(raw);
    if cleaned.is_empty() {
        return Err("Indicator cannot be empty".to_string());
    }

    // If URL provided, extract hostname
    let candidate = if cleaned.contains("://") {
        let parsed = url::Url::parse(&cleaned).map_err(|_| "Invalid URL format".to_string())?;
        parsed
            .host_str()
            .ok_or_else(|| "URL missing hostname".to_string())?
            .to_string()
    } else {
        cleaned
    };
    let candidate = candidate.trim().trim_end_matches('.');

    // Check IPv4 / IPv6
    if let Ok(ip) = candidate.parse::<IpAddr>() {
        if is_non_public_ip(ip) {
            return Err(format!(
                "Privacy Guard: Refusing to send private/internal IP ({ip}) to external CTI APIs."
            ));
        }
        return Ok(match ip {
            IpAddr::V4(v4) => EnrichIndicator::Ipv4(v4.to_string()),
            IpAddr::V6(v6) => EnrichIndicator::Ipv6(v6.to_string()),
        });
    }

    // Check MD5 (32), SHA1 (40), SHA256 (64) hex hash
    if matches!(candidate.len(), 32 | 40 | 64) && candidate.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(EnrichIndicator::FileHash(candidate.to_ascii_lowercase()));
    }

    // Check public domain
    let lower = candidate.to_ascii_lowercase();
    if lower.len() < 3
        || lower.len() > 253
        || !lower.contains('.')
        || !lower
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        return Err(
            "Enter a valid public IPv4/IPv6 address, domain name, or MD5/SHA1/SHA256 file hash."
                .to_string(),
        );
    }

    const INTERNAL_SUFFIXES: &[&str] = &[
        ".local",
        ".localhost",
        ".internal",
        ".lan",
        ".home",
        ".home.arpa",
        ".corp",
        ".intranet",
        ".localdomain",
    ];
    if INTERNAL_SUFFIXES.iter().any(|suf| lower.ends_with(suf)) {
        return Err(format!(
            "Privacy Guard: Refusing to send internal domain ({lower}) to external CTI APIs."
        ));
    }

    Ok(EnrichIndicator::Domain(lower))
}

async fn pinned_get_json(
    url: &str,
    headers: &[(&str, &str)],
) -> Result<(reqwest::StatusCode, Value), String> {
    let validated = validate_outbound_url(url, OutboundUrlPolicy::StrictPublicHttps).await?;
    let client = build_pinned_http_client(
        &validated,
        Duration::from_secs(12),
        "AiBrainWorX-Threat-Board/0.5 (Local CTI Enrichment)",
    )?;
    let mut req = client
        .get(validated.url.as_str())
        .header("Accept", "application/json");
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| format!("Network request failed: {e}"))?;
    let status = resp.status();
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| format!("Failed reading response body: {e}"))?;
    if bytes.len() > MAX_HTTP_BODY_BYTES {
        return Err("Upstream CTI response exceeded safety limit".to_string());
    }
    let json = serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null);
    Ok((status, json))
}

/// Parses an AlienVault OTX `/api/v1/pulses/subscribed` JSON payload into a bounded `OtxPulseCache`.
pub fn parse_otx_pulses_payload(json: &Value, now: DateTime<Utc>) -> OtxPulseCache {
    let mut cache = OtxPulseCache {
        last_synced_at: Some(now),
        ..OtxPulseCache::default()
    };
    let Some(results) = json.get("results").and_then(Value::as_array) else {
        return cache;
    };

    let mut total_indicators = 0usize;

    for pulse in results.iter().take(MAX_OTX_PULSES_STORED) {
        let id = pulse
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let name = strip_invisible_unicode(
            pulse
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("Untitled Pulse"),
        )
        .trim()
        .chars()
        .take(110)
        .collect::<String>();
        let author = pulse
            .get("author_name")
            .and_then(Value::as_str)
            .unwrap_or("OTX")
            .chars()
            .take(48)
            .collect::<String>();
        let modified = pulse
            .get("modified")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let tags: Vec<String> = pulse
            .get("tags")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .take(5)
                    .map(|t| strip_invisible_unicode(t).chars().take(32).collect())
                    .collect()
            })
            .unwrap_or_default();

        let mut pulse_ind_count = 0usize;
        if let Some(indicators) = pulse.get("indicators").and_then(Value::as_array) {
            for ind in indicators {
                if total_indicators >= MAX_OTX_INDICATORS_TOTAL {
                    break;
                }
                let ind_type = ind
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_ascii_lowercase();
                let raw_val = ind
                    .get("indicator")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim();
                if raw_val.is_empty() || raw_val.len() > 256 {
                    continue;
                }
                let pulse_label = if author.is_empty() {
                    name.clone()
                } else {
                    format!("{name} ({author})")
                };

                let added = match ind_type.as_str() {
                    "ipv4" | "ipv6" => {
                        if let Ok(ip) = raw_val.parse::<IpAddr>() {
                            if !is_non_public_ip(ip) {
                                let entry = cache.ip_pulses.entry(ip.to_string()).or_default();
                                if !entry.contains(&pulse_label) && entry.len() < 5 {
                                    entry.push(pulse_label);
                                }
                                true
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    }
                    "domain" | "hostname" => {
                        let d = raw_val.trim_end_matches('.').to_ascii_lowercase();
                        if d.contains('.') && d.len() <= 253 {
                            let entry = cache.domain_pulses.entry(d).or_default();
                            if !entry.contains(&pulse_label) && entry.len() < 5 {
                                entry.push(pulse_label);
                            }
                            true
                        } else {
                            false
                        }
                    }
                    "url" => {
                        if let Ok(u) = url::Url::parse(raw_val) {
                            if let Some(host) = u.host_str() {
                                let d = host.to_ascii_lowercase();
                                let entry = cache.domain_pulses.entry(d).or_default();
                                if !entry.contains(&pulse_label) && entry.len() < 5 {
                                    entry.push(pulse_label);
                                }
                                true
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    }
                    "filehash-md5" | "filehash-sha1" | "filehash-sha256" => {
                        let h = raw_val.to_ascii_lowercase();
                        if h.chars().all(|c| c.is_ascii_hexdigit()) {
                            let entry = cache.hash_pulses.entry(h).or_default();
                            if !entry.contains(&pulse_label) && entry.len() < 5 {
                                entry.push(pulse_label);
                            }
                            true
                        } else {
                            false
                        }
                    }
                    _ => false,
                };

                if added {
                    pulse_ind_count += 1;
                    total_indicators += 1;
                }
            }
        }

        cache.pulses.push(OtxPulseSummary {
            id,
            name,
            author,
            modified,
            indicator_count: pulse_ind_count,
            tags,
        });
    }

    cache.pulse_count = cache.pulses.len();
    cache.indicator_count = total_indicators;
    cache
}

/// Pulls the user's subscribed OTX Pulses privately down into a local `OtxPulseCache`.
pub async fn sync_otx_subscribed_pulses(api_key: &str) -> Result<(OtxPulseCache, u64), String> {
    let key = api_key.trim();
    if key.is_empty() {
        return Err(
            "AlienVault OTX API key is required (enter in Feeds & Alerts or set OTX_API_KEY)."
                .to_string(),
        );
    }
    let t0 = Instant::now();
    let url = "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=25";
    let (status, json) = pinned_get_json(url, &[("X-OTX-API-KEY", key)]).await?;
    if !status.is_success() {
        let detail = json
            .get("detail")
            .and_then(Value::as_str)
            .unwrap_or("Check API key and OTX account permissions");
        return Err(format!(
            "OTX API returned HTTP {}: {detail}",
            status.as_u16()
        ));
    }
    let cache = parse_otx_pulses_payload(&json, Utc::now());
    Ok((cache, t0.elapsed().as_millis() as u64))
}

pub async fn test_cti_provider(provider: CtiProviderId, api_key: Option<&str>) -> CtiTestResponse {
    let t0 = Instant::now();
    let key = api_key.map(str::trim).filter(|s| !s.is_empty());

    let result: Result<String, String> = match provider {
        CtiProviderId::Otx => {
            let Some(k) = key else {
                return CtiTestResponse {
                    provider,
                    ok: false,
                    latency_ms: 0,
                    message: "OTX API key is required.".to_string(),
                };
            };
            match pinned_get_json(
                "https://otx.alienvault.com/api/v1/user/me",
                &[("X-OTX-API-KEY", k)],
            )
            .await
            {
                Ok((st, j)) if st.is_success() => {
                    let user = j
                        .get("username")
                        .and_then(Value::as_str)
                        .unwrap_or("verified");
                    let subs = j.get("follower_count").and_then(Value::as_u64).unwrap_or(0);
                    Ok(format!(
                        "Authenticated as OTX user '{user}' (followers: {subs})"
                    ))
                }
                Ok((st, _)) => Err(format!(
                    "OTX returned HTTP {} — verify your OTX API key",
                    st.as_u16()
                )),
                Err(e) => Err(e),
            }
        }
        CtiProviderId::Greynoise => {
            let mut hdrs: Vec<(&str, &str)> = Vec::new();
            if let Some(k) = key {
                hdrs.push(("key", k));
            }
            match pinned_get_json("https://api.greynoise.io/v3/community/8.8.8.8", &hdrs).await {
                Ok((st, j)) if st.is_success() || st.as_u16() == 404 => {
                    let detail = j
                        .get("name")
                        .and_then(Value::as_str)
                        .or_else(|| j.get("message").and_then(Value::as_str))
                        .unwrap_or("API reachable");
                    Ok(format!(
                        "GreyNoise Community reachable (8.8.8.8 -> {detail}{})",
                        if key.is_some() {
                            ", API key accepted"
                        } else {
                            ", anonymous tier"
                        }
                    ))
                }
                Ok((st, j)) => {
                    let msg = j
                        .get("message")
                        .and_then(Value::as_str)
                        .unwrap_or("check API key or rate limit");
                    Err(format!("GreyNoise returned HTTP {}: {msg}", st.as_u16()))
                }
                Err(e) => Err(e),
            }
        }
        CtiProviderId::Abuseipdb => {
            let Some(k) = key else {
                return CtiTestResponse {
                    provider,
                    ok: false,
                    latency_ms: 0,
                    message: "AbuseIPDB API key is required.".to_string(),
                };
            };
            match pinned_get_json(
                "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=30",
                &[("Key", k)],
            )
            .await
            {
                Ok((st, j)) if st.is_success() => {
                    let score = j
                        .pointer("/data/abuseConfidenceScore")
                        .and_then(Value::as_u64)
                        .unwrap_or(0);
                    Ok(format!(
                        "AbuseIPDB v2 key verified (8.8.8.8 confidence {score}%)"
                    ))
                }
                Ok((st, _)) => Err(format!(
                    "AbuseIPDB returned HTTP {} — verify your key",
                    st.as_u16()
                )),
                Err(e) => Err(e),
            }
        }
        CtiProviderId::Virustotal => {
            let Some(k) = key else {
                return CtiTestResponse {
                    provider,
                    ok: false,
                    latency_ms: 0,
                    message: "VirusTotal API key is required.".to_string(),
                };
            };
            match pinned_get_json(
                "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
                &[("x-apikey", k)],
            )
            .await
            {
                Ok((st, j)) if st.is_success() => {
                    let harmless = j
                        .pointer("/data/attributes/last_analysis_stats/harmless")
                        .and_then(Value::as_u64)
                        .unwrap_or(0);
                    Ok(format!(
                        "VirusTotal v3 key verified (8.8.8.8 -> {harmless} harmless engines)"
                    ))
                }
                Ok((st, _)) => Err(format!(
                    "VirusTotal returned HTTP {} — verify your key",
                    st.as_u16()
                )),
                Err(e) => Err(e),
            }
        }
    };

    match result {
        Ok(message) => CtiTestResponse {
            provider,
            ok: true,
            latency_ms: t0.elapsed().as_millis() as u64,
            message,
        },
        Err(message) => CtiTestResponse {
            provider,
            ok: false,
            latency_ms: t0.elapsed().as_millis() as u64,
            message,
        },
    }
}

async fn query_otx(ind: &EnrichIndicator, key: &str) -> CtiProviderFinding {
    let t0 = Instant::now();
    let (seg, ref_seg) = match ind {
        EnrichIndicator::Ipv4(_) => ("IPv4", "ip"),
        EnrichIndicator::Ipv6(_) => ("IPv6", "ip"),
        EnrichIndicator::Domain(_) => ("domain", "domain"),
        EnrichIndicator::FileHash(_) => ("file", "file"),
    };
    let val = ind.as_str();
    let url = format!("https://otx.alienvault.com/api/v1/indicators/{seg}/{val}/general");
    let ref_url = format!("https://otx.alienvault.com/indicator/{ref_seg}/{val}");

    match pinned_get_json(&url, &[("X-OTX-API-KEY", key)]).await {
        Ok((st, json)) if st.is_success() => {
            let count = json
                .pointer("/pulse_info/count")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let mut tags = Vec::new();
            let mut pulse_names = Vec::new();
            if let Some(pulses) = json.pointer("/pulse_info/pulses").and_then(Value::as_array) {
                let mut seen_tags = HashSet::new();
                for p in pulses.iter().take(4) {
                    if let Some(n) = p.get("name").and_then(Value::as_str) {
                        pulse_names.push(
                            strip_invisible_unicode(n)
                                .chars()
                                .take(60)
                                .collect::<String>(),
                        );
                    }
                    if let Some(ptags) = p.get("tags").and_then(Value::as_array) {
                        for t in ptags.iter().filter_map(Value::as_str) {
                            let clean = strip_invisible_unicode(t)
                                .chars()
                                .take(28)
                                .collect::<String>();
                            if seen_tags.insert(clean.to_ascii_lowercase()) && tags.len() < 6 {
                                tags.push(clean);
                            }
                        }
                    }
                }
            }
            let country = json
                .get("country_code")
                .and_then(Value::as_str)
                .unwrap_or("");
            let asn = json.get("asn").and_then(Value::as_str).unwrap_or("");
            let verdict = if count >= 3 {
                "MALICIOUS"
            } else if count >= 1 {
                "SUSPICIOUS"
            } else {
                "CLEAN"
            };
            let mut summary = if count > 0 {
                format!(
                    "Found in {count} OTX pulse(s){}",
                    if pulse_names.is_empty() {
                        String::new()
                    } else {
                        format!(": {}", pulse_names.join(" · "))
                    }
                )
            } else {
                "0 OTX threat pulses found for this indicator.".to_string()
            };
            if !country.is_empty() || !asn.is_empty() {
                summary.push_str(&format!(" ({country} {asn})").replace("  ", " "));
            }
            CtiProviderFinding {
                provider: CtiProviderId::Otx,
                provider_name: CtiProviderId::Otx.display_name().to_string(),
                ok: true,
                verdict: verdict.to_string(),
                score: Some((count.min(100)) as u32),
                summary,
                tags,
                reference_url: Some(ref_url),
                latency_ms: t0.elapsed().as_millis() as u64,
                error: None,
            }
        }
        Ok((st, _)) => CtiProviderFinding {
            provider: CtiProviderId::Otx,
            provider_name: CtiProviderId::Otx.display_name().to_string(),
            ok: false,
            verdict: "ERROR".to_string(),
            score: None,
            summary: format!("OTX API returned HTTP {}", st.as_u16()),
            tags: vec![],
            reference_url: Some(ref_url),
            latency_ms: t0.elapsed().as_millis() as u64,
            error: Some(format!("HTTP {}", st.as_u16())),
        },
        Err(e) => CtiProviderFinding {
            provider: CtiProviderId::Otx,
            provider_name: CtiProviderId::Otx.display_name().to_string(),
            ok: false,
            verdict: "ERROR".to_string(),
            score: None,
            summary: "OTX lookup failed".to_string(),
            tags: vec![],
            reference_url: Some(ref_url),
            latency_ms: t0.elapsed().as_millis() as u64,
            error: Some(e),
        },
    }
}

async fn query_greynoise(ind: &EnrichIndicator, key: Option<&str>) -> CtiProviderFinding {
    let t0 = Instant::now();
    let EnrichIndicator::Ipv4(ip) = ind else {
        return CtiProviderFinding {
            provider: CtiProviderId::Greynoise,
            provider_name: CtiProviderId::Greynoise.display_name().to_string(),
            ok: true,
            verdict: "SKIPPED".to_string(),
            score: None,
            summary: "GreyNoise Community supports IPv4 indicators only.".to_string(),
            tags: vec![],
            reference_url: None,
            latency_ms: 0,
            error: None,
        };
    };

    let url = format!("https://api.greynoise.io/v3/community/{ip}");
    let ref_url = format!("https://viz.greynoise.io/ip/{ip}");
    let mut hdrs = Vec::new();
    if let Some(k) = key {
        hdrs.push(("key", k));
    }

    match pinned_get_json(&url, &hdrs).await {
        Ok((st, json)) if st.is_success() || st.as_u16() == 404 => {
            let noise = json.get("noise").and_then(Value::as_bool).unwrap_or(false);
            let riot = json.get("riot").and_then(Value::as_bool).unwrap_or(false);
            let cls = json
                .get("classification")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let name = json
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("Unknown");
            let msg = json.get("message").and_then(Value::as_str).unwrap_or("");

            let verdict = if riot || cls.eq_ignore_ascii_case("benign") {
                "BENIGN"
            } else if cls.eq_ignore_ascii_case("malicious") {
                "MALICIOUS"
            } else if noise {
                "SUSPICIOUS"
            } else {
                "CLEAN"
            };

            let mut tags = Vec::new();
            if riot {
                tags.push("RIOT: Known Benign Service".to_string());
            }
            if noise {
                tags.push("Internet Background Scanner".to_string());
            }
            if cls != "unknown" {
                tags.push(cls.to_ascii_uppercase());
            }
            let summary = if st.as_u16() == 404 || (!noise && !riot) {
                format!(
                    "Not seen scanning the internet (not RIOT / not mass noise){}",
                    if msg.is_empty() {
                        String::new()
                    } else {
                        format!(" — {msg}")
                    }
                )
            } else {
                format!("{name} · classification: {cls} (noise={noise}, riot={riot})")
            };

            CtiProviderFinding {
                provider: CtiProviderId::Greynoise,
                provider_name: CtiProviderId::Greynoise.display_name().to_string(),
                ok: true,
                verdict: verdict.to_string(),
                score: None,
                summary,
                tags,
                reference_url: Some(ref_url),
                latency_ms: t0.elapsed().as_millis() as u64,
                error: None,
            }
        }
        Ok((st, _)) => CtiProviderFinding {
            provider: CtiProviderId::Greynoise,
            provider_name: CtiProviderId::Greynoise.display_name().to_string(),
            ok: false,
            verdict: "ERROR".to_string(),
            score: None,
            summary: format!("GreyNoise returned HTTP {}", st.as_u16()),
            tags: vec![],
            reference_url: Some(ref_url),
            latency_ms: t0.elapsed().as_millis() as u64,
            error: Some(format!("HTTP {}", st.as_u16())),
        },
        Err(e) => CtiProviderFinding {
            provider: CtiProviderId::Greynoise,
            provider_name: CtiProviderId::Greynoise.display_name().to_string(),
            ok: false,
            verdict: "ERROR".to_string(),
            score: None,
            summary: "GreyNoise lookup failed".to_string(),
            tags: vec![],
            reference_url: Some(ref_url),
            latency_ms: t0.elapsed().as_millis() as u64,
            error: Some(e),
        },
    }
}

async fn query_abuseipdb(ind: &EnrichIndicator, key: &str) -> CtiProviderFinding {
    let t0 = Instant::now();
    let ip = match ind {
        EnrichIndicator::Ipv4(s) | EnrichIndicator::Ipv6(s) => s,
        _ => {
            return CtiProviderFinding {
                provider: CtiProviderId::Abuseipdb,
                provider_name: CtiProviderId::Abuseipdb.display_name().to_string(),
                ok: true,
                verdict: "SKIPPED".to_string(),
                score: None,
                summary: "AbuseIPDB supports IPv4/IPv6 indicators only.".to_string(),
                tags: vec![],
                reference_url: None,
                latency_ms: 0,
                error: None,
            };
        }
    };

    let url = format!("https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90");
    let ref_url = format!("https://www.abuseipdb.com/check/{ip}");

    match pinned_get_json(&url, &[("Key", key)]).await {
        Ok((st, json)) if st.is_success() => {
            let score = json
                .pointer("/data/abuseConfidenceScore")
                .and_then(Value::as_u64)
                .unwrap_or(0) as u32;
            let reports = json
                .pointer("/data/totalReports")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let isp = json
                .pointer("/data/isp")
                .and_then(Value::as_str)
                .unwrap_or("Unknown ISP");
            let cc = json
                .pointer("/data/countryCode")
                .and_then(Value::as_str)
                .unwrap_or("--");
            let is_tor = json
                .pointer("/data/isTor")
                .and_then(Value::as_bool)
                .unwrap_or(false);

            let verdict = if score >= 50 {
                "MALICIOUS"
            } else if score >= 15 || reports >= 5 {
                "SUSPICIOUS"
            } else {
                "CLEAN"
            };
            let mut tags = vec![format!("Confidence {score}%"), format!("{reports} reports")];
            if is_tor {
                tags.push("Tor Exit".to_string());
            }

            CtiProviderFinding {
                provider: CtiProviderId::Abuseipdb,
                provider_name: CtiProviderId::Abuseipdb.display_name().to_string(),
                ok: true,
                verdict: verdict.to_string(),
                score: Some(score),
                summary: format!(
                    "Abuse Confidence {score}% across {reports} report(s) · {isp} ({cc})"
                ),
                tags,
                reference_url: Some(ref_url),
                latency_ms: t0.elapsed().as_millis() as u64,
                error: None,
            }
        }
        Ok((st, _)) => CtiProviderFinding {
            provider: CtiProviderId::Abuseipdb,
            provider_name: CtiProviderId::Abuseipdb.display_name().to_string(),
            ok: false,
            verdict: "ERROR".to_string(),
            score: None,
            summary: format!("AbuseIPDB returned HTTP {}", st.as_u16()),
            tags: vec![],
            reference_url: Some(ref_url),
            latency_ms: t0.elapsed().as_millis() as u64,
            error: Some(format!("HTTP {}", st.as_u16())),
        },
        Err(e) => CtiProviderFinding {
            provider: CtiProviderId::Abuseipdb,
            provider_name: CtiProviderId::Abuseipdb.display_name().to_string(),
            ok: false,
            verdict: "ERROR".to_string(),
            score: None,
            summary: "AbuseIPDB lookup failed".to_string(),
            tags: vec![],
            reference_url: Some(ref_url),
            latency_ms: t0.elapsed().as_millis() as u64,
            error: Some(e),
        },
    }
}

async fn query_virustotal(ind: &EnrichIndicator, key: &str) -> CtiProviderFinding {
    let t0 = Instant::now();
    let (seg, gui_seg) = match ind {
        EnrichIndicator::Ipv4(_) | EnrichIndicator::Ipv6(_) => ("ip_addresses", "ip-address"),
        EnrichIndicator::Domain(_) => ("domains", "domain"),
        EnrichIndicator::FileHash(_) => ("files", "file"),
    };
    let val = ind.as_str();
    let url = format!("https://www.virustotal.com/api/v3/{seg}/{val}");
    let ref_url = format!("https://www.virustotal.com/gui/{gui_seg}/{val}");

    match pinned_get_json(&url, &[("x-apikey", key)]).await {
        Ok((st, json)) if st.is_success() => {
            let mal = json
                .pointer("/data/attributes/last_analysis_stats/malicious")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let susp = json
                .pointer("/data/attributes/last_analysis_stats/suspicious")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let harmless = json
                .pointer("/data/attributes/last_analysis_stats/harmless")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let rep = json
                .pointer("/data/attributes/reputation")
                .and_then(Value::as_i64)
                .unwrap_or(0);

            let verdict = if mal >= 2 {
                "MALICIOUS"
            } else if mal == 1 || susp >= 2 {
                "SUSPICIOUS"
            } else {
                "CLEAN"
            };
            CtiProviderFinding {
                provider: CtiProviderId::Virustotal,
                provider_name: CtiProviderId::Virustotal.display_name().to_string(),
                ok: true,
                verdict: verdict.to_string(),
                score: Some((mal.min(100)) as u32),
                summary: format!(
                    "{mal} malicious · {susp} suspicious · {harmless} harmless engines (reputation: {rep})"
                ),
                tags: vec![
                    format!("{mal} malicious"),
                    format!("{susp} suspicious"),
                    format!("rep {rep}"),
                ],
                reference_url: Some(ref_url),
                latency_ms: t0.elapsed().as_millis() as u64,
                error: None,
            }
        }
        Ok((st, _)) if st.as_u16() == 404 => CtiProviderFinding {
            provider: CtiProviderId::Virustotal,
            provider_name: CtiProviderId::Virustotal.display_name().to_string(),
            ok: true,
            verdict: "CLEAN".to_string(),
            score: Some(0),
            summary: "Indicator not present in VirusTotal database.".to_string(),
            tags: vec![],
            reference_url: Some(ref_url),
            latency_ms: t0.elapsed().as_millis() as u64,
            error: None,
        },
        Ok((st, _)) => CtiProviderFinding {
            provider: CtiProviderId::Virustotal,
            provider_name: CtiProviderId::Virustotal.display_name().to_string(),
            ok: false,
            verdict: "ERROR".to_string(),
            score: None,
            summary: format!("VirusTotal returned HTTP {}", st.as_u16()),
            tags: vec![],
            reference_url: Some(ref_url),
            latency_ms: t0.elapsed().as_millis() as u64,
            error: Some(format!("HTTP {}", st.as_u16())),
        },
        Err(e) => CtiProviderFinding {
            provider: CtiProviderId::Virustotal,
            provider_name: CtiProviderId::Virustotal.display_name().to_string(),
            ok: false,
            verdict: "ERROR".to_string(),
            score: None,
            summary: "VirusTotal lookup failed".to_string(),
            tags: vec![],
            reference_url: Some(ref_url),
            latency_ms: t0.elapsed().as_millis() as u64,
            error: Some(e),
        },
    }
}

pub fn aggregate_verdict(findings: &[CtiProviderFinding]) -> String {
    if findings.iter().any(|f| f.verdict == "MALICIOUS") {
        "MALICIOUS".to_string()
    } else if findings.iter().any(|f| f.verdict == "SUSPICIOUS") {
        "SUSPICIOUS".to_string()
    } else if findings.iter().any(|f| f.verdict == "BENIGN") {
        "BENIGN / NOISE".to_string()
    } else {
        "CLEAN / UNKNOWN".to_string()
    }
}

/// Runs explicit on-demand enrichment concurrently across all enabled BYO CTI providers.
pub async fn enrich_indicator(
    raw_indicator: &str,
    cfg: &CtiConfig,
) -> Result<CtiEnrichmentResponse, String> {
    let ind = classify_and_validate_indicator(raw_indicator)?;

    let otx_key = if cfg.otx_enabled {
        effective_cti_key(cfg, CtiProviderId::Otx)
    } else {
        None
    };
    let gn_enabled = cfg.greynoise_enabled;
    let gn_key = effective_cti_key(cfg, CtiProviderId::Greynoise);
    let abuse_key = if cfg.abuseipdb_enabled {
        effective_cti_key(cfg, CtiProviderId::Abuseipdb)
    } else {
        None
    };
    let vt_key = if cfg.virustotal_enabled {
        effective_cti_key(cfg, CtiProviderId::Virustotal)
    } else {
        None
    };

    if otx_key.is_none() && !gn_enabled && abuse_key.is_none() && vt_key.is_none() {
        return Err(
            "No BYO CTI enrichment providers are enabled yet. Enable AlienVault OTX, GreyNoise, AbuseIPDB, or VirusTotal under Feeds & Alerts → BYO CTI Enrichment."
                .to_string(),
        );
    }

    let (otx_res, gn_res, abuse_res, vt_res) = tokio::join!(
        async {
            match otx_key.as_deref() {
                Some(k) => Some(query_otx(&ind, k).await),
                None => None,
            }
        },
        async {
            if gn_enabled {
                Some(query_greynoise(&ind, gn_key.as_deref()).await)
            } else {
                None
            }
        },
        async {
            match abuse_key.as_deref() {
                Some(k) => Some(query_abuseipdb(&ind, k).await),
                None => None,
            }
        },
        async {
            match vt_key.as_deref() {
                Some(k) => Some(query_virustotal(&ind, k).await),
                None => None,
            }
        },
    );

    let mut findings = Vec::new();
    for item in [otx_res, gn_res, abuse_res, vt_res].into_iter().flatten() {
        findings.push(item);
    }

    let overall_verdict = aggregate_verdict(&findings);
    Ok(CtiEnrichmentResponse {
        indicator: ind.as_str().to_string(),
        indicator_type: ind.kind_str().to_string(),
        overall_verdict,
        enriched_at: Utc::now(),
        cached: false,
        findings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn privacy_guard_blocks_rfc1918_loopback_and_internal_domains() {
        assert!(classify_and_validate_indicator("10.0.0.15").is_err());
        assert!(classify_and_validate_indicator("192.168.1.42").is_err());
        assert!(classify_and_validate_indicator("172.16.5.9").is_err());
        assert!(classify_and_validate_indicator("127.0.0.1").is_err());
        assert!(classify_and_validate_indicator("169.254.169.254").is_err());
        assert!(classify_and_validate_indicator("fileserver.corp.local").is_err());
        assert!(classify_and_validate_indicator("db.prod.internal").is_err());
    }

    #[test]
    fn classifies_public_ip_defanged_domain_url_and_hashes() {
        assert_eq!(
            classify_and_validate_indicator("198.51.100[.]42").unwrap(),
            EnrichIndicator::Ipv4("198.51.100.42".to_string())
        );
        assert_eq!(
            classify_and_validate_indicator("hxxps://evil[.]example.com/gate").unwrap(),
            EnrichIndicator::Domain("evil.example.com".to_string())
        );
        let sha256 = "a".repeat(64);
        assert_eq!(
            classify_and_validate_indicator(&sha256).unwrap(),
            EnrichIndicator::FileHash(sha256)
        );
    }

    #[test]
    fn cti_config_never_serializes_api_keys() {
        let cfg = CtiConfig {
            otx_enabled: true,
            otx_sync_pulses: true,
            otx_api_key: "SUPER_SECRET_OTX_KEY".to_string(),
            greynoise_api_key: "SUPER_SECRET_GN_KEY".to_string(),
            abuseipdb_api_key: "SUPER_SECRET_ABUSE_KEY".to_string(),
            virustotal_api_key: "SUPER_SECRET_VT_KEY".to_string(),
            ..CtiConfig::default()
        };
        let serialized = serde_json::to_string(&cfg).expect("serialize");
        assert!(!serialized.contains("SUPER_SECRET"));
    }

    #[test]
    fn parses_otx_pulses_and_indexes_public_indicators_only() {
        let payload = json!({
            "results": [
                {
                    "id": "pulse-1",
                    "name": "LummaStealer C2 Wave",
                    "author_name": "AlienVault",
                    "modified": "2026-11-22T12:00:00Z",
                    "tags": ["lumma", "infostealer"],
                    "indicators": [
                        { "type": "IPv4", "indicator": "198.51.100.42" },
                        { "type": "IPv4", "indicator": "10.0.0.5" },
                        { "type": "domain", "indicator": "c2-drop.example.invalid" },
                        { "type": "FileHash-SHA256", "indicator": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
                    ]
                }
            ]
        });
        let cache = parse_otx_pulses_payload(&payload, Utc::now());
        assert_eq!(cache.pulse_count, 1);
        assert_eq!(cache.indicator_count, 3);
        assert!(cache.ip_pulses.contains_key("198.51.100.42"));
        assert!(!cache.ip_pulses.contains_key("10.0.0.5"));
        assert!(cache.domain_pulses.contains_key("c2-drop.example.invalid"));
        assert!(cache
            .hash_pulses
            .contains_key("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    }

    #[test]
    fn aggregates_verdicts_by_highest_severity() {
        let make = |v: &str| CtiProviderFinding {
            provider: CtiProviderId::Otx,
            provider_name: "OTX".to_string(),
            ok: true,
            verdict: v.to_string(),
            score: None,
            summary: String::new(),
            tags: vec![],
            reference_url: None,
            latency_ms: 10,
            error: None,
        };
        assert_eq!(
            aggregate_verdict(&[make("CLEAN"), make("BENIGN")]),
            "BENIGN / NOISE"
        );
        assert_eq!(
            aggregate_verdict(&[make("BENIGN"), make("SUSPICIOUS")]),
            "SUSPICIOUS"
        );
        assert_eq!(
            aggregate_verdict(&[make("SUSPICIOUS"), make("MALICIOUS")]),
            "MALICIOUS"
        );
    }
}
