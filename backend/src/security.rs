use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use axum::http::{header, HeaderMap};
use regex::{Captures, Regex};
use tokio::net::lookup_host;
use url::{Host, Url};

pub const KEYCHAIN_SERVICE: &str = "aibrainworx-threat-board";
pub const KEYCHAIN_ACCOUNT_AI_API_KEY: &str = "ai_provider_api_key";
pub const KEYCHAIN_ACCOUNT_DB_VAULT_KEY: &str = "db_vault_key_v1";
pub const SESSION_COOKIE_NAME: &str = "abw_session";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundUrlPolicy {
    /// Strict external public HTTPS only (webhooks, custom threat feeds).
    /// Blocks loopback, RFC1918, ULA, CGNAT, link-local, metadata, and non-HTTPS.
    StrictPublicHttps,
    /// AI provider endpoint policy: HTTPS or loopback HTTP always allowed;
    /// private LAN IPs allowed only when `allow_lan` is true; link-local &
    /// cloud metadata (`169.254.0.0/16`, `fe80::/10`, `100.100.100.200`) always blocked.
    AiProvider { allow_lan: bool },
}

#[derive(Debug, Clone)]
pub struct ValidatedUrl {
    pub url: Url,
    pub host: String,
    pub resolved_addrs: Vec<SocketAddr>,
}

/// Checks whether a single IP address is permitted under `policy`.
/// Handles IPv4-mapped IPv6 (`::ffff:x.x.x.x`) by unwrapping to IPv4 first so
/// mapped loopback/metadata addresses cannot bypass SSRF validation.
pub fn is_ip_allowed(ip: IpAddr, policy: OutboundUrlPolicy) -> bool {
    let normalized = match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        other => other,
    };

    match normalized {
        IpAddr::V4(v4) => is_ipv4_allowed(v4, policy),
        IpAddr::V6(v6) => is_ipv6_allowed(v6, policy),
    }
}

fn is_ipv4_allowed(v4: Ipv4Addr, policy: OutboundUrlPolicy) -> bool {
    let octets = v4.octets();
    let is_cgnat = octets[0] == 100 && (64..=127).contains(&octets[1]);
    let is_benchmark = octets[0] == 198 && (18..=19).contains(&octets[1]);
    let is_this_network = octets[0] == 0;
    let is_ietf_protocol = octets[0] == 192 && octets[1] == 0 && octets[2] == 0;
    let is_class_e = octets[0] >= 240;
    let is_reserved_or_non_public = v4.is_unspecified()
        || v4.is_multicast()
        || v4.is_broadcast()
        || v4.is_link_local()
        || v4.is_documentation()
        || is_this_network
        || is_ietf_protocol
        || is_class_e;

    if is_reserved_or_non_public {
        return false;
    }

    // Explicitly block known cloud metadata IP even in CGNAT range (Alibaba Cloud)
    if v4 == Ipv4Addr::new(100, 100, 100, 200) {
        return false;
    }

    match policy {
        OutboundUrlPolicy::StrictPublicHttps => {
            !(v4.is_loopback() || v4.is_private() || is_cgnat || is_benchmark)
        }
        OutboundUrlPolicy::AiProvider { allow_lan } => {
            if v4.is_loopback() {
                return true;
            }
            if v4.is_private() || is_cgnat || is_benchmark {
                return allow_lan;
            }
            true
        }
    }
}

fn is_ipv6_allowed(v6: Ipv6Addr, policy: OutboundUrlPolicy) -> bool {
    let seg = v6.segments();
    let is_link_local = (seg[0] & 0xffc0) == 0xfe80;
    let is_site_local = (seg[0] & 0xffc0) == 0xfec0;
    let is_ula = (seg[0] & 0xfe00) == 0xfc00;
    let is_doc = seg[0] == 0x2001 && seg[1] == 0x0db8;
    // IPv6 transition & special-use ranges that can encapsulate/translate private IPv4 targets
    let is_nat64_well_known = seg[0] == 0x0064
        && seg[1] == 0xff9b
        && seg[2] == 0
        && seg[3] == 0
        && seg[4] == 0
        && seg[5] == 0;
    let is_nat64_local = seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2] == 0x0001;
    let is_6to4 = seg[0] == 0x2002;
    let is_teredo = seg[0] == 0x2001 && seg[1] == 0x0000;
    let is_ipv4_compatible = seg[0] == 0
        && seg[1] == 0
        && seg[2] == 0
        && seg[3] == 0
        && seg[4] == 0
        && seg[5] == 0
        && !v6.is_unspecified()
        && !v6.is_loopback();
    let is_ipv4_translated =
        seg[0] == 0 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0 && seg[4] == 0xffff && seg[5] == 0;
    let is_discard = seg[0] == 0x0100 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0;
    let is_benchmark = seg[0] == 0x2001 && seg[1] == 0x0002 && seg[2] == 0;
    let is_orchid =
        seg[0] == 0x2001 && ((seg[1] & 0xfff0) == 0x0010 || (seg[1] & 0xffe0) == 0x0020);

    if v6.is_unspecified()
        || v6.is_multicast()
        || is_link_local
        || is_site_local
        || is_doc
        || is_nat64_well_known
        || is_nat64_local
        || is_6to4
        || is_teredo
        || is_ipv4_compatible
        || is_ipv4_translated
        || is_discard
        || is_benchmark
        || is_orchid
    {
        return false;
    }

    match policy {
        OutboundUrlPolicy::StrictPublicHttps => !(v6.is_loopback() || is_ula),
        OutboundUrlPolicy::AiProvider { allow_lan } => {
            if v6.is_loopback() {
                return true;
            }
            if is_ula {
                return allow_lan;
            }
            true
        }
    }
}

fn is_blocked_hostname(host_lower: &str, policy: OutboundUrlPolicy) -> bool {
    let is_metadata_domain = host_lower == "metadata.google.internal"
        || host_lower.ends_with(".metadata.google.internal")
        || host_lower == "metadata"
        || host_lower == "instance-data";
    if is_metadata_domain {
        return true;
    }

    match policy {
        OutboundUrlPolicy::StrictPublicHttps => {
            host_lower == "localhost"
                || host_lower.ends_with(".localhost")
                || host_lower.ends_with(".local")
                || host_lower.ends_with(".internal")
        }
        OutboundUrlPolicy::AiProvider { allow_lan } => {
            if host_lower == "localhost" || host_lower.ends_with(".localhost") {
                return false;
            }
            if !allow_lan && (host_lower.ends_with(".local") || host_lower.ends_with(".internal")) {
                return true;
            }
            false
        }
    }
}

/// Validates URL syntax, scheme, hostname rules, AND resolves DNS to ensure every
/// returned IP complies with `policy` before any network connection occurs.
pub async fn validate_outbound_url(
    raw: &str,
    policy: OutboundUrlPolicy,
) -> Result<ValidatedUrl, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("URL cannot be empty".into());
    }
    if trimmed.len() > 2048 {
        return Err("URL exceeds maximum length (2048 chars)".into());
    }

    let mut parsed = Url::parse(trimmed).map_err(|e| format!("Invalid URL: {e}"))?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("URL credentials (user:pass@host) are not permitted".into());
    }

    let scheme = parsed.scheme().to_string();
    let raw_host = parsed
        .host_str()
        .ok_or_else(|| "URL must contain a valid hostname".to_string())?
        .to_string();
    let host_str = raw_host.trim_end_matches('.').to_string();
    if host_str.is_empty() || host_str.contains("..") {
        return Err("URL contains an empty or malformed hostname".into());
    }
    // Canonicalize trailing-dot FQDNs (e.g. `https://example.com./hook` -> `https://example.com/hook`)
    // directly inside `parsed` so reqwest's lookup key ALWAYS matches `resolve_to_addrs(&validated.host, ...)`,
    // eliminating trailing-dot DNS-rebinding TOCTOU mismatches.
    if matches!(parsed.host(), Some(Host::Domain(_))) && raw_host != host_str {
        parsed
            .set_host(Some(&host_str))
            .map_err(|_| format!("Invalid canonical hostname: {host_str}"))?;
    }
    let host_lower = host_str.to_ascii_lowercase();

    match policy {
        OutboundUrlPolicy::StrictPublicHttps => {
            if scheme != "https" {
                return Err("Only HTTPS URLs are permitted for external feeds and webhooks".into());
            }
        }
        OutboundUrlPolicy::AiProvider { allow_lan } => {
            if scheme != "https" && scheme != "http" {
                return Err("Only HTTP or HTTPS URLs are supported".into());
            }
            if scheme == "http" {
                let is_local_name = host_lower == "localhost" || host_lower.ends_with(".localhost");
                let is_allowed_literal = match parsed.host() {
                    Some(Host::Ipv4(v4)) => is_loopback_or_lan_ip(IpAddr::V4(v4), allow_lan),
                    Some(Host::Ipv6(v6)) => is_loopback_or_lan_ip(IpAddr::V6(v6), allow_lan),
                    _ => is_local_name || allow_lan,
                };
                if !is_allowed_literal {
                    return Err(
                        "Plaintext HTTP is only permitted for loopback (localhost/127.0.0.1) or explicit LAN endpoints; use HTTPS for public hosts".into()
                    );
                }
            }
        }
    }

    if is_blocked_hostname(&host_lower, policy) {
        return Err(format!("Blocked internal or metadata hostname: {host_str}"));
    }

    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| "Unable to determine target port".to_string())?;

    // Handle literal IPs directly without DNS lookup; resolve domain names and check every IP.
    let resolved_addrs: Vec<SocketAddr> = match parsed.host() {
        Some(Host::Ipv4(v4)) => {
            let ip = IpAddr::V4(v4);
            if !is_ip_allowed(ip, policy) {
                return Err(format!("Blocked non-permitted IP address: {ip}"));
            }
            vec![SocketAddr::new(ip, port)]
        }
        Some(Host::Ipv6(v6)) => {
            let ip = IpAddr::V6(v6);
            if !is_ip_allowed(ip, policy) {
                return Err(format!("Blocked non-permitted IPv6 address: {ip}"));
            }
            vec![SocketAddr::new(ip, port)]
        }
        Some(Host::Domain(_)) => {
            let lookup = tokio::time::timeout(
                Duration::from_secs(5),
                lookup_host((host_str.as_str(), port)),
            )
            .await
            .map_err(|_| format!("DNS lookup timed out for {host_str}"))?
            .map_err(|e| format!("DNS resolution failed for {host_str}: {e}"))?;

            let addrs: Vec<SocketAddr> = lookup.collect();
            if addrs.is_empty() {
                return Err(format!("DNS returned no addresses for {host_str}"));
            }
            for addr in &addrs {
                if !is_ip_allowed(addr.ip(), policy) {
                    return Err(format!(
                        "Resolved IP {} for {host_str} violates outbound SSRF policy",
                        addr.ip()
                    ));
                }
                if let OutboundUrlPolicy::AiProvider { allow_lan } = policy {
                    if scheme == "http" && !is_loopback_or_lan_ip(addr.ip(), allow_lan) {
                        return Err(format!(
                            "Plaintext HTTP to resolved public IP {} for {host_str} is blocked; use HTTPS",
                            addr.ip()
                        ));
                    }
                }
            }
            addrs
        }
        None => return Err("URL missing host".into()),
    };

    Ok(ValidatedUrl {
        url: parsed,
        host: host_str,
        resolved_addrs,
    })
}

fn is_loopback_or_lan_ip(ip: IpAddr, allow_lan: bool) -> bool {
    let normalized = match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        other => other,
    };
    match normalized {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            let is_cgnat = o[0] == 100
                && (64..=127).contains(&o[1])
                && v4 != Ipv4Addr::new(100, 100, 100, 200);
            let is_benchmark = o[0] == 198 && (18..=19).contains(&o[1]);
            v4.is_loopback() || (allow_lan && (v4.is_private() || is_cgnat || is_benchmark))
        }
        IpAddr::V6(v6) => {
            let is_ula = (v6.segments()[0] & 0xfe00) == 0xfc00;
            v6.is_loopback() || (allow_lan && is_ula)
        }
    }
}

/// Builds a no-redirect, no-proxy reqwest Client pinned to the DNS-validated socket addresses
/// so remote 302 redirects, proxy env vars, or DNS rebinding cannot bypass SSRF validation.
pub fn build_pinned_http_client(
    validated: &ValidatedUrl,
    timeout: Duration,
    user_agent: &str,
) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder()
        .connect_timeout(timeout.min(Duration::from_secs(10)))
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .gzip(true)
        .deflate(true)
        .user_agent(user_agent);

    if matches!(validated.url.host(), Some(Host::Domain(_))) && !validated.resolved_addrs.is_empty()
    {
        builder = builder.resolve_to_addrs(&validated.host, &validated.resolved_addrs);
    }

    builder
        .build()
        .map_err(|e| format!("Failed to construct pinned HTTP client: {e}"))
}

/// Performs an outbound HTTPS GET request validating SSRF policy + DNS pinning on every
/// redirect hop (up to `max_redirects`) so compromised feeds/mirrors cannot redirect to
/// loopback, RFC1918, ULA, or cloud metadata addresses.
pub async fn send_ssrf_safe_get(
    url: &str,
    timeout: Duration,
    user_agent: &str,
    accept: Option<&str>,
    max_redirects: usize,
) -> Result<reqwest::Response, String> {
    let mut current_url = url.to_string();

    for hop in 0..=max_redirects {
        let validated =
            validate_outbound_url(&current_url, OutboundUrlPolicy::StrictPublicHttps).await?;
        let client = build_pinned_http_client(&validated, timeout, user_agent)?;
        let mut req = client.get(validated.url.clone());
        if let Some(acc) = accept {
            req = req.header("Accept", acc);
        }

        let resp = tokio::time::timeout(timeout, req.send())
            .await
            .map_err(|_| "Request timeout".to_string())?
            .map_err(|e| e.without_url().to_string())?;

        if resp.status().is_redirection() {
            if hop >= max_redirects {
                return Err(format!(
                    "Redirect limit exceeded ({max_redirects} hops) while fetching feed"
                ));
            }
            let loc = resp
                .headers()
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "Redirect response missing Location header".to_string())?;
            let next_url = validated
                .url
                .join(loc)
                .map_err(|e| format!("Invalid redirect Location URL: {e}"))?;
            current_url = next_url.to_string();
            continue;
        }

        return Ok(resp);
    }

    Err("Redirect limit exceeded".to_string())
}

/// Performs an outbound DNS-pinned, zero-redirect HTTPS POST with a JSON body.
pub async fn send_ssrf_safe_post_json(
    url: &str,
    timeout: Duration,
    user_agent: &str,
    body: &serde_json::Value,
) -> Result<reqwest::Response, String> {
    let validated = validate_outbound_url(url, OutboundUrlPolicy::StrictPublicHttps).await?;
    let client = build_pinned_http_client(&validated, timeout, user_agent)?;
    tokio::time::timeout(timeout, client.post(validated.url).json(body).send())
        .await
        .map_err(|_| "Request timeout".to_string())?
        .map_err(|e| e.without_url().to_string())
}

/// Strips invisible control characters, bidi overrides, zero-width spaces,
/// and Unicode Tag characters (U+E0000..=U+E007F) used to smuggle hidden prompts.
pub fn strip_invisible_unicode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        let cp = ch as u32;
        let is_safe_ws = matches!(ch, '\n' | '\r' | '\t');
        let is_c0 = cp < 0x20 && !is_safe_ws;
        let is_c1 = (0x7f..=0x9f).contains(&cp);
        let is_zero_width = (0x200b..=0x200f).contains(&cp)
            || (0x202a..=0x202e).contains(&cp)
            || (0x2060..=0x2069).contains(&cp)
            || cp == 0x061c
            || cp == 0xfeff;
        let is_tag_block = (0xe0000..=0xe007f).contains(&cp);

        if !(is_c0 || is_c1 || is_zero_width || is_tag_block) {
            out.push(ch);
        }
    }
    out
}

fn is_safe_markdown_link_target(raw_target: &str) -> bool {
    let first_token = raw_target.split_whitespace().next().unwrap_or("");
    let unwrapped = first_token
        .strip_prefix('<')
        .and_then(|s| s.strip_suffix('>'))
        .unwrap_or(first_token)
        .trim();
    if unwrapped.is_empty() {
        return false;
    }
    let lower = unwrapped.to_ascii_lowercase();
    // Reject HTML entities or protocol-relative URLs that can disguise dangerous schemes
    if lower.contains("&#") || lower.contains("&colon;") || lower.starts_with("//") {
        return false;
    }
    lower.starts_with("https://")
        || lower.starts_with("http://")
        || lower.starts_with('#')
        || lower.starts_with('/')
}

/// Sanitizes LLM-returned Markdown before storage or rendering:
/// - Strips invisible Unicode / bidi spoofing
/// - Blocks inline AND reference-style Markdown tracking images (`![alt](url)`, `![alt][ref]`)
/// - Neutralizes dangerous link schemes (`javascript:`, `data:`, `file:`, `vbscript:`, entity-encoded)
///   across inline links, angle-bracket links, and reference-style link definitions
/// - Strips `<script>`/`<style>`/`<iframe>`/`<object>`/`<embed>`/`<svg>` blocks AND all raw HTML tags
pub fn sanitize_llm_markdown(md: &str) -> String {
    static RE_SCRIPT_BLOCK: OnceLock<Regex> = OnceLock::new();
    static RE_ANY_HTML_TAG: OnceLock<Regex> = OnceLock::new();
    static RE_MD_IMAGE_INLINE: OnceLock<Regex> = OnceLock::new();
    static RE_MD_IMAGE_REF: OnceLock<Regex> = OnceLock::new();
    static RE_MD_LINK_INLINE: OnceLock<Regex> = OnceLock::new();
    static RE_MD_REF_DEF: OnceLock<Regex> = OnceLock::new();

    let clean_unicode = strip_invisible_unicode(md);

    let re_script = RE_SCRIPT_BLOCK.get_or_init(|| {
        Regex::new(r"(?is)<script\b[^>]*>.*?</script>|<style\b[^>]*>.*?</style>|<iframe\b[^>]*>.*?</iframe>|<object\b[^>]*>.*?</object>|<embed\b[^>]*>.*?</embed>|<svg\b[^>]*>.*?</svg>")
            .expect("valid regex")
    });
    let no_scripts = re_script.replace_all(&clean_unicode, "");

    // Strip all raw HTML tags (e.g. <details open ontoggle=...>, <img ...>, <marquee>, etc.)
    // while preserving prose comparisons like `a < 5` or `version <= 2.4`.
    let re_html_tag = RE_ANY_HTML_TAG.get_or_init(|| {
        Regex::new(r"(?i)</?[a-z][a-z0-9:-]*(?:\s+[^<>]*)?/?>").expect("valid regex")
    });
    let no_html_tags = re_html_tag.replace_all(&no_scripts, "");

    // Remove inline Markdown image embeds to stop exfiltration/tracking pixels.
    let re_img = RE_MD_IMAGE_INLINE.get_or_init(|| {
        Regex::new(r"!\[([^\]]*)\]\(([^)\s]+(?:\s+[^)]*)?)\)").expect("valid regex")
    });
    let no_inline_imgs = re_img.replace_all(&no_html_tags, |caps: &Captures| {
        let alt = caps.get(1).map(|m| m.as_str().trim()).unwrap_or("");
        if alt.is_empty() {
            "[external image blocked]".to_string()
        } else {
            format!("[image blocked: {alt}]")
        }
    });

    // Also block reference-style Markdown images (`![alt][ref]` and `![alt][]`).
    let re_ref_img = RE_MD_IMAGE_REF
        .get_or_init(|| Regex::new(r"!\[([^\]]*)\]\[[^\]]*\]").expect("valid regex"));
    let no_imgs = re_ref_img.replace_all(&no_inline_imgs, |caps: &Captures| {
        let alt = caps.get(1).map(|m| m.as_str().trim()).unwrap_or("");
        if alt.is_empty() {
            "[external image blocked]".to_string()
        } else {
            format!("[image blocked: {alt}]")
        }
    });

    // Only keep safe http/https/relative inline links; neutralize javascript:, data:, file:, etc.
    let re_link = RE_MD_LINK_INLINE
        .get_or_init(|| Regex::new(r"\[([^\]]+)\]\(([^)]+)\)").expect("valid regex"));
    let safe_inline_links = re_link.replace_all(&no_imgs, |caps: &Captures| {
        let label = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let target = caps.get(2).map(|m| m.as_str().trim()).unwrap_or("");
        if is_safe_markdown_link_target(target) {
            format!("[{label}]({target})")
        } else {
            format!("{label} (unsafe-link-removed)")
        }
    });

    // Sanitize reference-style link definitions (`[1]: javascript:alert(1)`).
    let re_ref_def = RE_MD_REF_DEF.get_or_init(|| {
        Regex::new(r"(?m)^[ \t]{0,3}\[([^\]]+)\]:[ \t]*(\S+)(.*)$").expect("valid regex")
    });
    let safe_links = re_ref_def.replace_all(&safe_inline_links, |caps: &Captures| {
        let id = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let target = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        let rest = caps.get(3).map(|m| m.as_str()).unwrap_or("");
        if is_safe_markdown_link_target(target) {
            format!("[{id}]: {target}{rest}")
        } else {
            format!("[{id}]: #unsafe-link-removed")
        }
    });

    safe_links.into_owned()
}

/// Defangs an IPv4 or IPv6 indicator for safe copy/paste sharing.
#[allow(dead_code)]
pub fn defang_ip(ip: &str) -> String {
    let trimmed = ip.trim();
    if trimmed.contains(':') {
        trimmed.replace(':', "[:]")
    } else if let Some(last_dot) = trimmed.rfind('.') {
        format!("{}[.]{}", &trimmed[..last_dot], &trimmed[last_dot + 1..])
    } else {
        trimmed.replace('.', "[.]")
    }
}

/// Defangs an HTTP/HTTPS URL into non-clickable `hxxp://` / `hxxps://` + `[.]` host.
#[allow(dead_code)]
pub fn defang_url(raw_url: &str) -> String {
    let trimmed = raw_url.trim();
    let lower = trimmed.to_ascii_lowercase();
    let (prefix, rest) = if lower.starts_with("https://") {
        ("hxxps://", &trimmed[8..])
    } else if lower.starts_with("http://") {
        ("hxxp://", &trimmed[7..])
    } else {
        ("", trimmed)
    };

    match rest.find('/') {
        Some(idx) => {
            let host = rest[..idx].replace('.', "[.]");
            format!("{prefix}{host}{}", &rest[idx..])
        }
        None => format!("{prefix}{}", rest.replace('.', "[.]")),
    }
}

/// Redacts tail octets/hextets of an IP address for OPSEC/stream-safe mode.
#[allow(dead_code)]
pub fn redact_ip(ip: &str) -> String {
    let trimmed = ip.trim();
    if let Ok(parsed) = trimmed.parse::<IpAddr>() {
        match parsed {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                format!("{}.{}.xxx.xxx", o[0], o[1])
            }
            IpAddr::V6(v6) => {
                let s = v6.segments();
                format!("{:x}:{:x}:xxxx::xxxx", s[0], s[1])
            }
        }
    } else {
        "[REDACTED-IP]".to_string()
    }
}

/// Saves a secret into the OS native Keychain (Windows Credential Manager,
/// macOS Keychain, or Linux Secret Service).
pub fn keychain_set(account: &str, secret: &str) -> Result<(), String> {
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, account)
        .map_err(|e| format!("Keychain entry error: {e}"))?;
    entry
        .set_password(secret)
        .map_err(|e| format!("Failed saving secret to OS Keychain: {e}"))
}

/// Reads a secret from the OS native Keychain. Returns `Ok(None)` if not stored.
pub fn keychain_get(account: &str) -> Result<Option<String>, String> {
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, account)
        .map_err(|e| format!("Keychain entry error: {e}"))?;
    match entry.get_password() {
        Ok(val) => Ok(Some(val)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(format!("Failed reading OS Keychain: {e}")),
    }
}

/// Deletes a secret from the OS native Keychain if present.
pub fn keychain_delete(account: &str) -> Result<(), String> {
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, account)
        .map_err(|e| format!("Keychain entry error: {e}"))?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(format!("Failed deleting secret from OS Keychain: {e}")),
    }
}

/// Checks whether the OS Keychain backend can be opened cleanly in this environment.
pub fn keychain_is_available() -> bool {
    let Ok(entry) = keyring::Entry::new(KEYCHAIN_SERVICE, "__probe_nonexistent__") else {
        return false;
    };
    matches!(entry.get_password(), Ok(_) | Err(keyring::Error::NoEntry))
}

/// Restricts permissions on local database, key, and bootstrap token files.
/// Enforces `0600` on Unix and best-effort owner-only NTFS ACLs on Windows.
pub fn restrict_private_file_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o600);
            let _ = std::fs::set_permissions(path, perms);
        }
    }
    #[cfg(windows)]
    {
        // Skip expensive icacls calls for ephemeral unit-test temp files
        if path.starts_with(std::env::temp_dir()) {
            return;
        }
        if let Ok(user) = std::env::var("USERNAME") {
            let user_trim = user.trim();
            if !user_trim.is_empty() {
                let principal = match std::env::var("USERDOMAIN") {
                    Ok(dom) if !dom.trim().is_empty() => format!("{}\\{}", dom.trim(), user_trim),
                    _ => user_trim.to_string(),
                };
                let grant = format!("{principal}:(F)");
                let _ = std::process::Command::new("icacls")
                    .arg(path)
                    .arg("/inheritance:r")
                    .arg("/grant:r")
                    .arg(&grant)
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
            }
        }
    }
}

/// Authenticated AES-256-GCM field-level vault for sensitive local SQLite records
/// (2FA TOTP seeds and Slack/Discord/Teams webhook bearer URLs).
/// Key resolution priority:
/// 1. `ABW_VAULT_KEY` env var (64-char hex 256-bit key for container/orchestrator secrets)
/// 2. OS native Keychain (`keyring` v3) so a stolen `threat_board.db` alone cannot decrypt secrets
/// 3. Fallback `0600` local keyfile (`<data_dir>/.abw_vault.key`) for headless containers
#[derive(Clone)]
pub struct LocalFieldVault {
    key: [u8; 32],
}

impl LocalFieldVault {
    pub fn load_or_init(data_dir: &Path) -> Self {
        if let Ok(env_hex) = std::env::var("ABW_VAULT_KEY") {
            if let Some(key) = decode_hex_key32(env_hex.trim()) {
                return Self { key };
            }
        }

        let is_temp_dir = data_dir.starts_with(std::env::temp_dir());

        if !is_temp_dir {
            if let Ok(Some(kc_hex)) = keychain_get(KEYCHAIN_ACCOUNT_DB_VAULT_KEY) {
                if let Some(key) = decode_hex_key32(kc_hex.trim()) {
                    return Self { key };
                }
            }
        }

        let key_path = data_dir.join(".abw_vault.key");
        if let Ok(raw) = std::fs::read_to_string(&key_path) {
            if let Some(key) = decode_hex_key32(raw.trim()) {
                return Self { key };
            }
        }

        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).expect("OS CSPRNG failed generating vault key");
        let hex_key = hex::encode(key);

        if !is_temp_dir && keychain_set(KEYCHAIN_ACCOUNT_DB_VAULT_KEY, &hex_key).is_ok() {
            return Self { key };
        }

        let _ = std::fs::create_dir_all(data_dir);
        if std::fs::write(&key_path, format!("{hex_key}\n")).is_ok() {
            restrict_private_file_permissions(&key_path);
        }
        Self { key }
    }

    pub fn encrypt_field(&self, aad: &str, plaintext: &str) -> Result<String, String> {
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| format!("Vault cipher init error: {e}"))?;
        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| format!("CSPRNG nonce generation error: {e}"))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext.as_bytes(),
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| "Vault AES-256-GCM encryption failed".to_string())?;
        Ok(format!(
            "enc:v1:{}:{}",
            hex::encode(nonce_bytes),
            hex::encode(ct)
        ))
    }

    /// Decrypts `enc:v1:<nonce>:<ct>` values with AAD verification.
    /// Legacy pre-v0.6.1 plaintext values pass through cleanly for seamless upgrade.
    pub fn decrypt_field(&self, aad: &str, stored: &str) -> Result<String, String> {
        let Some(rest) = stored.strip_prefix("enc:v1:") else {
            return Ok(stored.to_string());
        };
        let Some((nonce_hex, ct_hex)) = rest.split_once(':') else {
            return Err("Malformed encrypted vault payload".to_string());
        };
        let nonce_vec =
            hex::decode(nonce_hex).map_err(|_| "Invalid vault nonce hex".to_string())?;
        if nonce_vec.len() != 12 {
            return Err("Invalid vault nonce length".to_string());
        }
        let ct = hex::decode(ct_hex).map_err(|_| "Invalid vault ciphertext hex".to_string())?;
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| format!("Vault cipher init error: {e}"))?;
        let pt = cipher
            .decrypt(
                Nonce::from_slice(&nonce_vec),
                Payload {
                    msg: ct.as_slice(),
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| {
                "Vault AES-256-GCM decryption failed (wrong key or tampered data)".to_string()
            })?;
        String::from_utf8(pt).map_err(|_| "Vault decrypted payload is not valid UTF-8".to_string())
    }
}

fn decode_hex_key32(raw: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(raw).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(arr)
}

/// Generates a cryptographically random hex token using OS CSPRNG.
pub fn generate_random_token(num_bytes: usize) -> Result<String, String> {
    let mut buf = vec![0u8; num_bytes];
    getrandom::getrandom(&mut buf).map_err(|e| format!("OS CSPRNG error: {e}"))?;
    Ok(hex::encode(buf))
}

/// Constant-time string comparison for bearer tokens and cookies.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    let max_len = ab.len().max(bb.len());
    let mut diff: u8 = if ab.len() == bb.len() { 0 } else { 1 };
    for i in 0..max_len {
        let av = ab.get(i).copied().unwrap_or(0);
        let bv = bb.get(i).copied().unwrap_or(0);
        diff |= av ^ bv;
    }
    diff == 0
}

pub fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    let val = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let rest = val
        .strip_prefix("Bearer ")
        .or_else(|| val.strip_prefix("bearer "))?;
    let trimmed = rest.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

pub fn extract_session_cookie<'a>(headers: &'a HeaderMap, cookie_name: &str) -> Option<&'a str> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let kv = part.trim();
        if let Some((name, val)) = kv.split_once('=') {
            if name.trim() == cookie_name {
                let v = val.trim();
                if !v.is_empty() {
                    return Some(v);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssrf_blocks_private_loopback_metadata_and_ipv4_mapped_v6() {
        let strict = OutboundUrlPolicy::StrictPublicHttps;
        assert!(!is_ip_allowed("127.0.0.1".parse().unwrap(), strict));
        assert!(!is_ip_allowed("10.0.0.5".parse().unwrap(), strict));
        assert!(!is_ip_allowed("172.16.12.1".parse().unwrap(), strict));
        assert!(!is_ip_allowed("192.168.1.1".parse().unwrap(), strict));
        assert!(!is_ip_allowed("169.254.169.254".parse().unwrap(), strict));
        assert!(!is_ip_allowed("100.64.0.1".parse().unwrap(), strict));
        assert!(!is_ip_allowed("100.100.100.200".parse().unwrap(), strict));
        assert!(!is_ip_allowed("0.0.0.0".parse().unwrap(), strict));
        assert!(!is_ip_allowed("::1".parse().unwrap(), strict));
        assert!(!is_ip_allowed("fe80::1".parse().unwrap(), strict));
        assert!(!is_ip_allowed("fc00::1".parse().unwrap(), strict));
        assert!(!is_ip_allowed("::ffff:127.0.0.1".parse().unwrap(), strict));
        assert!(!is_ip_allowed(
            "::ffff:169.254.169.254".parse().unwrap(),
            strict
        ));
        assert!(is_ip_allowed("1.1.1.1".parse().unwrap(), strict));
        assert!(is_ip_allowed(
            "2606:4700:4700::1111".parse().unwrap(),
            strict
        ));
    }

    #[test]
    fn ai_policy_allows_loopback_and_respects_lan_opt_in() {
        let no_lan = OutboundUrlPolicy::AiProvider { allow_lan: false };
        assert!(is_ip_allowed("127.0.0.1".parse().unwrap(), no_lan));
        assert!(is_ip_allowed("::1".parse().unwrap(), no_lan));
        assert!(!is_ip_allowed("192.168.1.50".parse().unwrap(), no_lan));
        assert!(!is_ip_allowed("169.254.169.254".parse().unwrap(), no_lan));

        let with_lan = OutboundUrlPolicy::AiProvider { allow_lan: true };
        assert!(is_ip_allowed("192.168.1.50".parse().unwrap(), with_lan));
        assert!(is_ip_allowed("10.1.2.3".parse().unwrap(), with_lan));
        assert!(!is_ip_allowed("169.254.169.254".parse().unwrap(), with_lan));
        assert!(!is_ip_allowed("100.100.100.200".parse().unwrap(), with_lan));
    }

    #[tokio::test]
    async fn validate_outbound_url_rejects_bad_schemes_and_private_ips() {
        let strict = OutboundUrlPolicy::StrictPublicHttps;
        assert!(validate_outbound_url("http://1.1.1.1/feed", strict)
            .await
            .is_err());
        assert!(validate_outbound_url("https://127.0.0.1/hook", strict)
            .await
            .is_err());
        assert!(
            validate_outbound_url("https://169.254.169.254/latest", strict)
                .await
                .is_err()
        );
        assert!(
            validate_outbound_url("https://[::ffff:127.0.0.1]/hook", strict)
                .await
                .is_err()
        );
        assert!(
            validate_outbound_url("https://user:pass@1.1.1.1/hook", strict)
                .await
                .is_err()
        );
        assert!(validate_outbound_url("https://1.1.1.1/webhook", strict)
            .await
            .is_ok());

        let ai_local = OutboundUrlPolicy::AiProvider { allow_lan: false };
        assert!(validate_outbound_url("http://127.0.0.1:11434/v1", ai_local)
            .await
            .is_ok());
        assert!(
            validate_outbound_url("http://192.168.1.10:11434/v1", ai_local)
                .await
                .is_err()
        );
    }

    #[test]
    fn strip_unicode_removes_bidi_and_tags() {
        let payload = "Hello\u{202E}txe\u{200B}t\u{E0041}\u{E0042}\nNext";
        let cleaned = strip_invisible_unicode(payload);
        assert_eq!(cleaned, "Hellotxet\nNext");
    }

    #[test]
    fn sanitize_markdown_blocks_scripts_images_and_javascript_links() {
        let md = "Report\n<script>alert(1)</script>\n![tracker](https://evil.invalid/px.png)\n[click](javascript:alert(2))\n[CISA](https://www.cisa.gov/)";
        let sanitized = sanitize_llm_markdown(md);
        assert!(!sanitized.contains("<script>"));
        assert!(!sanitized.contains("![tracker]"));
        assert!(!sanitized.contains("javascript:"));
        assert!(sanitized.contains("[image blocked: tracker]"));
        assert!(sanitized.contains("click (unsafe-link-removed)"));
        assert!(sanitized.contains("[CISA](https://www.cisa.gov/)"));
    }

    #[test]
    fn defang_and_redact_format_cleanly() {
        assert_eq!(defang_ip("198.51.100.42"), "198.51.100[.]42");
        assert_eq!(
            defang_url("https://phish.invalid/login.php"),
            "hxxps://phish[.]invalid/login.php"
        );
        assert_eq!(redact_ip("198.51.100.42"), "198.51.xxx.xxx");
    }

    #[test]
    fn constant_time_and_token_generation_work() {
        let t1 = generate_random_token(16).unwrap();
        let t2 = generate_random_token(16).unwrap();
        assert_eq!(t1.len(), 32);
        assert_ne!(t1, t2);
        assert!(constant_time_eq(&t1, &t1));
        assert!(!constant_time_eq(&t1, &t2));
        assert!(!constant_time_eq("abc", "abcd"));
    }

    #[test]
    fn ssrf_blocks_ipv6_transition_and_ipv4_special_ranges() {
        let strict = OutboundUrlPolicy::StrictPublicHttps;
        // IPv6 transition & special-use ranges
        assert!(!is_ip_allowed(
            "64:ff9b::127.0.0.1".parse().unwrap(),
            strict
        ));
        assert!(!is_ip_allowed("64:ff9b:1::1".parse().unwrap(), strict));
        assert!(!is_ip_allowed("2002:7f00:0001::1".parse().unwrap(), strict));
        assert!(!is_ip_allowed(
            "2001:0000:4136:e378::1".parse().unwrap(),
            strict
        ));
        assert!(!is_ip_allowed("::127.0.0.1".parse().unwrap(), strict));
        assert!(!is_ip_allowed(
            "::ffff:0:127.0.0.1".parse().unwrap(),
            strict
        ));
        assert!(!is_ip_allowed("fec0::1".parse().unwrap(), strict));
        assert!(!is_ip_allowed("100::1".parse().unwrap(), strict));
        assert!(!is_ip_allowed("2001:2::1".parse().unwrap(), strict));
        assert!(!is_ip_allowed("2001:20::1".parse().unwrap(), strict));
        // IPv4 Class E & IETF protocol assignments
        assert!(!is_ip_allowed("240.0.0.1".parse().unwrap(), strict));
        assert!(!is_ip_allowed("192.0.0.1".parse().unwrap(), strict));
    }

    #[tokio::test]
    async fn validate_outbound_url_canonicalizes_trailing_dot_for_dns_pin() {
        let ai_local = OutboundUrlPolicy::AiProvider { allow_lan: false };
        let validated = validate_outbound_url("http://localhost.:11434/v1", ai_local)
            .await
            .unwrap();
        assert_eq!(validated.host, "localhost");
        assert_eq!(validated.url.host_str(), Some("localhost"));
        assert!(!validated.url.as_str().contains("localhost."));
    }

    #[test]
    fn sanitize_markdown_blocks_html_tags_and_reference_link_bypasses() {
        let md = "Version <= 2.4.1\n<details open ontoggle=alert(1)>x</details>\n<marquee>hi</marquee>\n![px][img1]\n[click][js1]\n[angle](<javascript:alert(1)>)\n[ent](javascript&#58;alert(1))\n[proto](//evil.invalid/x)\n\n[img1]: https://evil.invalid/px.png\n[js1]: javascript:alert(9)\n[ok]: https://www.cisa.gov/";
        let out = sanitize_llm_markdown(md);
        assert!(out.contains("Version <= 2.4.1"));
        assert!(!out.contains("<details"));
        assert!(!out.contains("<marquee"));
        assert!(!out.contains("![px]"));
        assert!(out.contains("[image blocked: px]"));
        assert!(!out.contains("javascript:"));
        assert!(!out.contains("javascript&#58;"));
        assert!(out.contains("[js1]: #unsafe-link-removed"));
        assert!(out.contains("[ok]: https://www.cisa.gov/"));
        assert!(out.contains("proto (unsafe-link-removed)"));
    }

    #[test]
    fn local_field_vault_encrypts_with_aad_and_supports_legacy_plaintext() {
        let dir = std::env::temp_dir().join(format!("abw_vault_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let vault = LocalFieldVault::load_or_init(&dir);
        let ct = vault
            .encrypt_field(
                "webhook_url:w1",
                "https://hooks.slack.com/services/T/B/SECRET",
            )
            .unwrap();
        assert!(ct.starts_with("enc:v1:"));
        assert!(!ct.contains("SECRET"));
        assert_eq!(
            vault.decrypt_field("webhook_url:w1", &ct).unwrap(),
            "https://hooks.slack.com/services/T/B/SECRET"
        );
        // Wrong AAD must fail authentication
        assert!(vault.decrypt_field("webhook_url:w2", &ct).is_err());
        // Legacy plaintext passthrough works seamlessly
        assert_eq!(
            vault
                .decrypt_field("totp_secret_b32", "JBSWY3DPEHPK3PXP")
                .unwrap(),
            "JBSWY3DPEHPK3PXP"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
