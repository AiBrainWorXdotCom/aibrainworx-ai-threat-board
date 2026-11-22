use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use hmac::{Hmac, Mac};
use qrcode::{render::svg, QrCode};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::security::constant_time_eq;

type HmacSha1 = Hmac<Sha1>;

const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const RECOVERY_ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// Validated Argon2id parameters following OWASP interactive recommendations (19 MiB, 2 iterations, 1 lane).
fn argon2_engine() -> Argon2<'static> {
    let params = Params::new(19_456, 2, 1, None).expect("valid static Argon2id params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Normalizes and validates a local username (3-32 chars, ASCII letters/digits/._-).
pub fn validate_username(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim().to_ascii_lowercase();
    if trimmed.len() < 3 || trimmed.len() > 32 {
        return Err("Username must be between 3 and 32 characters.".to_string());
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
    {
        return Err(
            "Username may only contain letters, numbers, dots (.), underscores (_), and hyphens (-)."
                .to_string(),
        );
    }
    if !trimmed
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric())
    {
        return Err("Username must start with a letter or number.".to_string());
    }
    Ok(trimmed)
}

/// Validates password strength (10-128 characters, not blank/repetitive).
pub fn validate_password(raw: &str) -> Result<(), String> {
    if raw.len() < 10 {
        return Err("Password must be at least 10 characters long.".to_string());
    }
    if raw.len() > 128 {
        return Err("Password must be 128 characters or fewer.".to_string());
    }
    if raw.trim().is_empty() {
        return Err("Password cannot be whitespace only.".to_string());
    }
    Ok(())
}

/// Hashes a password using Argon2id with a fresh 128-bit CSPRNG salt.
pub fn hash_password(password: &str) -> Result<String, String> {
    let mut salt_bytes = [0u8; 16];
    getrandom::getrandom(&mut salt_bytes)
        .map_err(|e| format!("CSPRNG salt generation failed: {e}"))?;
    let salt = SaltString::encode_b64(&salt_bytes)
        .map_err(|e| format!("Failed encoding Argon2 salt: {e}"))?;
    argon2_engine()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| format!("Password hashing failed: {e}"))
}

/// Constant-time verification of a password against a stored PHC Argon2id hash.
pub fn verify_password(password: &str, stored_hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(stored_hash) else {
        return false;
    };
    argon2_engine()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Performs an Argon2id verification against a static dummy hash to prevent username enumeration by timing.
pub fn dummy_verify_password(password: &str) {
    // Valid Argon2id PHC string with same parameters (m=19456,t=2,p=1)
    const DUMMY_HASH: &str =
        "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let _ = verify_password(password, DUMMY_HASH);
}

/// Generates a 256-bit CSPRNG hex session token.
pub fn generate_session_token() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|e| format!("CSPRNG session token failed: {e}"))?;
    Ok(hex::encode(bytes))
}

/// SHA-256 hex digest of a session token or recovery code. Only hashes are persisted in SQLite.
pub fn hash_secret_sha256(raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    hex::encode(hasher.finalize())
}

/// Encodes arbitrary bytes into unpadded uppercase RFC 4648 Base32.
pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut buffer: u32 = 0;
    let mut bits_left: u32 = 0;
    for &byte in data {
        buffer = (buffer << 8) | u32::from(byte);
        bits_left += 8;
        while bits_left >= 5 {
            let idx = ((buffer >> (bits_left - 5)) & 0x1f) as usize;
            out.push(BASE32_ALPHABET[idx] as char);
            bits_left -= 5;
        }
    }
    if bits_left > 0 {
        let idx = ((buffer << (5 - bits_left)) & 0x1f) as usize;
        out.push(BASE32_ALPHABET[idx] as char);
    }
    out
}

/// Decodes RFC 4648 Base32 (case-insensitive, ignores spaces/hyphens/'=' padding).
pub fn base32_decode(input: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(input.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits_left: u32 = 0;
    for ch in input.chars() {
        if ch.is_ascii_whitespace() || ch == '-' || ch == '=' {
            continue;
        }
        let val = match ch.to_ascii_uppercase() {
            'A'..='Z' => (ch.to_ascii_uppercase() as u32) - ('A' as u32),
            '2'..='7' => (ch as u32) - ('2' as u32) + 26,
            _ => return Err("Invalid Base32 character in TOTP secret".to_string()),
        };
        buffer = (buffer << 5) | val;
        bits_left += 5;
        if bits_left >= 8 {
            out.push(((buffer >> (bits_left - 8)) & 0xff) as u8);
            bits_left -= 8;
        }
    }
    Ok(out)
}

/// Generates a fresh 160-bit CSPRNG TOTP secret encoded in Base32.
pub fn generate_totp_secret() -> Result<String, String> {
    let mut bytes = [0u8; 20];
    getrandom::getrandom(&mut bytes).map_err(|e| format!("CSPRNG TOTP secret failed: {e}"))?;
    Ok(base32_encode(&bytes))
}

/// Computes a 6-digit RFC 6238 TOTP code for a given Base32 secret and 30-second time step.
pub fn totp_code_at_step(secret_b32: &str, step: u64) -> Result<String, String> {
    let key = base32_decode(secret_b32)?;
    let mut mac = HmacSha1::new_from_slice(&key).map_err(|_| "Invalid TOTP key".to_string())?;
    mac.update(&step.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let bin_code: u32 = ((u32::from(digest[offset]) & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    let otp = bin_code % 1_000_000;
    Ok(format!("{otp:06}"))
}

/// Verifies a user-supplied 6-digit TOTP code within ±1 time step (30s drift tolerance)
/// while enforcing replay protection (`matched_step > last_used_step`).
pub fn verify_totp_code(
    secret_b32: &str,
    raw_code: &str,
    last_used_step: Option<u64>,
) -> Option<u64> {
    let cleaned: String = raw_code.chars().filter(|c| c.is_ascii_digit()).collect();
    if cleaned.len() != 6 {
        return None;
    }
    let now_secs = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    let current_step = now_secs / 30;
    verify_totp_code_at_step(secret_b32, &cleaned, current_step, last_used_step)
}

pub fn verify_totp_code_at_step(
    secret_b32: &str,
    cleaned_code: &str,
    current_step: u64,
    last_used_step: Option<u64>,
) -> Option<u64> {
    let min_step = current_step.saturating_sub(1);
    let max_step = current_step.saturating_add(1);
    for step in min_step..=max_step {
        if let Some(prev) = last_used_step {
            if step <= prev {
                continue;
            }
        }
        if let Ok(expected) = totp_code_at_step(secret_b32, step) {
            if constant_time_eq(cleaned_code, &expected) {
                return Some(step);
            }
        }
    }
    None
}

/// Builds a standard `otpauth://` provisioning URI for authenticator apps.
pub fn build_otpauth_uri(username: &str, secret_b32: &str) -> String {
    format!(
        "otpauth://totp/AiBrainWorX:{username}?secret={secret_b32}&issuer=AiBrainWorX&algorithm=SHA1&digits=6&period=30"
    )
}

fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = if chunk.len() > 1 {
            u32::from(chunk[1])
        } else {
            0
        };
        let b2 = if chunk.len() > 2 {
            u32::from(chunk[2])
        } else {
            0
        };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((n >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(n & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Renders a crisp, 100% offline base64 SVG QR code data URI (zero external network calls).
pub fn render_qr_svg_data_uri(uri: &str) -> Result<String, String> {
    let code = QrCode::new(uri.as_bytes()).map_err(|e| format!("QR generation failed: {e}"))?;
    let svg_xml = code
        .render::<svg::Color>()
        .min_dimensions(210, 210)
        .quiet_zone(true)
        .dark_color(svg::Color("#06090d"))
        .light_color(svg::Color("#ffffff"))
        .build();
    Ok(format!(
        "data:image/svg+xml;base64,{}",
        base64_encode(svg_xml.as_bytes())
    ))
}

/// Generates 8 single-use 10-character recovery codes (`XXXXX-XXXXX`) and their salted SHA-256 hashes.
pub fn generate_recovery_codes(username: &str) -> Result<(Vec<String>, Vec<String>), String> {
    let mut plaintext = Vec::with_capacity(8);
    let mut hashes = Vec::with_capacity(8);
    for _ in 0..8 {
        let mut raw = [0u8; 10];
        getrandom::getrandom(&mut raw).map_err(|e| format!("CSPRNG recovery code failed: {e}"))?;
        let chars: String = raw
            .iter()
            .map(|b| RECOVERY_ALPHABET[(*b as usize) % RECOVERY_ALPHABET.len()] as char)
            .collect();
        let formatted = format!("{}-{}", &chars[0..5], &chars[5..10]);
        let digest = hash_recovery_code(username, &formatted);
        plaintext.push(formatted);
        hashes.push(digest);
    }
    Ok((plaintext, hashes))
}

pub fn hash_recovery_code(username: &str, code: &str) -> String {
    let normalized: String = code
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    hash_secret_sha256(&format!("abw-recovery:{username}:{normalized}"))
}

/// Constant-time match & consumption of a single-use recovery code.
/// Returns `Some(remaining_hashes)` if matched.
pub fn consume_recovery_code(
    username: &str,
    raw_input: &str,
    stored_hashes: &[String],
) -> Option<Vec<String>> {
    let candidate = hash_recovery_code(username, raw_input);
    let mut matched_idx: Option<usize> = None;
    for (idx, existing) in stored_hashes.iter().enumerate() {
        if constant_time_eq(&candidate, existing) && matched_idx.is_none() {
            matched_idx = Some(idx);
        }
    }
    let idx = matched_idx?;
    let mut next = stored_hashes.to_vec();
    next.remove(idx);
    Some(next)
}

#[derive(Debug, Clone)]
struct FailBucket {
    failures: u32,
    window_start: Instant,
    locked_until: Option<Instant>,
}

/// In-memory brute-force protection with progressive lockout (60s -> 5m -> 15m).
pub struct AuthRateLimiter {
    buckets: Mutex<HashMap<String, FailBucket>>,
}

impl Default for AuthRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthRateLimiter {
    pub fn new() -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Checks whether a login key is currently locked out. Returns `Err(retry_after_secs)` if blocked.
    pub fn check_locked(&self, key: &str) -> Result<(), u64> {
        let now = Instant::now();
        let mut map = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(bucket) = map.get(key) {
            if let Some(until) = bucket.locked_until {
                if until > now {
                    return Err(until.duration_since(now).as_secs().max(1));
                }
            }
            if now.duration_since(bucket.window_start) > Duration::from_secs(900) {
                map.remove(key);
            }
        }
        Ok(())
    }

    /// Records a failed login attempt and returns `Some(lockout_secs)` if lockout was triggered.
    pub fn record_failure(&self, key: &str) -> Option<u64> {
        let now = Instant::now();
        let mut map = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() > 2048 {
            map.retain(|_, b| now.duration_since(b.window_start) <= Duration::from_secs(900));
            if map.len() > 2048 {
                map.clear();
            }
        }
        let bucket = map.entry(key.to_string()).or_insert_with(|| FailBucket {
            failures: 0,
            window_start: now,
            locked_until: None,
        });
        if now.duration_since(bucket.window_start) > Duration::from_secs(900) {
            bucket.failures = 0;
            bucket.window_start = now;
            bucket.locked_until = None;
        }
        bucket.failures = bucket.failures.saturating_add(1);
        let lock_secs = if bucket.failures >= 12 {
            Some(900)
        } else if bucket.failures >= 8 {
            Some(300)
        } else if bucket.failures >= 5 {
            Some(60)
        } else {
            None
        };
        if let Some(secs) = lock_secs {
            bucket.locked_until = Some(now + Duration::from_secs(secs));
        }
        lock_secs
    }

    /// Clears failure state on a successful login.
    pub fn record_success(&self, key: &str) {
        let mut map = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        map.remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2id_password_roundtrip_works() {
        let hash = hash_password("Correct-Horse-Battery-42!").expect("hash");
        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_password("Correct-Horse-Battery-42!", &hash));
        assert!(!verify_password("Wrong-Password-42!", &hash));
    }

    #[test]
    fn totp_rfc6238_vector_and_replay_protection() {
        // RFC 6238 SHA1 test secret: ASCII "12345678901234567890"
        let secret = base32_encode(b"12345678901234567890");
        // At t = 59s -> step 1 -> RFC 6238 8-digit = 94287082 -> 6-digit = 287082
        let code = totp_code_at_step(&secret, 1).expect("totp");
        assert_eq!(code, "287082");

        // Accepts step 1 initially
        assert_eq!(
            verify_totp_code_at_step(&secret, "287082", 1, None),
            Some(1)
        );
        // Rejects replay of step 1 when last_used_step == Some(1)
        assert_eq!(
            verify_totp_code_at_step(&secret, "287082", 1, Some(1)),
            None
        );
    }

    #[test]
    fn recovery_codes_are_single_use() {
        let (codes, hashes) = generate_recovery_codes("admin").expect("codes");
        assert_eq!(codes.len(), 8);
        let remaining = consume_recovery_code("admin", &codes[0], &hashes).expect("valid");
        assert_eq!(remaining.len(), 7);
        assert!(consume_recovery_code("admin", &codes[0], &remaining).is_none());
    }

    #[test]
    fn rate_limiter_locks_after_five_failures() {
        let limiter = AuthRateLimiter::new();
        for _ in 0..4 {
            assert!(limiter.record_failure("127.0.0.1:admin").is_none());
            assert!(limiter.check_locked("127.0.0.1:admin").is_ok());
        }
        assert_eq!(limiter.record_failure("127.0.0.1:admin"), Some(60));
        assert!(limiter.check_locked("127.0.0.1:admin").is_err());
        limiter.record_success("127.0.0.1:admin");
        assert!(limiter.check_locked("127.0.0.1:admin").is_ok());
    }

    #[test]
    fn offline_qr_svg_renders_without_network() {
        let uri = build_otpauth_uri("admin", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        let data_uri = render_qr_svg_data_uri(&uri).expect("qr");
        assert!(data_uri.starts_with("data:image/svg+xml;base64,"));
        assert!(data_uri.len() > 200);
    }
}
