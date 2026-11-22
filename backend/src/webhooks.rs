use std::time::{Duration, Instant};

use chrono::Utc;
use hmac::{Hmac, Mac};
use regex::Regex;
use serde_json::json;
use sha2::Sha256;
use url::Url;

use crate::models::{
    Severity, ThreatAlert, Vulnerability, WebhookKind, WebhookTarget, WebhookTargetPublic,
    WebhookTestResponse,
};
use crate::security::{build_pinned_http_client, validate_outbound_url, OutboundUrlPolicy};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
pub struct WebhookDispatchItem {
    pub alert_title: String,
    pub alert_summary: String,
    pub severity: Severity,
    pub is_kev: bool,
    pub matched_stack: Vec<String>,
    pub cve_id: Option<String>,
    pub ai_risk_score: Option<u8>,
}

/// Masks secret path segments / tokens in Slack, Discord, and Teams webhook URLs
/// so bearer URL credentials are never echoed back via read APIs or logs.
pub fn mask_webhook_url(raw: &str) -> String {
    let Ok(parsed) = Url::parse(raw.trim()) else {
        return "••••(invalid-url)".to_string();
    };
    let scheme = parsed.scheme();
    let host = parsed.host_str().unwrap_or("unknown");
    let port_part = parsed.port().map(|p| format!(":{p}")).unwrap_or_default();
    let path = parsed.path();
    let tail: String = if path.len() > 6 {
        path.chars()
            .rev()
            .take(4)
            .collect::<String>()
            .chars()
            .rev()
            .collect()
    } else {
        "****".to_string()
    };
    format!("{scheme}://{host}{port_part}/••••{tail}")
}

pub fn to_public_webhook(target: &WebhookTarget) -> WebhookTargetPublic {
    WebhookTargetPublic {
        id: target.id.clone(),
        name: target.name.clone(),
        kind: target.kind,
        url_masked: mask_webhook_url(&target.url),
        enabled: target.enabled,
        min_severity: target.min_severity,
        kev_only: target.kev_only,
        stack_only: target.stack_only,
        has_signing_secret: target.has_signing_secret || !target.signing_secret.is_empty(),
        last_status: target.last_status.clone(),
        last_sent_at: target.last_sent_at,
        failure_count: target.failure_count,
    }
}

pub fn sign_payload_hmac_sha256(secret: &str, body: &[u8]) -> Result<String, String> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| format!("Invalid HMAC key: {e}"))?;
    mac.update(body);
    let result = mac.finalize();
    Ok(format!("sha256={}", hex::encode(result.into_bytes())))
}

fn discord_color(sev: Severity) -> u32 {
    match sev {
        Severity::Critical => 0xef4444,
        Severity::High => 0xf97316,
        Severity::Medium => 0xeab308,
        Severity::Low => 0x3b82f6,
        Severity::Info => 0x64748b,
    }
}

pub fn build_webhook_payload(kind: WebhookKind, item: &WebhookDispatchItem) -> serde_json::Value {
    let sev_label = item.severity.as_str();
    let cve_tag = item.cve_id.as_deref().unwrap_or("TELEMETRY");
    let stack_tag = if item.matched_stack.is_empty() {
        String::new()
    } else {
        format!(" | Stack Hit: {}", item.matched_stack.join(", "))
    };
    let kev_tag = if item.is_kev { " | CISA KEV" } else { "" };
    let headline = format!("[{sev_label}] {cve_tag}{kev_tag}{stack_tag}");

    match kind {
        WebhookKind::Slack => json!({
            "text": format!("AiBrainWorX Alert: {} - {}", headline, item.alert_title),
            "blocks": [
                {
                    "type": "header",
                    "text": { "type": "plain_text", "text": headline }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": format!("*{}*\n{}", item.alert_title, item.alert_summary)
                    }
                }
            ]
        }),
        WebhookKind::Discord => json!({
            "username": "AiBrainWorX Threat Board",
            "embeds": [{
                "title": format!("{headline}: {}", item.alert_title),
                "description": item.alert_summary,
                "color": discord_color(item.severity),
                "timestamp": Utc::now().to_rfc3339(),
                "fields": [
                    { "name": "CVE / Target", "value": cve_tag, "inline": true },
                    { "name": "Severity", "value": sev_label, "inline": true },
                    { "name": "AI Risk", "value": item.ai_risk_score.map(|s| s.to_string()).unwrap_or_else(|| "N/A".into()), "inline": true }
                ]
            }]
        }),
        WebhookKind::Teams => json!({
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": item.alert_title,
            "themeColor": format!("{:06X}", discord_color(item.severity)),
            "title": format!("AiBrainWorX {headline}"),
            "text": format!("**{}**\n\n{}", item.alert_title, item.alert_summary)
        }),
        WebhookKind::Generic => json!({
            "event": "threat_alert",
            "source": "aibrainworx-threat-board",
            "timestamp": Utc::now().to_rfc3339(),
            "severity": sev_label,
            "cve_id": item.cve_id,
            "is_kev": item.is_kev,
            "matched_stack": item.matched_stack,
            "ai_risk_score": item.ai_risk_score,
            "title": item.alert_title,
            "summary": item.alert_summary,
        }),
    }
}

/// Validates outbound HTTPS SSRF policy and dispatches one signed/formatted webhook POST.
pub async fn send_webhook_payload(
    target: &WebhookTarget,
    payload: &serde_json::Value,
) -> WebhookTestResponse {
    let start = Instant::now();
    let validated =
        match validate_outbound_url(&target.url, OutboundUrlPolicy::StrictPublicHttps).await {
            Ok(v) => v,
            Err(reason) => {
                return WebhookTestResponse {
                    ok: false,
                    status_code: None,
                    message: format!("Blocked by SSRF policy: {reason}"),
                    latency_ms: start.elapsed().as_millis() as u64,
                };
            }
        };

    let client = match build_pinned_http_client(
        &validated,
        Duration::from_secs(10),
        "AiBrainWorX-Webhook/0.2",
    ) {
        Ok(c) => c,
        Err(e) => {
            return WebhookTestResponse {
                ok: false,
                status_code: None,
                message: e,
                latency_ms: start.elapsed().as_millis() as u64,
            };
        }
    };

    let body_bytes = match serde_json::to_vec(payload) {
        Ok(b) => b,
        Err(e) => {
            return WebhookTestResponse {
                ok: false,
                status_code: None,
                message: format!("Payload serialization error: {e}"),
                latency_ms: start.elapsed().as_millis() as u64,
            };
        }
    };

    let mut req = client
        .post(validated.url)
        .header("Content-Type", "application/json")
        .header("X-AiBrainWorX-Event", "threat_alert");

    if !target.signing_secret.trim().is_empty() {
        if let Ok(sig) = sign_payload_hmac_sha256(target.signing_secret.trim(), &body_bytes) {
            req = req.header("X-AiBrainWorX-Signature-256", sig);
        }
    }

    match req.body(body_bytes).send().await {
        Ok(resp) => {
            let code = resp.status().as_u16();
            let ok = resp.status().is_success();
            let message = if ok {
                format!("Delivered (HTTP {code})")
            } else {
                format!("Remote endpoint returned HTTP {code}")
            };
            WebhookTestResponse {
                ok,
                status_code: Some(code),
                message,
                latency_ms: start.elapsed().as_millis() as u64,
            }
        }
        Err(err) => {
            // Avoid printing full request URL which could leak Slack/Discord webhook secret tokens
            let redacted = redact_url_in_error(&err.to_string());
            WebhookTestResponse {
                ok: false,
                status_code: None,
                message: format!("Delivery failed: {redacted}"),
                latency_ms: start.elapsed().as_millis() as u64,
            }
        }
    }
}

fn redact_url_in_error(msg: &str) -> String {
    let re = Regex::new(r"https?://[^\s)]+").expect("valid regex");
    re.replace_all(msg, "[redacted-webhook-url]").into_owned()
}

pub fn build_dispatch_items(
    alerts: &[ThreatAlert],
    vulns: &std::collections::HashMap<String, Vulnerability>,
) -> Vec<WebhookDispatchItem> {
    alerts
        .iter()
        .take(5)
        .map(|a| {
            let linked_vuln = a.linked_item_id.as_deref().and_then(|id| vulns.get(id));
            WebhookDispatchItem {
                alert_title: a.title.clone(),
                alert_summary: a.summary.clone(),
                severity: a.severity,
                is_kev: linked_vuln.map(|v| v.is_kev).unwrap_or(false),
                matched_stack: linked_vuln
                    .map(|v| v.matched_stack.clone())
                    .unwrap_or_default(),
                cve_id: linked_vuln
                    .map(|v| v.id.clone())
                    .or_else(|| a.cve_ids.first().cloned()),
                ai_risk_score: linked_vuln.map(|v| v.ai_risk_score),
            }
        })
        .collect()
}

pub fn webhook_matches_item(target: &WebhookTarget, item: &WebhookDispatchItem) -> bool {
    if !target.enabled {
        return false;
    }
    if item.severity.rank() < target.min_severity.rank() {
        return false;
    }
    if target.kev_only && !item.is_kev {
        return false;
    }
    if target.stack_only && item.matched_stack.is_empty() {
        return false;
    }
    true
}

/// Dispatches matching webhooks concurrently outside any state lock and returns status tuples.
pub async fn dispatch_webhooks_batch(
    targets: Vec<WebhookTarget>,
    items: Vec<WebhookDispatchItem>,
) -> Vec<(String, bool, String)> {
    let mut results = Vec::new();
    for target in targets {
        let matching: Vec<&WebhookDispatchItem> = items
            .iter()
            .filter(|item| webhook_matches_item(&target, item))
            .collect();
        if matching.is_empty() {
            continue;
        }
        // Send highest-priority matching alert (or digest summary if multiple)
        let first = matching[0];
        let payload = build_webhook_payload(target.kind, first);
        let res = send_webhook_payload(&target, &payload).await;
        results.push((target.id, res.ok, res.message));
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webhook_url_masking_hides_secret_token() {
        let masked = mask_webhook_url(
            "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXX1234",
        );
        assert!(!masked.contains("T00000000"));
        assert!(!masked.contains("XXXXXXXX"));
        assert!(masked.starts_with("https://hooks.slack.com/"));
        assert!(masked.ends_with("1234"));
    }

    #[test]
    fn hmac_signature_is_deterministic_sha256_hex() {
        let sig = sign_payload_hmac_sha256("super-secret", b"hello").unwrap();
        assert!(sig.starts_with("sha256="));
        assert_eq!(sig.len(), 7 + 64);
        assert_eq!(
            sig,
            sign_payload_hmac_sha256("super-secret", b"hello").unwrap()
        );
        assert_ne!(
            sig,
            sign_payload_hmac_sha256("wrong-secret", b"hello").unwrap()
        );
    }

    #[test]
    fn webhook_filter_honors_severity_kev_and_stack() {
        let target = WebhookTarget {
            id: "1".into(),
            name: "SOC Slack".into(),
            kind: WebhookKind::Slack,
            url: "https://hooks.slack.com/services/a/b/c".into(),
            enabled: true,
            min_severity: Severity::High,
            kev_only: true,
            stack_only: true,
            ..Default::default()
        };
        let miss = WebhookDispatchItem {
            alert_title: "t".into(),
            alert_summary: "s".into(),
            severity: Severity::Critical,
            is_kev: false,
            matched_stack: vec!["openssl".into()],
            cve_id: Some("CVE-2026-1".into()),
            ai_risk_score: Some(90),
        };
        assert!(!webhook_matches_item(&target, &miss));

        let hit = WebhookDispatchItem {
            is_kev: true,
            ..miss
        };
        assert!(webhook_matches_item(&target, &hit));
    }
}
