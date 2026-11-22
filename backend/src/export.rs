use std::collections::HashSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::models::{
    AttackerIp, BotnetC2, NetworkTelemetry, PhishingUrl, ThreatNewsItem, Vulnerability,
};
use crate::security::strip_invisible_unicode;
use crate::store::ThreatStore;

/// Protects CSV/Excel exports against formula injection (`=`, `+`, `-`, `@`, `\t`, `\r`).
pub fn csv_safe_cell(raw: &str) -> String {
    let cleaned = strip_invisible_unicode(raw).replace('\0', "");
    let trimmed_start = cleaned.trim_start();
    let needs_prefix = trimmed_start
        .chars()
        .next()
        .is_some_and(|c| matches!(c, '=' | '+' | '-' | '@' | '\t' | '\r'));

    let escaped = if needs_prefix {
        format!("'{cleaned}")
    } else {
        cleaned
    };

    format!("\"{}\"", escaped.replace('"', "\"\""))
}

pub fn export_vulnerabilities_csv(vulns: &[Vulnerability]) -> String {
    let mut out = String::from(
        "cve_id,severity,ai_risk_score,cvss_score,epss_pct,epss_delta_24h_pct,is_kev,kev_due_date,kev_days_remaining,is_ai_related,has_public_exploit,triage_status,matched_stack,vendor,product,title,published_at\n",
    );
    for v in vulns {
        let sev = v.severity.as_str();
        let cvss = v.cvss_score.map(|c| format!("{c:.1}")).unwrap_or_default();
        let epss = v
            .epss_score
            .map(|e| format!("{:.2}", e * 100.0))
            .unwrap_or_default();
        let delta = v
            .epss_delta_24h
            .map(|d| format!("{:+.2}", d * 100.0))
            .unwrap_or_default();
        let due = v.kev_due_date.as_deref().unwrap_or("");
        let days_rem = v
            .kev_days_remaining
            .map(|d| d.to_string())
            .unwrap_or_default();
        let stack = v.matched_stack.join("; ");
        let vendor = v.vendor.as_deref().unwrap_or("");
        let product = v.product.as_deref().unwrap_or("");

        let row = [
            csv_safe_cell(&v.id),
            csv_safe_cell(sev),
            csv_safe_cell(&v.ai_risk_score.to_string()),
            csv_safe_cell(&cvss),
            csv_safe_cell(&epss),
            csv_safe_cell(&delta),
            csv_safe_cell(&v.is_kev.to_string()),
            csv_safe_cell(due),
            csv_safe_cell(&days_rem),
            csv_safe_cell(&v.is_ai_related.to_string()),
            csv_safe_cell(&v.has_public_exploit.to_string()),
            csv_safe_cell(v.triage_status.as_str()),
            csv_safe_cell(&stack),
            csv_safe_cell(vendor),
            csv_safe_cell(product),
            csv_safe_cell(&v.title),
            csv_safe_cell(&v.published_at.to_rfc3339()),
        ]
        .join(",");
        out.push_str(&row);
        out.push('\n');
    }
    out
}

pub fn export_vulnerability_markdown(v: &Vulnerability, related_news: &[ThreatNewsItem]) -> String {
    let mut md = String::new();
    md.push_str(&format!("# {} - {}\n\n", v.id, v.title));
    md.push_str(&format!(
        "- **Severity:** {} | **AI Risk Score:** {}/100 | **Triage:** `{}`\n",
        v.severity.as_str(),
        v.ai_risk_score,
        v.triage_status.as_str()
    ));
    md.push_str(&format!(
        "- **CVSS:** {} | **EPSS:** {} | **CISA KEV:** {}\n",
        v.cvss_score
            .map(|c| format!("{c:.1}"))
            .unwrap_or_else(|| "N/A".into()),
        v.epss_score
            .map(|e| format!("{:.2}%", e * 100.0))
            .unwrap_or_else(|| "N/A".into()),
        if v.is_kev {
            format!(
                "YES (Due: {})",
                v.kev_due_date.as_deref().unwrap_or("unspecified")
            )
        } else {
            "No".into()
        }
    ));
    if !v.matched_stack.is_empty() {
        md.push_str(&format!(
            "- **Exposed in My Stack:** {}\n",
            v.matched_stack.join(", ")
        ));
    }
    if let (Some(vendor), Some(product)) = (&v.vendor, &v.product) {
        md.push_str(&format!("- **Target:** {vendor} / {product}\n"));
    }
    if !v.triage_notes.trim().is_empty() {
        md.push_str(&format!(
            "\n## Analyst Triage Notes\n\n{}\n",
            v.triage_notes
        ));
    }
    md.push_str(&format!("\n## Description\n\n{}\n", v.description));

    if !v.ai_score_factors.is_empty() {
        md.push_str("\n## AI Risk Score Breakdown\n\n");
        for f in &v.ai_score_factors {
            md.push_str(&format!("- **+{} {}:** {}\n", f.points, f.label, f.detail));
        }
    }
    if !v.references.is_empty() {
        md.push_str("\n## References\n\n");
        for r in v.references.iter().take(12) {
            md.push_str(&format!("- {r}\n"));
        }
    }
    if !related_news.is_empty() {
        md.push_str("\n## Correlated Threat Intelligence\n\n");
        for n in related_news.iter().take(8) {
            md.push_str(&format!(
                "- **{}** ({}) — {}\n",
                n.source,
                n.published_at.format("%Y-%m-%d"),
                n.title
            ));
        }
    }
    md
}

/// Derives a deterministic RFC-4122 UUID from `seed` using SHA-256 without extra crate features.
fn deterministic_uuid(seed: &[u8]) -> Uuid {
    let hash = Sha256::digest(seed);
    let mut b = [0u8; 16];
    b.copy_from_slice(&hash[..16]);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    Uuid::from_bytes(b)
}

/// Generates a STIX 2.1 JSON Bundle with Identity, Vulnerability SDOs, and Indicator SDOs.
pub fn export_stix_bundle(
    vulns: &[Vulnerability],
    c2s: &[BotnetC2],
    attackers: &[AttackerIp],
    phishing: &[PhishingUrl],
) -> serde_json::Value {
    let identity_id = "identity--aibrainworx-0000-4000-8000-000000000001";
    let now = Utc::now().to_rfc3339();

    let mut objects: Vec<serde_json::Value> = vec![json!({
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": now,
        "modified": now,
        "name": "AiBrainWorX AI Threat Analysis Board",
        "identity_class": "system"
    })];

    for v in vulns.iter().take(300) {
        let stix_id = format!("vulnerability--{}", deterministic_uuid(v.id.as_bytes()));
        objects.push(json!({
            "type": "vulnerability",
            "spec_version": "2.1",
            "id": stix_id,
            "created": v.first_seen_at.to_rfc3339(),
            "modified": v.updated_at.to_rfc3339(),
            "created_by_ref": identity_id,
            "name": v.id,
            "description": v.description,
            "labels": v.mitre_tactics,
            "external_references": [{
                "source_name": "cve",
                "external_id": v.id,
                "url": format!("https://nvd.nist.gov/vuln/detail/{}", v.id)
            }]
        }));
    }

    let mut seen_patterns = HashSet::new();
    for c2 in c2s.iter().take(200) {
        let pattern = format!("[ipv4-addr:value = '{}']", c2.ip_address.replace('\'', ""));
        if !seen_patterns.insert(pattern.clone()) {
            continue;
        }
        let stix_id = format!("indicator--{}", deterministic_uuid(pattern.as_bytes()));
        objects.push(json!({
            "type": "indicator",
            "spec_version": "2.1",
            "id": stix_id,
            "created": now,
            "modified": now,
            "created_by_ref": identity_id,
            "name": format!("Botnet C2 {}", c2.malware),
            "indicator_types": ["malicious-activity"],
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": now,
        }));
    }

    for atk in attackers.iter().take(200) {
        let pattern = format!("[ipv4-addr:value = '{}']", atk.ip.replace('\'', ""));
        if !seen_patterns.insert(pattern.clone()) {
            continue;
        }
        let stix_id = format!("indicator--{}", deterministic_uuid(pattern.as_bytes()));
        objects.push(json!({
            "type": "indicator",
            "spec_version": "2.1",
            "id": stix_id,
            "created": now,
            "modified": now,
            "created_by_ref": identity_id,
            "name": "SANS Top Attacker IP",
            "indicator_types": ["malicious-activity"],
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": now,
        }));
    }

    for ph in phishing.iter().take(100) {
        let escaped_url = ph.url.replace('\\', "\\\\").replace('\'', "\\'");
        let pattern = format!("[url:value = '{escaped_url}']");
        if !seen_patterns.insert(pattern.clone()) {
            continue;
        }
        let stix_id = format!("indicator--{}", deterministic_uuid(pattern.as_bytes()));
        objects.push(json!({
            "type": "indicator",
            "spec_version": "2.1",
            "id": stix_id,
            "created": now,
            "modified": now,
            "created_by_ref": identity_id,
            "name": format!("Phishing URL ({})", ph.domain),
            "indicator_types": ["malicious-activity"],
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": now,
        }));
    }

    json!({
        "type": "bundle",
        "id": format!("bundle--{}", Uuid::new_v4()),
        "objects": objects
    })
}

/// Exports network threat IPs cleanly for firewalls (`edl`, `nftables`, `pf`) or formula-safe `csv`.
pub fn export_iocs_blocklist(
    format: &str,
    telemetry: &NetworkTelemetry,
) -> Result<(String, &'static str, &'static str), String> {
    let mut unique_ips = Vec::new();
    let mut seen = HashSet::new();

    for c2 in &telemetry.botnet_c2s {
        if let Ok(ip) = c2.ip_address.trim().parse::<std::net::IpAddr>() {
            let s = ip.to_string();
            if seen.insert(s.clone()) {
                unique_ips.push(s);
            }
        }
    }
    for atk in &telemetry.top_attacking_ips {
        if let Ok(ip) = atk.ip.trim().parse::<std::net::IpAddr>() {
            let s = ip.to_string();
            if seen.insert(s.clone()) {
                unique_ips.push(s);
            }
        }
    }

    match format.trim().to_ascii_lowercase().as_str() {
        "edl" | "txt" => {
            let mut body = String::from("# AiBrainWorX External Dynamic List (EDL)\n");
            for ip in &unique_ips {
                body.push_str(ip);
                body.push('\n');
            }
            Ok((
                body,
                "text/plain; charset=utf-8",
                "aibrainworx-iocs-edl.txt",
            ))
        }
        "pf" => {
            let mut body =
                String::from("# BSD / pfSense blocklist table <aibrainworx_blocklist>\n");
            for ip in &unique_ips {
                body.push_str(ip);
                body.push('\n');
            }
            Ok((
                body,
                "text/plain; charset=utf-8",
                "aibrainworx-pf-blocklist.txt",
            ))
        }
        "nftables" => {
            let v4_ips: Vec<String> = unique_ips
                .iter()
                .filter(|ip| ip.parse::<std::net::Ipv4Addr>().is_ok())
                .cloned()
                .collect();
            let elements = if v4_ips.is_empty() {
                String::new()
            } else {
                v4_ips.join(", ")
            };
            let body = format!(
                "# nftables set exported by AiBrainWorX\nset aibrainworx_blocklist {{\n    type ipv4_addr\n    flags interval\n    elements = {{ {elements} }}\n}}\n"
            );
            Ok((
                body,
                "text/plain; charset=utf-8",
                "aibrainworx-nftables-blocklist.nft",
            ))
        }
        "csv" => {
            let mut body = String::from("indicator,type,source,detail\n");
            for c2 in &telemetry.botnet_c2s {
                body.push_str(&format!(
                    "{},{},{},{}\n",
                    csv_safe_cell(&c2.ip_address),
                    csv_safe_cell("botnet_c2"),
                    csv_safe_cell("Abuse.ch Feodo"),
                    csv_safe_cell(&format!("{} ({})", c2.malware, c2.status)),
                ));
            }
            for atk in &telemetry.top_attacking_ips {
                body.push_str(&format!(
                    "{},{},{},{}\n",
                    csv_safe_cell(&atk.ip),
                    csv_safe_cell("attacker_ip"),
                    csv_safe_cell("SANS DShield"),
                    csv_safe_cell(&format!("reports={} attacks={}", atk.count, atk.attacks)),
                ));
            }
            for ph in &telemetry.phishing_urls {
                body.push_str(&format!(
                    "{},{},{},{}\n",
                    csv_safe_cell(&ph.url),
                    csv_safe_cell("phishing_url"),
                    csv_safe_cell(&ph.domain),
                    csv_safe_cell(ph.suspected_brand.as_deref().unwrap_or("")),
                ));
            }
            Ok((body, "text/csv; charset=utf-8", "aibrainworx-iocs.csv"))
        }
        other => Err(format!(
            "Unsupported IOC export format '{other}'; expected edl, pf, nftables, or csv"
        )),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotData {
    pub vulnerabilities: Vec<Vulnerability>,
    pub news: Vec<ThreatNewsItem>,
    pub telemetry: NetworkTelemetry,
    pub kev_cve_set: std::collections::BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfflineSnapshotEnvelope {
    pub schema_version: String,
    pub exported_at: DateTime<Utc>,
    pub data_sha256: String,
    pub data: SnapshotData,
}

/// Builds a secret-stripped portable offline snapshot protected with a deterministic SHA-256 digest.
/// Intentionally omits AI API keys, webhook URLs/secrets, and user-specific session secrets.
pub fn build_offline_snapshot(store: &ThreatStore) -> Result<OfflineSnapshotEnvelope, String> {
    let mut vulns: Vec<Vulnerability> = store.vulnerabilities.values().cloned().collect();
    vulns.sort_by(|a, b| a.id.cmp(&b.id));

    let mut news: Vec<ThreatNewsItem> = store.news.values().cloned().collect();
    news.sort_by(|a, b| a.id.cmp(&b.id));

    let kev_cve_set: std::collections::BTreeSet<String> =
        store.kev_cve_set.iter().cloned().collect();

    let data = SnapshotData {
        vulnerabilities: vulns,
        news,
        telemetry: store.telemetry.clone(),
        kev_cve_set,
    };

    let canonical = serde_json::to_vec(&data)
        .map_err(|e| format!("Failed serializing snapshot payload: {e}"))?;
    let digest = hex::encode(Sha256::digest(&canonical));

    Ok(OfflineSnapshotEnvelope {
        schema_version: "2.0".to_string(),
        exported_at: Utc::now(),
        data_sha256: digest,
        data,
    })
}

/// Verifies integrity SHA-256 digest of an imported offline snapshot and returns parsed payload.
pub fn verify_offline_snapshot(bytes: &[u8]) -> Result<OfflineSnapshotEnvelope, String> {
    let env: OfflineSnapshotEnvelope =
        serde_json::from_slice(bytes).map_err(|e| format!("Invalid offline snapshot JSON: {e}"))?;

    if env.schema_version != "2.0" {
        return Err(format!(
            "Unsupported snapshot schema_version '{}'",
            env.schema_version
        ));
    }

    let canonical = serde_json::to_vec(&env.data)
        .map_err(|e| format!("Failed verifying snapshot payload: {e}"))?;
    let expected = hex::encode(Sha256::digest(&canonical));
    if !crate::security::constant_time_eq(&expected, &env.data_sha256) {
        return Err("Snapshot integrity verification failed: SHA-256 mismatch".to_string());
    }

    Ok(env)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_neutralizes_excel_formula_injection() {
        assert_eq!(
            csv_safe_cell("=cmd|' /C calc'!A0"),
            "\"'=cmd|' /C calc'!A0\""
        );
        assert_eq!(csv_safe_cell("+1+1"), "\"'+1+1\"");
        assert_eq!(csv_safe_cell("-2+3"), "\"'-2+3\"");
        assert_eq!(csv_safe_cell("@SUM(1,2)"), "\"'@SUM(1,2)\"");
        assert_eq!(
            csv_safe_cell("normal \"quoted\" text"),
            "\"normal \"\"quoted\"\" text\""
        );
    }

    #[test]
    fn offline_snapshot_verifies_integrity_and_rejects_tampering() {
        let mut store = ThreatStore::default();
        store.kev_cve_set.insert("CVE-2026-0001".to_string());
        let env = build_offline_snapshot(&store).unwrap();
        let bytes = serde_json::to_vec(&env).unwrap();
        assert!(verify_offline_snapshot(&bytes).is_ok());

        let mut tampered = env.clone();
        tampered
            .data
            .kev_cve_set
            .insert("CVE-2099-9999".to_string());
        let tampered_bytes = serde_json::to_vec(&tampered).unwrap();
        assert!(verify_offline_snapshot(&tampered_bytes).is_err());
    }
}
