use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::analyzer::truncate_str;
use crate::models::{ThreatNewsItem, Vulnerability};
use crate::security::{sanitize_llm_markdown, strip_invisible_unicode};
use crate::store::ThreatStore;

pub const A2UI_PROTOCOL_VERSION: &str = "1.0";
pub const A2UI_CATALOG_ID: &str = "aibrainworx.soc.v1";

const MAX_COMPONENTS: usize = 40;
const MAX_JSON_DEPTH: usize = 8;
const MAX_ARRAY_ITEMS: usize = 64;
const MAX_STRING_LEN: usize = 4096;

/// Strictly allowlisted UI component primitives registered by the client catalog.
/// Unknown or raw HTML/script types are always rejected before reaching the UI.
const ALLOWED_COMPONENTS: &[&str] = &[
    "Column",
    "SplitGrid",
    "KpiStrip",
    "Banner",
    "BarChart",
    "VulnTable",
    "ActionChecklist",
    "NewsFeed",
    "IocPanel",
    "ExecutiveBrief",
    "ActionBar",
];

/// Strictly allowlisted client actions. AI-generated surfaces can NEVER touch
/// authentication/2FA, API keys, webhooks, alert rules, or arbitrary outbound URLs.
const ALLOWED_ACTIONS: &[&str] = &[
    "open_cve",
    "set_triage",
    "export_stix",
    "export_md",
    "navigate_tab",
    "copy_text",
];

const ALLOWED_TABS: &[&str] = &[
    "overview",
    "mystack",
    "vulnerabilities",
    "news",
    "network",
    "analyst",
    "alerts",
    "models",
];

const ALLOWED_TRIAGE_STATUSES: &[&str] = &[
    "new",
    "investigating",
    "mitigated",
    "false_positive",
    "accepted",
];

/// Declarative A2UI 1.0 `agent_to_renderer` surface payload attached to analyst responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2uiSurfacePayload {
    pub version: String,
    pub surface_id: String,
    pub catalog_id: String,
    pub intent: String,
    pub messages: Vec<A2uiServerMessage>,
}

/// A2UI 1.0 wire messages separating surface metadata, flat component adjacency list,
/// and bound `dataModel` values resolved via RFC 6901 JSON Pointers (`@path`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum A2uiServerMessage {
    CreateSurface {
        #[serde(rename = "surfaceId")]
        surface_id: String,
        #[serde(rename = "catalogId")]
        catalog_id: String,
        #[serde(rename = "rootComponentId")]
        root_component_id: String,
        title: String,
        subtitle: String,
    },
    UpdateDataModel {
        #[serde(rename = "surfaceId")]
        surface_id: String,
        path: String,
        value: Value,
    },
    UpdateComponents {
        #[serde(rename = "surfaceId")]
        surface_id: String,
        components: Vec<A2uiComponent>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2uiComponent {
    pub id: String,
    pub component: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub children: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub props: Map<String, Value>,
}

/// Optional lightweight patch block an external LLM may emit (` ```a2ui-patch `)
/// to customize the surface headline, summary banner, or checklist steps while
/// preserving Rust-verified live telemetry data bindings.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
struct LlmSurfacePatch {
    headline: Option<String>,
    subtitle: Option<String>,
    banner_title: Option<String>,
    banner_body: Option<String>,
    banner_tone: Option<String>,
    playbook: Vec<LlmPlaybookPatchItem>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
struct LlmPlaybookPatchItem {
    priority: Option<String>,
    title: String,
    detail: String,
    cve_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalystIntent {
    NetworkIoc,
    AiSupplyChain,
    KevRansomware,
    BreakingNews,
    StackExposure,
    CveDeepDive,
    ThreatOverview,
}

impl AnalystIntent {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NetworkIoc => "network_ioc",
            Self::AiSupplyChain => "ai_supply_chain",
            Self::KevRansomware => "kev_ransomware",
            Self::BreakingNews => "breaking_news",
            Self::StackExposure => "stack_exposure",
            Self::CveDeepDive => "cve_deep_dive",
            Self::ThreatOverview => "threat_overview",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::NetworkIoc => "Network Perimeter & IOC Surface",
            Self::AiSupplyChain => "AI / ML Supply-Chain Surface",
            Self::KevRansomware => "CISA KEV & Ransomware Surface",
            Self::BreakingNews => "Breaking Advisories & PoC Surface",
            Self::StackExposure => "My Stack Exposure Surface",
            Self::CveDeepDive => "CVE Investigation Surface",
            Self::ThreatOverview => "Interactive Threat Posture Surface",
        }
    }
}

fn has_word(lower_text: &str, word: &str) -> bool {
    lower_text
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|tok| tok == word)
}

pub fn classify_query_intent(query: &str, query_cves: &[String]) -> AnalystIntent {
    let q = query.to_ascii_lowercase();
    if !query_cves.is_empty() {
        return AnalystIntent::CveDeepDive;
    }
    if q.contains("my stack")
        || q.contains("stack exposure")
        || has_word(&q, "sbom")
        || q.contains("inventory")
        || q.contains("affected in our")
    {
        return AnalystIntent::StackExposure;
    }
    if has_word(&q, "port")
        || has_word(&q, "ports")
        || q.contains("botnet")
        || has_word(&q, "c2")
        || has_word(&q, "c2s")
        || q.contains("phish")
        || has_word(&q, "ioc")
        || has_word(&q, "iocs")
        || has_word(&q, "network")
        || q.contains("attacker ip")
    {
        return AnalystIntent::NetworkIoc;
    }
    if has_word(&q, "ai")
        || has_word(&q, "llm")
        || has_word(&q, "llms")
        || q.contains("pytorch")
        || q.contains("langchain")
        || has_word(&q, "mcp")
        || q.contains("vllm")
        || q.contains("pickle")
        || q.contains("mlops")
    {
        return AnalystIntent::AiSupplyChain;
    }
    if has_word(&q, "kev")
        || has_word(&q, "kevs")
        || q.contains("ransomware")
        || has_word(&q, "cisa")
        || q.contains("deadline")
        || q.contains("overdue")
    {
        return AnalystIntent::KevRansomware;
    }
    if q.contains("breaking")
        || has_word(&q, "news")
        || has_word(&q, "poc")
        || has_word(&q, "pocs")
        || q.contains("48 hour")
        || has_word(&q, "48h")
        || q.contains("advisories")
    {
        return AnalystIntent::BreakingNews;
    }
    AnalystIntent::ThreatOverview
}

fn path_ref(pointer: &str) -> Value {
    json!({ "@path": pointer })
}

fn clean_text(raw: &str, max_len: usize) -> String {
    let stripped = strip_invisible_unicode(raw);
    let trimmed = stripped.trim();
    if trimmed.chars().count() <= max_len {
        trimmed.to_string()
    } else {
        truncate_str(trimmed, max_len)
    }
}

fn target_label(v: &Vulnerability) -> String {
    match (&v.vendor, &v.product) {
        (Some(ven), Some(prod)) => format!("{ven} {prod}"),
        (Some(ven), None) => ven.clone(),
        (None, Some(prod)) => prod.clone(),
        (None, None) => v
            .ecosystem
            .clone()
            .unwrap_or_else(|| "Multiple / OSS".to_string()),
    }
}

fn vuln_to_row(v: &Vulnerability) -> Value {
    json!({
        "id": v.id,
        "title": clean_text(&v.title, 150),
        "target": clean_text(&target_label(v), 64),
        "severity": v.severity.as_str(),
        "aiRisk": v.ai_risk_score,
        "cvss": v.cvss_score,
        "epssPct": v.epss_score.map(|e| ((e * 1000.0).round()) / 10.0),
        "epssSpike": v.epss_spike,
        "isKev": v.is_kev,
        "kevDueDate": v.kev_due_date,
        "kevDaysRemaining": v.kev_days_remaining,
        "ransomware": v.ransomware_use,
        "isAi": v.is_ai_related,
        "hasExploit": v.has_public_exploit,
        "patchedVersion": v.patched_version,
        "matchedStack": v.matched_stack.iter().take(3).cloned().collect::<Vec<_>>(),
        "triageStatus": v.triage_status.as_str(),
        "vectors": v.attack_vectors.iter().take(2).cloned().collect::<Vec<_>>(),
    })
}

fn news_to_card(n: &ThreatNewsItem) -> Value {
    json!({
        "id": n.id,
        "source": clean_text(&n.source, 48),
        "category": clean_text(&n.category, 40),
        "title": clean_text(&n.title, 160),
        "summary": clean_text(&n.summary, 220),
        "url": n.url,
        "publishedAt": n.published_at.to_rfc3339(),
        "severity": n.severity.as_str(),
        "aiRisk": n.ai_risk_score,
        "cves": n.extracted_cves.iter().take(4).cloned().collect::<Vec<_>>(),
        "tags": n.tags.iter().take(4).cloned().collect::<Vec<_>>(),
    })
}

/// Optional helper to extract an LLM's ` ```a2ui-patch ... ``` ` block and return
/// `(markdown_without_patch_block, parsed_patch)`.
fn extract_llm_a2ui_patch(raw_md: &str) -> (String, Option<LlmSurfacePatch>) {
    let marker = "```a2ui-patch";
    let Some(start) = raw_md.find(marker) else {
        return (raw_md.to_string(), None);
    };
    let after_marker = &raw_md[start + marker.len()..];
    let Some(end_rel) = after_marker.find("```") else {
        return (raw_md.to_string(), None);
    };
    let json_body = after_marker[..end_rel].trim();
    let parsed = serde_json::from_str::<LlmSurfacePatch>(json_body).ok();
    let mut cleaned_md = String::with_capacity(raw_md.len());
    cleaned_md.push_str(raw_md[..start].trim_end());
    let rest = after_marker[end_rel + 3..].trim_start();
    if !rest.is_empty() {
        if !cleaned_md.is_empty() {
            cleaned_md.push_str("\n\n");
        }
        cleaned_md.push_str(rest);
    }
    (cleaned_md, parsed)
}

/// Builds a strictly validated, data-bound A2UI 1.0 SOC surface for an AI Threat Analyst query.
#[allow(clippy::too_many_arguments)]
pub fn build_analyst_a2ui_surface(
    query: &str,
    query_cves: &[String],
    store: &ThreatStore,
    top_vulns: &[&Vulnerability],
    top_news: &[&ThreatNewsItem],
    matched_vuln_count: usize,
    matched_news_count: usize,
    external_llm_markdown: Option<&str>,
    now: DateTime<Utc>,
) -> (A2uiSurfacePayload, Option<String>) {
    let intent = classify_query_intent(query, query_cves);
    let surface_id = format!("soc-surface-{}", &Uuid::new_v4().simple().to_string()[..8]);

    let (cleaned_llm_md, llm_patch) = match external_llm_markdown {
        Some(raw) => {
            let (stripped, patch) = extract_llm_a2ui_patch(raw);
            let sanitized = sanitize_llm_markdown(&stripped);
            (Some(sanitized), patch)
        }
        None => (None, None),
    };

    // Build intent-specific KPI metrics
    let matched_kev_count = top_vulns.iter().filter(|v| v.is_kev).count();
    let matched_ransomware = top_vulns.iter().filter(|v| v.ransomware_use).count();
    let matched_stack = top_vulns
        .iter()
        .filter(|v| !v.matched_stack.is_empty())
        .count();
    let max_risk = top_vulns.iter().map(|v| v.ai_risk_score).max().unwrap_or(0);
    let max_epss_pct = top_vulns
        .iter()
        .filter_map(|v| v.epss_score)
        .fold(0.0_f64, f64::max)
        * 100.0;
    let feeds_ok = store
        .feed_health
        .iter()
        .filter(|f| f.status == "OK")
        .count();
    let feeds_total = store.feed_health.len();

    let kpis = match intent {
        AnalystIntent::NetworkIoc => vec![
            json!({
                "label": "SANS INFOCON",
                "value": store.telemetry.infocon_status.to_ascii_uppercase(),
                "detail": "Global internet threat status",
                "tone": if store.telemetry.infocon_status.eq_ignore_ascii_case("green") { "mint" } else { "crit" },
            }),
            json!({
                "label": "ACTIVE BOTNET C2s",
                "value": store.telemetry.botnet_c2s.len().to_string(),
                "detail": "abuse.ch Feodo Tracker live",
                "tone": if !store.telemetry.botnet_c2s.is_empty() { "crit" } else { "neutral" },
            }),
            json!({
                "label": "PHISHING URLs",
                "value": store.telemetry.phishing_total_count.to_string(),
                "detail": "OpenPhish live feed",
                "tone": "warn",
            }),
            json!({
                "label": "COMPROMISED IPs",
                "value": store.telemetry.compromised_ips_total_count.to_string(),
                "detail": "Emerging Threats blocklist",
                "tone": "cyan",
            }),
        ],
        AnalystIntent::KevRansomware => {
            let overdue = top_vulns
                .iter()
                .filter(|v| v.kev_days_remaining.map(|d| d < 0).unwrap_or(false))
                .count();
            vec![
                json!({
                    "label": "MATCHED KEVs",
                    "value": matched_kev_count.to_string(),
                    "detail": format!("{} total matching CVEs", matched_vuln_count),
                    "tone": if matched_kev_count > 0 { "crit" } else { "neutral" },
                }),
                json!({
                    "label": "RANSOMWARE LINKED",
                    "value": matched_ransomware.to_string(),
                    "detail": "Known ransomware campaign use",
                    "tone": if matched_ransomware > 0 { "crit" } else { "warn" },
                }),
                json!({
                    "label": "KEV OVERDUE",
                    "value": overdue.to_string(),
                    "detail": "Past CISA BOD 22-01 due date",
                    "tone": if overdue > 0 { "crit" } else { "mint" },
                }),
                json!({
                    "label": "PEAK EPSS (30D)",
                    "value": format!("{:.1}%", max_epss_pct),
                    "detail": format!("Peak AI Risk {}/100", max_risk),
                    "tone": if max_epss_pct >= 50.0 { "warn" } else { "cyan" },
                }),
            ]
        }
        AnalystIntent::AiSupplyChain => {
            let ai_total = store
                .vulnerabilities
                .values()
                .filter(|v| v.is_ai_related)
                .count();
            let ai_pocs = top_vulns.iter().filter(|v| v.has_public_exploit).count();
            vec![
                json!({
                    "label": "AI/ML CVEs TRACKED",
                    "value": ai_total.to_string(),
                    "detail": format!("{} matched this query", matched_vuln_count),
                    "tone": "cyan",
                }),
                json!({
                    "label": "PEAK AI RISK",
                    "value": format!("{}/100", max_risk),
                    "detail": format!("{} CISA KEV active", matched_kev_count),
                    "tone": if max_risk >= 80 { "crit" } else { "warn" },
                }),
                json!({
                    "label": "PUBLIC EXPLOITS",
                    "value": ai_pocs.to_string(),
                    "detail": "PoC / active weaponization",
                    "tone": if ai_pocs > 0 { "warn" } else { "mint" },
                }),
                json!({
                    "label": "STACK HITS",
                    "value": matched_stack.to_string(),
                    "detail": "Matched in My Stack SBOM",
                    "tone": if matched_stack > 0 { "crit" } else { "neutral" },
                }),
            ]
        }
        AnalystIntent::BreakingNews => {
            let poc_news = top_news
                .iter()
                .filter(|n| {
                    n.category == "Exploit PoC"
                        || n.tags.iter().any(|t| t == "Exploit PoC" || t == "Zero-Day")
                })
                .count();
            vec![
                json!({
                    "label": "MATCHED ADVISORIES",
                    "value": matched_news_count.to_string(),
                    "detail": format!("Showing top {} reports", top_news.len()),
                    "tone": "cyan",
                }),
                json!({
                    "label": "EXPLOIT PoC / 0-DAY",
                    "value": poc_news.to_string(),
                    "detail": "In top correlated wire items",
                    "tone": if poc_news > 0 { "crit" } else { "warn" },
                }),
                json!({
                    "label": "LINKED CVEs",
                    "value": matched_vuln_count.to_string(),
                    "detail": format!("{} CISA KEV confirmed", matched_kev_count),
                    "tone": if matched_kev_count > 0 { "crit" } else { "warn" },
                }),
                json!({
                    "label": "LIVE FEEDS OK",
                    "value": format!("{}/{}", feeds_ok, feeds_total.max(1)),
                    "detail": format!("Threat Index {}/100", store.ai_brief.global_threat_index),
                    "tone": "mint",
                }),
            ]
        }
        _ => vec![
            json!({
                "label": "THREAT INDEX",
                "value": format!("{}/100", store.ai_brief.global_threat_index),
                "detail": store.ai_brief.threat_level_label.clone(),
                "tone": if store.ai_brief.global_threat_index >= 80 { "crit" } else if store.ai_brief.global_threat_index >= 60 { "warn" } else { "mint" },
            }),
            json!({
                "label": "MATCHED CVEs",
                "value": matched_vuln_count.to_string(),
                "detail": format!("{} KEV · {} Stack hits", matched_kev_count, matched_stack),
                "tone": if matched_kev_count > 0 { "crit" } else { "cyan" },
            }),
            json!({
                "label": "PEAK RISK / EPSS",
                "value": format!("{}/100", max_risk),
                "detail": format!("Max EPSS {:.1}%", max_epss_pct),
                "tone": if max_risk >= 85 { "crit" } else { "warn" },
            }),
            json!({
                "label": "CORRELATED INTEL",
                "value": matched_news_count.to_string(),
                "detail": format!("{}/{} active feeds", feeds_ok, feeds_total.max(1)),
                "tone": "mint",
            }),
        ],
    };

    // Build intent-adapted Recharts BarChart data
    let (chart_title, chart_subtitle, chart_unit, chart_accent, chart_series): (
        String,
        String,
        String,
        String,
        Vec<Value>,
    ) = if intent == AnalystIntent::NetworkIoc && !store.telemetry.top_attacked_ports.is_empty() {
        let series = store
            .telemetry
            .top_attacked_ports
            .iter()
            .take(6)
            .map(|p| {
                json!({
                    "name": format!("{}/{}", p.port, clean_text(&p.service_name, 12)),
                    "value": p.records,
                    "secondary": p.sources,
                    "detail": format!("{} distinct attacking source IPs", p.sources),
                })
            })
            .collect();
        (
            "Most Probed Internet Services (24h)".to_string(),
            "SANS ISC DShield attack record volume by destination port".to_string(),
            "records".to_string(),
            "orange".to_string(),
            series,
        )
    } else if !top_vulns.is_empty() {
        let series = top_vulns
            .iter()
            .take(6)
            .map(|v| {
                let epss_pct = (v.epss_score.unwrap_or(0.0) * 1000.0).round() / 10.0;
                json!({
                    "name": v.id,
                    "value": v.ai_risk_score,
                    "secondary": epss_pct,
                    "detail": format!(
                        "{} · CVSS {} · EPSS {:.1}%{}",
                        clean_text(&target_label(v), 28),
                        v.cvss_score.map(|c| format!("{c:.1}")).unwrap_or_else(|| "N/A".to_string()),
                        epss_pct,
                        if v.is_kev { " · KEV" } else { "" }
                    ),
                })
            })
            .collect();
        (
            "Priority CVE Risk & Exploitability Profile".to_string(),
            "AI Risk Score (0–100) across top matched vulnerabilities".to_string(),
            "pts".to_string(),
            if intent == AnalystIntent::KevRansomware {
                "red".to_string()
            } else if intent == AnalystIntent::AiSupplyChain {
                "cyan".to_string()
            } else {
                "mint".to_string()
            },
            series,
        )
    } else {
        let series = store
            .ai_brief
            .top_attack_vectors
            .iter()
            .take(6)
            .map(|v| {
                json!({
                    "name": clean_text(&v.label, 18),
                    "value": v.count,
                    "detail": format!("{} tracked CVEs in 7d window", v.count),
                })
            })
            .collect();
        (
            "Dominant Attack Vectors (7-Day Telemetry)".to_string(),
            "Distribution across live vulnerability feeds".to_string(),
            "CVEs".to_string(),
            "cyan".to_string(),
            series,
        )
    };

    // Build interactive Containment & Remediation Playbook
    let mut playbook: Vec<Value> = Vec::new();
    if let Some(patch) = &llm_patch {
        for (idx, item) in patch.playbook.iter().take(5).enumerate() {
            let title = clean_text(&item.title, 120);
            let detail = clean_text(&item.detail, 240);
            if title.is_empty() {
                continue;
            }
            let priority = match item
                .priority
                .as_deref()
                .unwrap_or("P1")
                .to_ascii_uppercase()
                .as_str()
            {
                "P0" => "P0",
                "P2" => "P2",
                _ => "P1",
            };
            let action = item.cve_id.as_ref().and_then(|cid| {
                let c = cid.trim().to_ascii_uppercase();
                if is_valid_vuln_id(&c) {
                    Some(json!({ "type": "open_cve", "label": format!("Inspect {c}"), "cveId": c }))
                } else {
                    None
                }
            });
            playbook.push(json!({
                "id": format!("step-llm-{idx}"),
                "priority": priority,
                "title": title,
                "detail": detail,
                "action": action,
            }));
        }
    }

    if playbook.is_empty() {
        if let Some(first_kev) = top_vulns.iter().find(|v| v.is_kev) {
            let due_s = first_kev
                .kev_due_date
                .as_deref()
                .map(|d| format!(" (CISA due {d})"))
                .unwrap_or_default();
            playbook.push(json!({
                "id": "step-kev",
                "priority": "P0",
                "title": format!("Patch or isolate {} immediately{}", first_kev.id, due_s),
                "detail": clean_text(
                    first_kev
                        .kev_required_action
                        .as_deref()
                        .unwrap_or("Confirmed active exploitation in CISA KEV catalog; apply vendor fix or isolate perimeter exposure."),
                    200
                ),
                "action": { "type": "open_cve", "label": format!("Inspect {}", first_kev.id), "cveId": first_kev.id },
            }));
        } else if let Some(first_v) = top_vulns.first() {
            let patch_hint = first_v
                .patched_version
                .as_deref()
                .map(|p| format!("Upgrade {} to version {}.", target_label(first_v), p))
                .unwrap_or_else(|| {
                    format!(
                        "Verify {} exposure and apply vendor advisory or WAF compensating rules.",
                        target_label(first_v)
                    )
                });
            playbook.push(json!({
                "id": "step-top-cve",
                "priority": "P0",
                "title": format!("Triage top-risk {} ({}/100)", first_v.id, first_v.ai_risk_score),
                "detail": clean_text(&patch_hint, 200),
                "action": { "type": "open_cve", "label": format!("Inspect {}", first_v.id), "cveId": first_v.id },
            }));
        }

        if intent == AnalystIntent::AiSupplyChain || top_vulns.iter().any(|v| v.is_ai_related) {
            playbook.push(json!({
                "id": "step-ai-deps",
                "priority": "P1",
                "title": "Audit AI/ML dependencies & untrusted model loading",
                "detail": "Pin PyTorch, LangChain, vLLM, and MCP server packages; disable pickle deserialization and verify SBOM matches in My Stack.",
                "action": { "type": "navigate_tab", "label": "Open My Stack", "tab": "mystack" },
            }));
        } else {
            playbook.push(json!({
                "id": "step-stack-check",
                "priority": "P1",
                "title": "Cross-check matched CVEs against your local SBOM",
                "detail": "Correlate affected vendors, packages, and versions against My Stack to isolate exposed production hosts.",
                "action": { "type": "navigate_tab", "label": "Open My Stack", "tab": "mystack" },
            }));
        }

        if intent == AnalystIntent::NetworkIoc || !store.telemetry.botnet_c2s.is_empty() {
            playbook.push(json!({
                "id": "step-ioc-block",
                "priority": if intent == AnalystIntent::NetworkIoc { "P0" } else { "P2" },
                "title": format!(
                    "Enforce perimeter blocks on {} active C2s & top probed ports",
                    store.telemetry.botnet_c2s.len()
                ),
                "detail": "Export EDL/nftables/pf blocklists from Network IOCs and hunt outbound egress logs for C2 beaconing.",
                "action": { "type": "navigate_tab", "label": "Open Network IOCs", "tab": "network" },
            }));
        }

        if let Some(first_v) = top_vulns.first() {
            playbook.push(json!({
                "id": "step-stix",
                "priority": "P2",
                "title": format!("Share STIX 2.1 bundle for {} with SIEM / SOAR", first_v.id),
                "detail": "Export structured STIX 2.1 intelligence for automated detection engineering and incident tracking.",
                "action": { "type": "export_stix", "label": "Export STIX 2.1", "cveId": first_v.id },
            }));
        }
    }

    // Build alert banner when high-urgency signals are present (or LLM supplied one)
    let mut banner_data: Option<Value> = None;
    if let Some(patch) = &llm_patch {
        if let Some(bt) = patch.banner_title.as_deref().map(str::trim) {
            if !bt.is_empty() {
                let tone = match patch
                    .banner_tone
                    .as_deref()
                    .unwrap_or("info")
                    .to_ascii_lowercase()
                    .as_str()
                {
                    "error" | "critical" => "error",
                    "warning" | "warn" => "warning",
                    "success" => "success",
                    _ => "info",
                };
                banner_data = Some(json!({
                    "tone": tone,
                    "badge": intent.label().to_ascii_uppercase(),
                    "title": clean_text(bt, 160),
                    "body": clean_text(patch.banner_body.as_deref().unwrap_or(""), 260),
                }));
            }
        }
    }
    if banner_data.is_none() {
        if matched_stack > 0 {
            let first_stack_cve = top_vulns
                .iter()
                .find(|v| !v.matched_stack.is_empty())
                .map(|v| v.id.clone());
            banner_data = Some(json!({
                "tone": "warning",
                "badge": "MY STACK EXPOSURE",
                "title": format!("{} matched CVEs overlap your local software inventory", matched_stack),
                "body": "Prioritize stack-matched CVEs below — click Inspect or set Triage status directly from this interactive surface.",
                "action": first_stack_cve.map(|id| json!({ "type": "open_cve", "label": format!("Inspect {id}"), "cveId": id })),
            }));
        } else if matched_kev_count > 0 && intent == AnalystIntent::KevRansomware {
            let first_kev = top_vulns.iter().find(|v| v.is_kev).map(|v| v.id.clone());
            banner_data = Some(json!({
                "tone": "error",
                "badge": "ACTIVE EXPLOITATION · CISA KEV",
                "title": format!("{} matched CISA KEV entries ({} ransomware-linked)", matched_kev_count, matched_ransomware),
                "body": "Active in-the-wild exploitation confirmed. Use one-click triage and STIX 2.1 actions below to track remediation.",
                "action": first_kev.map(|id| json!({ "type": "open_cve", "label": format!("Inspect {id}"), "cveId": id })),
            }));
        }
    }

    // Network telemetry snapshot for IocPanel (OPSEC-redacted client-side when OPSEC Mode is on)
    let c2_rows: Vec<Value> = store
        .telemetry
        .botnet_c2s
        .iter()
        .take(6)
        .map(|c| {
            json!({
                "ip": c.ip_address,
                "port": c.port,
                "malware": clean_text(&c.malware, 32),
                "country": c.country.as_deref().unwrap_or("--"),
                "status": c.status,
                "hostname": c.hostname,
            })
        })
        .collect();
    let port_rows: Vec<Value> = store
        .telemetry
        .top_attacked_ports
        .iter()
        .take(6)
        .map(|p| {
            json!({
                "port": p.port,
                "service": clean_text(&p.service_name, 24),
                "records": p.records,
                "sources": p.sources,
            })
        })
        .collect();

    let vuln_rows: Vec<Value> = top_vulns.iter().map(|v| vuln_to_row(v)).collect();
    let news_cards: Vec<Value> = top_news.iter().map(|n| news_to_card(n)).collect();

    let mut data_model = json!({
        "query": clean_text(query, 200),
        "generatedAt": now.to_rfc3339(),
        "kpis": kpis,
        "chart": {
            "series": chart_series,
        },
        "vulns": vuln_rows,
        "news": news_cards,
        "playbook": playbook,
        "network": {
            "infocon": store.telemetry.infocon_status.to_ascii_uppercase(),
            "phishingTotal": store.telemetry.phishing_total_count,
            "compromisedIpsTotal": store.telemetry.compromised_ips_total_count,
            "c2s": c2_rows,
            "ports": port_rows,
        },
    });
    if let Some(banner) = &banner_data {
        data_model["banner"] = banner.clone();
    }
    if let Some(llm_md) = &cleaned_llm_md {
        data_model["brief"] = json!({
            "markdown": llm_md,
        });
    }

    // Compose flat A2UI 1.0 component graph adapted to intent
    let mut components: Vec<A2uiComponent> = Vec::new();
    let mut root_children: Vec<String> = Vec::new();

    if banner_data.is_some() {
        root_children.push("urgent-banner".to_string());
        let mut props = Map::new();
        props.insert("data".to_string(), path_ref("/banner"));
        components.push(A2uiComponent {
            id: "urgent-banner".to_string(),
            component: "Banner".to_string(),
            children: None,
            props,
        });
    }

    // Always include KPI Strip at top
    root_children.push("kpi-strip".to_string());
    {
        let mut props = Map::new();
        props.insert("items".to_string(), path_ref("/kpis"));
        components.push(A2uiComponent {
            id: "kpi-strip".to_string(),
            component: "KpiStrip".to_string(),
            children: None,
            props,
        });
    }

    // If an external LLM produced synthesis prose, surface it directly inside the A2UI layout
    if cleaned_llm_md.is_some() {
        root_children.push("llm-brief".to_string());
        let mut props = Map::new();
        props.insert("title".to_string(), json!("AI Model Executive Synthesis"));
        props.insert("markdown".to_string(), path_ref("/brief/markdown"));
        components.push(A2uiComponent {
            id: "llm-brief".to_string(),
            component: "ExecutiveBrief".to_string(),
            children: None,
            props,
        });
    }

    // Intent-driven primary widgets
    if intent == AnalystIntent::NetworkIoc {
        // SplitGrid: Ports Chart + Playbook, then IOC Panel, then optional VulnTable
        let mut split_children = Vec::new();
        if !store.telemetry.top_attacked_ports.is_empty() {
            split_children.push("primary-chart".to_string());
            let mut props = Map::new();
            props.insert("title".to_string(), json!(chart_title));
            props.insert("subtitle".to_string(), json!(chart_subtitle));
            props.insert("unit".to_string(), json!(chart_unit));
            props.insert("accent".to_string(), json!(chart_accent));
            props.insert("data".to_string(), path_ref("/chart/series"));
            components.push(A2uiComponent {
                id: "primary-chart".to_string(),
                component: "BarChart".to_string(),
                children: None,
                props,
            });
        }
        split_children.push("remediation-playbook".to_string());
        {
            let mut props = Map::new();
            props.insert("title".to_string(), json!("Perimeter Containment Playbook"));
            props.insert("items".to_string(), path_ref("/playbook"));
            components.push(A2uiComponent {
                id: "remediation-playbook".to_string(),
                component: "ActionChecklist".to_string(),
                children: None,
                props,
            });
        }
        root_children.push("split-top".to_string());
        components.push(A2uiComponent {
            id: "split-top".to_string(),
            component: "SplitGrid".to_string(),
            children: Some(split_children),
            props: Map::new(),
        });

        root_children.push("ioc-panel".to_string());
        {
            let mut props = Map::new();
            props.insert(
                "title".to_string(),
                json!("Live Botnet C2 & Port Telemetry"),
            );
            props.insert("data".to_string(), path_ref("/network"));
            components.push(A2uiComponent {
                id: "ioc-panel".to_string(),
                component: "IocPanel".to_string(),
                children: None,
                props,
            });
        }

        if !top_vulns.is_empty() {
            root_children.push("vuln-table".to_string());
            let mut props = Map::new();
            props.insert(
                "title".to_string(),
                json!("Correlated Network Vulnerabilities"),
            );
            props.insert("rows".to_string(), path_ref("/vulns"));
            components.push(A2uiComponent {
                id: "vuln-table".to_string(),
                component: "VulnTable".to_string(),
                children: None,
                props,
            });
        }
    } else if intent == AnalystIntent::BreakingNews {
        if !top_news.is_empty() {
            root_children.push("news-feed".to_string());
            let mut props = Map::new();
            props.insert(
                "title".to_string(),
                json!("Breaking Exploit PoCs & Security Advisories"),
            );
            props.insert("items".to_string(), path_ref("/news"));
            components.push(A2uiComponent {
                id: "news-feed".to_string(),
                component: "NewsFeed".to_string(),
                children: None,
                props,
            });
        }
        if !top_vulns.is_empty() {
            root_children.push("vuln-table".to_string());
            let mut props = Map::new();
            props.insert(
                "title".to_string(),
                json!("Extracted & Correlated Priority CVEs"),
            );
            props.insert("rows".to_string(), path_ref("/vulns"));
            components.push(A2uiComponent {
                id: "vuln-table".to_string(),
                component: "VulnTable".to_string(),
                children: None,
                props,
            });
        }
        root_children.push("remediation-playbook".to_string());
        {
            let mut props = Map::new();
            props.insert("title".to_string(), json!("SOC Hunting & Triage Checklist"));
            props.insert("items".to_string(), path_ref("/playbook"));
            components.push(A2uiComponent {
                id: "remediation-playbook".to_string(),
                component: "ActionChecklist".to_string(),
                children: None,
                props,
            });
        }
    } else {
        // Default / KEV / AI Supply-Chain / Stack / CVE Deep-Dive layout
        if !top_vulns.is_empty() {
            root_children.push("vuln-table".to_string());
            let mut props = Map::new();
            let table_title = match intent {
                AnalystIntent::AiSupplyChain => "Active AI / ML Supply-Chain Vulnerabilities",
                AnalystIntent::KevRansomware => "CISA KEV & Ransomware-Linked Vulnerabilities",
                AnalystIntent::StackExposure => "Vulnerabilities Impacting Your Stack",
                AnalystIntent::CveDeepDive => "Matched CVE Dossiers & Quick Triage",
                _ => "Priority Vulnerabilities (Interactive Triage)",
            };
            props.insert("title".to_string(), json!(table_title));
            props.insert("rows".to_string(), path_ref("/vulns"));
            components.push(A2uiComponent {
                id: "vuln-table".to_string(),
                component: "VulnTable".to_string(),
                children: None,
                props,
            });
        }

        // SplitGrid: Risk BarChart + Interactive Remediation Playbook
        let mut split_children = Vec::new();
        split_children.push("primary-chart".to_string());
        {
            let mut props = Map::new();
            props.insert("title".to_string(), json!(chart_title));
            props.insert("subtitle".to_string(), json!(chart_subtitle));
            props.insert("unit".to_string(), json!(chart_unit));
            props.insert("accent".to_string(), json!(chart_accent));
            props.insert("data".to_string(), path_ref("/chart/series"));
            components.push(A2uiComponent {
                id: "primary-chart".to_string(),
                component: "BarChart".to_string(),
                children: None,
                props,
            });
        }
        split_children.push("remediation-playbook".to_string());
        {
            let mut props = Map::new();
            props.insert(
                "title".to_string(),
                json!("Recommended Containment Playbook"),
            );
            props.insert("items".to_string(), path_ref("/playbook"));
            components.push(A2uiComponent {
                id: "remediation-playbook".to_string(),
                component: "ActionChecklist".to_string(),
                children: None,
                props,
            });
        }
        root_children.push("split-mid".to_string());
        components.push(A2uiComponent {
            id: "split-mid".to_string(),
            component: "SplitGrid".to_string(),
            children: Some(split_children),
            props: Map::new(),
        });

        if !top_news.is_empty() {
            root_children.push("news-feed".to_string());
            let mut props = Map::new();
            props.insert(
                "title".to_string(),
                json!("Correlated Reports & Advisories"),
            );
            props.insert("items".to_string(), path_ref("/news"));
            components.push(A2uiComponent {
                id: "news-feed".to_string(),
                component: "NewsFeed".to_string(),
                children: None,
                props,
            });
        } else if !store.telemetry.botnet_c2s.is_empty() {
            root_children.push("ioc-panel".to_string());
            let mut props = Map::new();
            props.insert("title".to_string(), json!("Live Network & C2 Telemetry"));
            props.insert("data".to_string(), path_ref("/network"));
            components.push(A2uiComponent {
                id: "ioc-panel".to_string(),
                component: "IocPanel".to_string(),
                children: None,
                props,
            });
        }
    }

    // Bottom quick-navigation ActionBar
    root_children.push("quick-actions".to_string());
    {
        let mut actions = vec![
            json!({ "type": "navigate_tab", "label": "All Vulnerabilities", "tab": "vulnerabilities" }),
            json!({ "type": "navigate_tab", "label": "My Stack Exposure", "tab": "mystack" }),
            json!({ "type": "navigate_tab", "label": "Network IOCs", "tab": "network" }),
            json!({ "type": "navigate_tab", "label": "News & Advisories", "tab": "news" }),
        ];
        if let Some(first_v) = top_vulns.first() {
            actions.insert(
                0,
                json!({ "type": "export_stix", "label": format!("Export {} STIX 2.1", first_v.id), "cveId": first_v.id }),
            );
        }
        let mut props = Map::new();
        props.insert("actions".to_string(), Value::Array(actions));
        components.push(A2uiComponent {
            id: "quick-actions".to_string(),
            component: "ActionBar".to_string(),
            children: None,
            props,
        });
    }

    // Root Column container
    components.insert(
        0,
        A2uiComponent {
            id: "root".to_string(),
            component: "Column".to_string(),
            children: Some(root_children),
            props: Map::new(),
        },
    );

    let title = llm_patch
        .as_ref()
        .and_then(|p| p.headline.as_deref())
        .map(|s| clean_text(s, 110))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| intent.label().to_string());

    let subtitle = llm_patch
        .as_ref()
        .and_then(|p| p.subtitle.as_deref())
        .map(|s| clean_text(s, 160))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            format!(
                "Query: \"{}\" · {} CVEs & {} advisories correlated across {}/{} feeds",
                truncate_str(query, 68),
                matched_vuln_count,
                matched_news_count,
                feeds_ok,
                feeds_total.max(1)
            )
        });

    let raw_payload = A2uiSurfacePayload {
        version: A2UI_PROTOCOL_VERSION.to_string(),
        surface_id: surface_id.clone(),
        catalog_id: A2UI_CATALOG_ID.to_string(),
        intent: intent.as_str().to_string(),
        messages: vec![
            A2uiServerMessage::CreateSurface {
                surface_id: surface_id.clone(),
                catalog_id: A2UI_CATALOG_ID.to_string(),
                root_component_id: "root".to_string(),
                title,
                subtitle,
            },
            A2uiServerMessage::UpdateDataModel {
                surface_id: surface_id.clone(),
                path: "/".to_string(),
                value: data_model,
            },
            A2uiServerMessage::UpdateComponents {
                surface_id,
                components,
            },
        ],
    };

    let validated = validate_and_sanitize_a2ui(raw_payload)
        .expect("internal Rust A2UI builder always emits a valid catalog payload");
    (validated, cleaned_llm_md)
}

/// Builds a compact, interactive A2UI 1.0 Deep Triage surface for a single CVE inside `InvestigationDrawer`.
pub fn build_vuln_triage_a2ui_surface(
    vuln: &Vulnerability,
    related_news: &[&ThreatNewsItem],
    synthesis_markdown: Option<&str>,
    now: DateTime<Utc>,
) -> A2uiSurfacePayload {
    let surface_id = format!(
        "triage-surface-{}",
        &Uuid::new_v4().simple().to_string()[..8]
    );
    let target = target_label(vuln);

    let factor_series: Vec<Value> = vuln
        .ai_score_factors
        .iter()
        .take(6)
        .map(|f| {
            json!({
                "name": clean_text(&f.label, 22),
                "value": f.points,
                "detail": clean_text(&f.detail, 120),
            })
        })
        .collect();

    let mut playbook: Vec<Value> = Vec::new();
    if let Some(action) = &vuln.kev_required_action {
        playbook.push(json!({
            "id": "triage-kev",
            "priority": "P0",
            "title": format!(
                "Execute CISA KEV Mandate{}",
                vuln.kev_due_date.as_deref().map(|d| format!(" (Due {d})")).unwrap_or_default()
            ),
            "detail": clean_text(action, 200),
            "action": { "type": "set_triage", "label": "Mark Investigating", "cveId": vuln.id, "status": "investigating" },
        }));
    }
    if let Some(patched) = &vuln.patched_version {
        playbook.push(json!({
            "id": "triage-upgrade",
            "priority": "P0",
            "title": format!("Upgrade {} to version {}", clean_text(&target, 48), clean_text(patched, 32)),
            "detail": "Deploy patched build and verify dependency lockfiles / container layers.",
            "action": { "type": "copy_text", "label": "Copy Version", "text": patched },
        }));
    } else {
        playbook.push(json!({
            "id": "triage-mitigate",
            "priority": "P1",
            "title": format!("Apply vendor advisory & compensating WAF/ACL controls for {}", clean_text(&target, 48)),
            "detail": "Restrict untrusted network ingress and monitor logs for exploit indicators.",
            "action": { "type": "set_triage", "label": "Mark Mitigated", "cveId": vuln.id, "status": "mitigated" },
        }));
    }
    if vuln.is_ai_related {
        playbook.push(json!({
            "id": "triage-ai",
            "priority": "P1",
            "title": "Audit AI/ML model loaders & MCP/agent dependencies",
            "detail": "Verify no untrusted weights, pickle files, or unpinned inference servers remain exposed.",
            "action": { "type": "navigate_tab", "label": "Open My Stack", "tab": "mystack" },
        }));
    }
    playbook.push(json!({
        "id": "triage-export",
        "priority": "P2",
        "title": "Package STIX 2.1 / Markdown dossier for incident ticket",
        "detail": "Attach machine-readable threat intel to Jira, ServiceNow, or SIEM hunting rules.",
        "action": { "type": "export_stix", "label": "Export STIX 2.1", "cveId": vuln.id },
    }));

    let mut data_model = json!({
        "generatedAt": now.to_rfc3339(),
        "chart": { "series": factor_series },
        "playbook": playbook,
        "news": related_news.iter().take(3).map(|n| news_to_card(n)).collect::<Vec<_>>(),
    });
    if let Some(md) = synthesis_markdown {
        data_model["brief"] = json!({ "markdown": sanitize_llm_markdown(md) });
    }

    let mut root_children: Vec<String> = Vec::new();
    let mut components: Vec<A2uiComponent> = Vec::new();

    if synthesis_markdown.is_some() {
        root_children.push("triage-brief".to_string());
        let mut props = Map::new();
        props.insert("title".to_string(), json!("Deep AI Triage Synthesis"));
        props.insert("markdown".to_string(), path_ref("/brief/markdown"));
        components.push(A2uiComponent {
            id: "triage-brief".to_string(),
            component: "ExecutiveBrief".to_string(),
            children: None,
            props,
        });
    }

    if !vuln.ai_score_factors.is_empty() {
        root_children.push("factor-chart".to_string());
        let mut props = Map::new();
        props.insert("title".to_string(), json!("AI Risk Factor Attribution"));
        props.insert(
            "subtitle".to_string(),
            json!(format!(
                "Total AI Risk {}/100 ({})",
                vuln.ai_risk_score,
                vuln.severity.as_str()
            )),
        );
        props.insert("unit".to_string(), json!("pts"));
        props.insert(
            "accent".to_string(),
            json!(if vuln.ai_risk_score >= 85 {
                "red"
            } else {
                "mint"
            }),
        );
        props.insert("data".to_string(), path_ref("/chart/series"));
        components.push(A2uiComponent {
            id: "factor-chart".to_string(),
            component: "BarChart".to_string(),
            children: None,
            props,
        });
    }

    root_children.push("triage-playbook".to_string());
    {
        let mut props = Map::new();
        props.insert(
            "title".to_string(),
            json!("Interactive Remediation Checklist"),
        );
        props.insert("items".to_string(), path_ref("/playbook"));
        components.push(A2uiComponent {
            id: "triage-playbook".to_string(),
            component: "ActionChecklist".to_string(),
            children: None,
            props,
        });
    }

    root_children.push("triage-actions".to_string());
    {
        let mut props = Map::new();
        props.insert(
            "actions".to_string(),
            json!([
                { "type": "set_triage", "label": "Set Investigating", "cveId": vuln.id, "status": "investigating" },
                { "type": "set_triage", "label": "Set Mitigated", "cveId": vuln.id, "status": "mitigated" },
                { "type": "export_stix", "label": "STIX 2.1", "cveId": vuln.id },
                { "type": "export_md", "label": "Markdown", "cveId": vuln.id },
            ]),
        );
        components.push(A2uiComponent {
            id: "triage-actions".to_string(),
            component: "ActionBar".to_string(),
            children: None,
            props,
        });
    }

    components.insert(
        0,
        A2uiComponent {
            id: "root".to_string(),
            component: "Column".to_string(),
            children: Some(root_children),
            props: Map::new(),
        },
    );

    let payload = A2uiSurfacePayload {
        version: A2UI_PROTOCOL_VERSION.to_string(),
        surface_id: surface_id.clone(),
        catalog_id: A2UI_CATALOG_ID.to_string(),
        intent: "cve_triage".to_string(),
        messages: vec![
            A2uiServerMessage::CreateSurface {
                surface_id: surface_id.clone(),
                catalog_id: A2UI_CATALOG_ID.to_string(),
                root_component_id: "root".to_string(),
                title: format!("Deep Triage — {}", vuln.id),
                subtitle: clean_text(&target, 90),
            },
            A2uiServerMessage::UpdateDataModel {
                surface_id: surface_id.clone(),
                path: "/".to_string(),
                value: data_model,
            },
            A2uiServerMessage::UpdateComponents {
                surface_id,
                components,
            },
        ],
    };

    validate_and_sanitize_a2ui(payload)
        .expect("internal Rust CVE triage A2UI builder always emits a valid payload")
}

/// Optional instruction suffix appended when calling an external LLM so capable models
/// can optionally tailor the interactive A2UI headline/banner/playbook while keeping all
/// CVE telemetry strictly Rust-verified.
pub const EXTERNAL_LLM_A2UI_HINT: &str = "OPTIONAL A2UI STRUCTURED PATCH: After your concise Markdown analysis, you may optionally append one fenced ```a2ui-patch JSON block with keys {\"headline\": string, \"banner_title\": string, \"banner_body\": string, \"banner_tone\": \"info\"|\"warning\"|\"error\", \"playbook\": [{\"priority\": \"P0\"|\"P1\"|\"P2\", \"title\": string, \"detail\": string, \"cve_id\": \"CVE-...\"}]} (max 4 playbook items). Never include HTML or scripts.";

fn is_valid_vuln_id(id: &str) -> bool {
    let trimmed = id.trim();
    if trimmed.len() < 4 || trimmed.len() > 40 {
        return false;
    }
    trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

fn sanitize_action_value(val: &Value) -> Option<Value> {
    let obj = val.as_object()?;
    let action_type = obj.get("type")?.as_str()?.trim();
    if !ALLOWED_ACTIONS.contains(&action_type) {
        return None;
    }
    let label = obj
        .get("label")
        .and_then(Value::as_str)
        .map(|s| clean_text(s, 64))
        .unwrap_or_else(|| action_type.to_string());

    match action_type {
        "open_cve" | "export_stix" | "export_md" => {
            let cve_id = obj.get("cveId")?.as_str()?.trim();
            if !is_valid_vuln_id(cve_id) {
                return None;
            }
            Some(json!({ "type": action_type, "label": label, "cveId": cve_id }))
        }
        "set_triage" => {
            let cve_id = obj.get("cveId")?.as_str()?.trim();
            let status = obj.get("status")?.as_str()?.trim().to_ascii_lowercase();
            if !is_valid_vuln_id(cve_id) || !ALLOWED_TRIAGE_STATUSES.contains(&status.as_str()) {
                return None;
            }
            Some(json!({
                "type": "set_triage",
                "label": label,
                "cveId": cve_id,
                "status": status,
            }))
        }
        "navigate_tab" => {
            let tab = obj.get("tab")?.as_str()?.trim().to_ascii_lowercase();
            if !ALLOWED_TABS.contains(&tab.as_str()) {
                return None;
            }
            Some(json!({ "type": "navigate_tab", "label": label, "tab": tab }))
        }
        "copy_text" => {
            let text = clean_text(obj.get("text")?.as_str()?, 512);
            if text.is_empty() {
                return None;
            }
            Some(json!({ "type": "copy_text", "label": label, "text": text }))
        }
        _ => None,
    }
}

fn sanitize_json_value(val: Value, depth: usize, preserve_markdown: bool) -> Value {
    if depth >= MAX_JSON_DEPTH {
        return Value::Null;
    }
    match val {
        Value::String(s) => {
            let cleaned = if preserve_markdown {
                sanitize_llm_markdown(&s)
            } else {
                let no_inv = strip_invisible_unicode(&s);
                let trimmed = no_inv.trim();
                let lower = trimmed.to_ascii_lowercase();
                if lower.starts_with("javascript:")
                    || lower.starts_with("data:")
                    || lower.starts_with("vbscript:")
                {
                    "[blocked-uri]".to_string()
                } else {
                    trimmed.to_string()
                }
            };
            if cleaned.chars().count() > MAX_STRING_LEN {
                Value::String(truncate_str(&cleaned, MAX_STRING_LEN))
            } else {
                Value::String(cleaned)
            }
        }
        Value::Array(arr) => Value::Array(
            arr.into_iter()
                .take(MAX_ARRAY_ITEMS)
                .map(|v| sanitize_json_value(v, depth + 1, preserve_markdown))
                .collect(),
        ),
        Value::Object(map) => {
            let mut out = Map::new();
            for (k, v) in map {
                let key = clean_text(&k, 64);
                if key.is_empty() {
                    continue;
                }
                if key == "action" {
                    if let Some(safe_act) = sanitize_action_value(&v) {
                        out.insert(key, safe_act);
                    }
                    continue;
                }
                if key == "actions" {
                    if let Value::Array(acts) = v {
                        let safe_acts: Vec<Value> = acts
                            .iter()
                            .take(12)
                            .filter_map(sanitize_action_value)
                            .collect();
                        out.insert(key, Value::Array(safe_acts));
                    }
                    continue;
                }
                let is_md = key == "markdown";
                out.insert(key, sanitize_json_value(v, depth + 1, is_md));
            }
            Value::Object(out)
        }
        other => other,
    }
}

/// Strictly validates and sanitizes an A2UI 1.0 payload against the `aibrainworx.soc.v1`
/// security catalog: checks protocol version, catalog ID, component allowlist, action allowlist,
/// max component count, acyclic/valid references, and strips dangerous URIs/invisible Unicode.
pub fn validate_and_sanitize_a2ui(
    mut payload: A2uiSurfacePayload,
) -> Result<A2uiSurfacePayload, String> {
    if payload.version != A2UI_PROTOCOL_VERSION {
        return Err(format!(
            "Unsupported A2UI protocol version: {}",
            payload.version
        ));
    }
    if payload.catalog_id != A2UI_CATALOG_ID {
        return Err(format!("Untrusted A2UI catalog ID: {}", payload.catalog_id));
    }
    if payload.surface_id.trim().is_empty() {
        return Err("Missing A2UI surface_id".to_string());
    }

    let mut has_create = false;
    let mut root_id = String::new();
    let mut sanitized_messages = Vec::with_capacity(payload.messages.len());

    for msg in payload.messages.drain(..) {
        match msg {
            A2uiServerMessage::CreateSurface {
                surface_id,
                catalog_id,
                root_component_id,
                title,
                subtitle,
            } => {
                if catalog_id != A2UI_CATALOG_ID {
                    return Err(format!(
                        "Untrusted catalogId in createSurface: {catalog_id}"
                    ));
                }
                has_create = true;
                root_id = clean_text(&root_component_id, 64);
                sanitized_messages.push(A2uiServerMessage::CreateSurface {
                    surface_id: clean_text(&surface_id, 64),
                    catalog_id,
                    root_component_id: root_id.clone(),
                    title: clean_text(&title, 120),
                    subtitle: clean_text(&subtitle, 220),
                });
            }
            A2uiServerMessage::UpdateDataModel {
                surface_id,
                path,
                value,
            } => {
                let clean_path = if path.starts_with('/') {
                    clean_text(&path, 128)
                } else {
                    "/".to_string()
                };
                sanitized_messages.push(A2uiServerMessage::UpdateDataModel {
                    surface_id: clean_text(&surface_id, 64),
                    path: clean_path,
                    value: sanitize_json_value(value, 0, false),
                });
            }
            A2uiServerMessage::UpdateComponents {
                surface_id,
                components,
            } => {
                let mut valid_components = Vec::new();
                let mut seen_ids = HashSet::new();
                for comp in components.into_iter().take(MAX_COMPONENTS) {
                    let comp_type = comp.component.trim();
                    if !ALLOWED_COMPONENTS.contains(&comp_type) {
                        continue;
                    }
                    let id = clean_text(&comp.id, 64);
                    if id.is_empty() || !seen_ids.insert(id.clone()) {
                        continue;
                    }
                    let sanitized_props =
                        match sanitize_json_value(Value::Object(comp.props), 0, false) {
                            Value::Object(m) => m,
                            _ => Map::new(),
                        };
                    let children = comp.children.map(|kids| {
                        kids.into_iter()
                            .take(24)
                            .map(|c| clean_text(&c, 64))
                            .filter(|c| !c.is_empty() && c != &id)
                            .collect::<Vec<_>>()
                    });
                    valid_components.push(A2uiComponent {
                        id,
                        component: comp_type.to_string(),
                        children,
                        props: sanitized_props,
                    });
                }

                // Prune dangling child references & detect cycles from root
                let id_set: HashSet<String> =
                    valid_components.iter().map(|c| c.id.clone()).collect();
                for c in &mut valid_components {
                    if let Some(kids) = &mut c.children {
                        kids.retain(|k| id_set.contains(k));
                    }
                }
                if !root_id.is_empty() && !id_set.contains(&root_id) {
                    return Err(
                        "A2UI rootComponentId missing from validated components".to_string()
                    );
                }

                // Ensure graph reachable from root is acyclic
                let children_map: HashMap<&str, Vec<&str>> = valid_components
                    .iter()
                    .map(|c| {
                        (
                            c.id.as_str(),
                            c.children
                                .as_deref()
                                .unwrap_or(&[])
                                .iter()
                                .map(String::as_str)
                                .collect(),
                        )
                    })
                    .collect();
                if !root_id.is_empty()
                    && has_cycle(
                        &root_id,
                        &children_map,
                        &mut HashSet::new(),
                        &mut HashSet::new(),
                    )
                {
                    return Err("A2UI component graph contains a cycle".to_string());
                }

                sanitized_messages.push(A2uiServerMessage::UpdateComponents {
                    surface_id: clean_text(&surface_id, 64),
                    components: valid_components,
                });
            }
        }
    }

    if !has_create {
        return Err("A2UI payload missing createSurface message".to_string());
    }

    payload.messages = sanitized_messages;
    Ok(payload)
}

fn has_cycle<'a>(
    node: &'a str,
    adj: &HashMap<&'a str, Vec<&'a str>>,
    visiting: &mut HashSet<&'a str>,
    visited: &mut HashSet<&'a str>,
) -> bool {
    if visited.contains(node) {
        return false;
    }
    if !visiting.insert(node) {
        return true;
    }
    if let Some(neighbors) = adj.get(node) {
        for next in neighbors {
            if has_cycle(next, adj, visiting, visited) {
                return true;
            }
        }
    }
    visiting.remove(node);
    visited.insert(node);
    false
}

/// Resolves an RFC 6901 JSON Pointer (`@path`, e.g. `/vulns/0/id`) against a `dataModel`.
#[cfg(test)]
pub fn resolve_json_pointer<'a>(root: &'a Value, pointer: &str) -> Option<&'a Value> {
    if pointer.is_empty() || pointer == "/" {
        return Some(root);
    }
    root.pointer(pointer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{BotnetC2, PortAttack, ScoreFactor, Severity, TriageStatus};

    fn sample_store() -> ThreatStore {
        let mut store = ThreatStore::default();
        let now = Utc::now();
        store.ai_brief.global_threat_index = 84;
        store.ai_brief.threat_level_label = "CRITICAL".to_string();
        store.telemetry.infocon_status = "yellow".to_string();
        store.telemetry.phishing_total_count = 420;
        store.telemetry.compromised_ips_total_count = 1280;
        store.telemetry.top_attacked_ports.push(PortAttack {
            rank: 1,
            port: 443,
            service_name: "HTTPS".to_string(),
            records: 95000,
            targets: 12000,
            sources: 3400,
        });
        store.telemetry.botnet_c2s.push(BotnetC2 {
            ip_address: "198.51.100.22".to_string(),
            port: 443,
            status: "online".to_string(),
            hostname: Some("c2.example.invalid".to_string()),
            as_number: Some(64512),
            as_name: Some("TEST-NET".to_string()),
            country: Some("XX".to_string()),
            malware: "QakBot".to_string(),
            first_seen: None,
            last_online: None,
        });

        let v = Vulnerability {
            id: "CVE-2026-41001".to_string(),
            aliases: vec![],
            title: "Critical PyTorch Remote Code Execution".to_string(),
            description: "Untrusted deserialization leads to RCE.".to_string(),
            severity: Severity::Critical,
            cvss_score: Some(9.8),
            cvss_vector: None,
            epss_score: Some(0.91),
            epss_percentile: Some(0.99),
            ai_risk_score: 96,
            ai_score_factors: vec![ScoreFactor {
                label: "CISA KEV".to_string(),
                points: 35,
                detail: "Confirmed active exploitation".to_string(),
            }],
            ai_summary: "Active KEV RCE".to_string(),
            is_kev: true,
            kev_date_added: Some("2026-11-20".to_string()),
            kev_due_date: Some("2026-12-01".to_string()),
            kev_required_action: Some("Upgrade to patched build immediately.".to_string()),
            forensic_triage: None,
            ransomware_use: true,
            has_public_exploit: true,
            is_ai_related: true,
            vendor: Some("PyTorch".to_string()),
            product: Some("torch".to_string()),
            ecosystem: Some("PyPI".to_string()),
            patched_version: Some("2.6.1".to_string()),
            cwes: vec!["CWE-502".to_string()],
            mitre_tactics: vec!["Execution".to_string()],
            attack_vectors: vec!["Remote Code Execution".to_string()],
            sources: vec!["CISA KEV".to_string()],
            references: vec![],
            published_at: now,
            updated_at: now,
            first_seen_at: now,
            epss_delta_24h: Some(0.22),
            epss_delta_7d: Some(0.30),
            epss_spike: true,
            kev_days_remaining: Some(5),
            matched_stack: vec!["torch".to_string()],
            triage_status: TriageStatus::New,
            triage_notes: String::new(),
        };
        store.vulnerabilities.insert(v.id.clone(), v);
        store
    }

    #[test]
    fn builds_valid_surfaces_for_all_soc_intents() {
        let store = sample_store();
        let vulns: Vec<&Vulnerability> = store.vulnerabilities.values().collect();
        let news: Vec<&ThreatNewsItem> = vec![];
        let now = Utc::now();

        let cases = [
            (
                "Summarize critical vulnerabilities from this past week",
                "threat_overview",
            ),
            (
                "What AI, LLM, PyTorch, or MCP vulnerabilities are active?",
                "ai_supply_chain",
            ),
            (
                "Which CISA KEV vulnerabilities have known ransomware campaign linkage?",
                "kev_ransomware",
            ),
            (
                "What breaking exploit PoCs and advisories came out in 48 hours?",
                "breaking_news",
            ),
            (
                "Summarize top attacked network ports and botnet C2s",
                "network_ioc",
            ),
            ("Check my stack exposure right now", "stack_exposure"),
        ];

        for (q, expected_intent) in cases {
            let (surface, _) =
                build_analyst_a2ui_surface(q, &[], &store, &vulns, &news, 1, 0, None, now);
            assert_eq!(surface.version, "1.0");
            assert_eq!(surface.catalog_id, A2UI_CATALOG_ID);
            assert_eq!(surface.intent, expected_intent);
            assert_eq!(surface.messages.len(), 3);

            // Verify @path binding resolves cleanly against the emitted dataModel
            let data_model = match &surface.messages[1] {
                A2uiServerMessage::UpdateDataModel { value, .. } => value,
                _ => panic!("expected UpdateDataModel at index 1"),
            };
            assert!(resolve_json_pointer(data_model, "/kpis/0/label").is_some());
            assert_eq!(
                resolve_json_pointer(data_model, "/vulns/0/id").and_then(Value::as_str),
                Some("CVE-2026-41001")
            );
        }
    }

    #[test]
    fn rejects_unknown_components_forbidden_actions_and_javascript_uris() {
        let malicious = A2uiSurfacePayload {
            version: "1.0".to_string(),
            surface_id: "test-1".to_string(),
            catalog_id: A2UI_CATALOG_ID.to_string(),
            intent: "threat_overview".to_string(),
            messages: vec![
                A2uiServerMessage::CreateSurface {
                    surface_id: "test-1".to_string(),
                    catalog_id: A2UI_CATALOG_ID.to_string(),
                    root_component_id: "root".to_string(),
                    title: "Title\u{202E}Spoof".to_string(),
                    subtitle: "Sub".to_string(),
                },
                A2uiServerMessage::UpdateDataModel {
                    surface_id: "test-1".to_string(),
                    path: "/".to_string(),
                    value: json!({
                        "badUrl": "javascript:alert(1)",
                        "action": { "type": "delete_database", "target": "auth" },
                        "actions": [
                            { "type": "exfiltrate_api_key", "url": "https://evil.invalid" },
                            { "type": "open_cve", "label": "Inspect", "cveId": "CVE-2026-41001" }
                        ]
                    }),
                },
                A2uiServerMessage::UpdateComponents {
                    surface_id: "test-1".to_string(),
                    components: vec![
                        A2uiComponent {
                            id: "root".to_string(),
                            component: "Column".to_string(),
                            children: Some(vec!["evil-script".to_string(), "safe-bar".to_string()]),
                            props: Map::new(),
                        },
                        A2uiComponent {
                            id: "evil-script".to_string(),
                            component: "RawHtmlIframe".to_string(),
                            children: None,
                            props: Map::new(),
                        },
                        A2uiComponent {
                            id: "safe-bar".to_string(),
                            component: "ActionBar".to_string(),
                            children: None,
                            props: Map::new(),
                        },
                    ],
                },
            ],
        };

        let sanitized = validate_and_sanitize_a2ui(malicious).expect("should sanitize cleanly");
        if let A2uiServerMessage::CreateSurface { title, .. } = &sanitized.messages[0] {
            assert_eq!(title, "TitleSpoof");
        }
        if let A2uiServerMessage::UpdateDataModel { value, .. } = &sanitized.messages[1] {
            assert_eq!(value["badUrl"].as_str(), Some("[blocked-uri]"));
            assert!(value.get("action").is_none());
            assert_eq!(value["actions"].as_array().unwrap().len(), 1);
            assert_eq!(value["actions"][0]["type"].as_str(), Some("open_cve"));
        }
        if let A2uiServerMessage::UpdateComponents { components, .. } = &sanitized.messages[2] {
            assert_eq!(components.len(), 2);
            assert_eq!(
                components[0].children.as_ref().unwrap(),
                &vec!["safe-bar".to_string()]
            );
        }
    }

    #[test]
    fn rejects_untrusted_catalog_and_cycles() {
        let wrong_catalog = A2uiSurfacePayload {
            version: "1.0".to_string(),
            surface_id: "s1".to_string(),
            catalog_id: "evil.catalog.v1".to_string(),
            intent: "test".to_string(),
            messages: vec![],
        };
        assert!(validate_and_sanitize_a2ui(wrong_catalog).is_err());

        let cyclic = A2uiSurfacePayload {
            version: "1.0".to_string(),
            surface_id: "s2".to_string(),
            catalog_id: A2UI_CATALOG_ID.to_string(),
            intent: "test".to_string(),
            messages: vec![
                A2uiServerMessage::CreateSurface {
                    surface_id: "s2".to_string(),
                    catalog_id: A2UI_CATALOG_ID.to_string(),
                    root_component_id: "a".to_string(),
                    title: "Cycle".to_string(),
                    subtitle: "".to_string(),
                },
                A2uiServerMessage::UpdateComponents {
                    surface_id: "s2".to_string(),
                    components: vec![
                        A2uiComponent {
                            id: "a".to_string(),
                            component: "Column".to_string(),
                            children: Some(vec!["b".to_string()]),
                            props: Map::new(),
                        },
                        A2uiComponent {
                            id: "b".to_string(),
                            component: "Column".to_string(),
                            children: Some(vec!["a".to_string()]),
                            props: Map::new(),
                        },
                    ],
                },
            ],
        };
        assert!(validate_and_sanitize_a2ui(cyclic).is_err());
    }

    #[test]
    fn extracts_optional_llm_a2ui_patch_block() {
        let raw = "## Summary\nHigh risk detected.\n\n```a2ui-patch\n{\"headline\":\"Custom SOC Focus\",\"playbook\":[{\"priority\":\"P0\",\"title\":\"Patch PyTorch\",\"detail\":\"Upgrade immediately\",\"cve_id\":\"CVE-2026-41001\"}]}\n```";
        let (md, patch) = extract_llm_a2ui_patch(raw);
        assert!(md.contains("High risk detected."));
        assert!(!md.contains("a2ui-patch"));
        let p = patch.expect("patch parsed");
        assert_eq!(p.headline.as_deref(), Some("Custom SOC Focus"));
        assert_eq!(p.playbook.len(), 1);
    }
}
