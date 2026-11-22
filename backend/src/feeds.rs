use std::collections::{HashMap, HashSet};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use chrono::{DateTime, NaiveDate, NaiveDateTime, TimeZone, Utc};
use futures::stream::{self, StreamExt};
use serde_json::Value;
use tracing::{info, warn};

use crate::analyzer::{
    analyze_news_item, enrich_vulnerability, evaluate_alerts, generate_ai_brief,
    strip_html_and_clean, truncate_str,
};
use crate::models::{
    AttackerIp, BotnetC2, CustomFeedConfig, CustomFeedKind, EpssSpike, EpssTopThreat, FeedHealth,
    PhishingUrl, PortAttack, Severity, SseEvent, SweepDelta, ThreatNewsItem, TriageStatus,
    Vulnerability,
};
use crate::security::{build_pinned_http_client, validate_outbound_url, OutboundUrlPolicy};
use crate::stack::correlate_stack;
use crate::store::AppState;
use crate::webhooks::{build_dispatch_items, dispatch_webhooks_batch};

const USER_AGENT: &str = "AiBrainWorXCyberThreatBoard/1.0 (Local SOC Dashboard)";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(18);
const MAX_FEED_BYTES: usize = 12 * 1024 * 1024;

pub fn sanitize_http_url(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 2048 {
        return None;
    }
    let parsed = url::Url::parse(trimmed).ok()?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return None;
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return None;
    }
    Some(parsed.to_string())
}

struct RssFeedDef {
    id: &'static str,
    name: &'static str,
    category: &'static str,
    url: &'static str,
}

const RSS_FEEDS: &[RssFeedDef] = &[
    RssFeedDef {
        id: "cisa_advisories",
        name: "CISA Cybersecurity Advisories",
        category: "Advisory",
        url: "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    },
    RssFeedDef {
        id: "cisa_ics",
        name: "CISA ICS Advisories",
        category: "Advisory",
        url: "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml",
    },
    RssFeedDef {
        id: "bleepingcomputer",
        name: "BleepingComputer",
        category: "Breaking News",
        url: "https://www.bleepingcomputer.com/feed/",
    },
    RssFeedDef {
        id: "thehackernews",
        name: "The Hacker News",
        category: "Breaking News",
        url: "https://feeds.feedburner.com/TheHackersNews",
    },
    RssFeedDef {
        id: "krebs",
        name: "Krebs on Security",
        category: "Breaking News",
        url: "https://krebsonsecurity.com/feed/",
    },
    RssFeedDef {
        id: "securityweek",
        name: "SecurityWeek",
        category: "Breaking News",
        url: "https://www.securityweek.com/feed/",
    },
    RssFeedDef {
        id: "darkreading",
        name: "Dark Reading",
        category: "Breaking News",
        url: "https://www.darkreading.com/rss.xml",
    },
    RssFeedDef {
        id: "exploitdb",
        name: "Exploit-DB PoCs",
        category: "Exploit PoC",
        url: "https://www.exploit-db.com/rss.xml",
    },
    RssFeedDef {
        id: "sans_diary",
        name: "SANS ISC Handler Diary",
        category: "Research",
        url: "https://isc.sans.edu/rssfeed.xml",
    },
    RssFeedDef {
        id: "project_zero",
        name: "Google Project Zero",
        category: "Research",
        url: "https://googleprojectzero.blogspot.com/feeds/posts/default?alt=rss",
    },
    RssFeedDef {
        id: "msrc",
        name: "Microsoft MSRC Updates",
        category: "Vendor Patch",
        url: "https://msrc.microsoft.com/update-guide/rss",
    },
];

pub async fn run_sweep(state: AppState) {
    if state.server_mode.offline_mode {
        info!("Offline air-gapped mode active; skipping remote feed sweep.");
        return;
    }

    if state
        .sweep_in_progress
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        info!("Sweep already in progress; skipping duplicate trigger");
        return;
    }

    let started_at = Utc::now();
    let _ = state.sse_tx.send(SseEvent::SweepStarted { started_at });
    info!("Starting concurrent public cybersecurity threat sweep...");

    let (disabled_feeds, custom_feeds, prev_cve_ids, prev_kev_ids, prev_stack_ids) = {
        let store = state.store.read().await;
        let disabled: HashSet<String> = store
            .feed_settings
            .disabled_feeds
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect();
        let custom: Vec<CustomFeedConfig> = store
            .feed_settings
            .custom_feeds
            .iter()
            .filter(|f| f.enabled)
            .cloned()
            .collect();
        let cves: HashSet<String> = store.vulnerabilities.keys().cloned().collect();
        let kevs: HashSet<String> = store
            .vulnerabilities
            .values()
            .filter(|v| v.is_kev)
            .map(|v| v.id.clone())
            .collect();
        let stack_ids: HashSet<String> = store
            .vulnerabilities
            .values()
            .filter(|v| !v.matched_stack.is_empty())
            .map(|v| v.id.clone())
            .collect();
        (disabled, custom, cves, kevs, stack_ids)
    };

    let is_disabled = |id: &str, name: &str| {
        disabled_feeds.contains(&id.to_ascii_lowercase())
            || disabled_feeds.contains(&name.to_ascii_lowercase())
    };

    let http = state.http.clone();

    // Launch all independent feed categories concurrently, skipping disabled feeds cleanly.
    let (
        (kev_vulns, kev_set, kev_health),
        (nvd_vulns, nvd_health),
        (gh_vulns, gh_health),
        (circl_vulns, circl_health),
        (osv_vulns, osv_health),
        (infocon, infocon_health),
        (top_ports, ports_health),
        (top_ips, ips_health),
        (botnet_c2s, feodo_health),
        (phish_urls, phish_total, phish_health),
        (comp_set, comp_sample, comp_total, comp_health),
        (top_epss_global, epss_global_health),
        (hn_news, hn_health),
        rss_results,
        custom_outcome,
    ) = tokio::join!(
        async {
            if is_disabled("cisa_kev", "CISA Known Exploited Vulnerabilities") {
                (
                    Vec::new(),
                    HashSet::new(),
                    disabled_health(
                        "cisa_kev",
                        "CISA Known Exploited Vulnerabilities",
                        "Vulnerability DB",
                        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                    ),
                )
            } else {
                fetch_cisa_kev(&http).await
            }
        },
        async {
            if is_disabled("nvd_api", "NIST NVD CVE 2.0 (7-Day)") {
                (
                    Vec::new(),
                    disabled_health(
                        "nvd_api",
                        "NIST NVD CVE 2.0 (7-Day)",
                        "Vulnerability DB",
                        "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    ),
                )
            } else {
                fetch_nvd_recent(&http).await
            }
        },
        async {
            if is_disabled("github_advisories", "GitHub Security Advisories") {
                (
                    Vec::new(),
                    disabled_health(
                        "github_advisories",
                        "GitHub Security Advisories",
                        "Vulnerability DB",
                        "https://api.github.com/advisories",
                    ),
                )
            } else {
                fetch_github_advisories(&http).await
            }
        },
        async {
            if is_disabled("circl_cve", "CIRCL Vulnerability Feed") {
                (
                    Vec::new(),
                    disabled_health(
                        "circl_cve",
                        "CIRCL Vulnerability Feed",
                        "Vulnerability DB",
                        "https://cve.circl.lu/api/last",
                    ),
                )
            } else {
                fetch_circl_recent(&http).await
            }
        },
        async {
            if is_disabled("osv_ai", "OSV.dev AI/ML Supply Chain") {
                (
                    Vec::new(),
                    disabled_health(
                        "osv_ai",
                        "OSV.dev AI/ML Supply Chain",
                        "AI Supply Chain",
                        "https://api.osv.dev/v1/query",
                    ),
                )
            } else {
                fetch_osv_ai_watchlist(&http).await
            }
        },
        async {
            if is_disabled("sans_infocon", "SANS ISC INFOCON Status") {
                (
                    None,
                    disabled_health(
                        "sans_infocon",
                        "SANS ISC INFOCON Status",
                        "Network Telemetry",
                        "https://isc.sans.edu/api/infocon?json",
                    ),
                )
            } else {
                fetch_sans_infocon(&http).await
            }
        },
        async {
            if is_disabled("sans_ports", "SANS ISC Top Attacked Ports") {
                (
                    Vec::new(),
                    disabled_health(
                        "sans_ports",
                        "SANS ISC Top Attacked Ports",
                        "Network Telemetry",
                        "https://isc.sans.edu/api/topports/records/15?json",
                    ),
                )
            } else {
                fetch_sans_top_ports(&http).await
            }
        },
        async {
            if is_disabled("sans_ips", "SANS ISC Top Attacking IPs") {
                (
                    Vec::new(),
                    disabled_health(
                        "sans_ips",
                        "SANS ISC Top Attacking IPs",
                        "Network Telemetry",
                        "https://isc.sans.edu/api/sources/attacks/25?json",
                    ),
                )
            } else {
                fetch_sans_top_ips(&http).await
            }
        },
        async {
            if is_disabled("feodo_c2", "abuse.ch Feodo Botnet C2s") {
                (
                    Vec::new(),
                    disabled_health(
                        "feodo_c2",
                        "abuse.ch Feodo Botnet C2s",
                        "IOC & Malware",
                        "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
                    ),
                )
            } else {
                fetch_feodo_c2(&http).await
            }
        },
        async {
            if is_disabled("openphish", "OpenPhish Live Phishing Feed") {
                (
                    Vec::new(),
                    0,
                    disabled_health(
                        "openphish",
                        "OpenPhish Live Phishing Feed",
                        "IOC & Malware",
                        "https://openphish.com/feed.txt",
                    ),
                )
            } else {
                fetch_openphish(&http).await
            }
        },
        async {
            if is_disabled("et_compromised", "Emerging Threats Compromised IPs") {
                (
                    HashSet::new(),
                    Vec::new(),
                    0,
                    disabled_health(
                        "et_compromised",
                        "Emerging Threats Compromised IPs",
                        "IOC & Malware",
                        "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
                    ),
                )
            } else {
                fetch_emerging_threats(&http).await
            }
        },
        async {
            if is_disabled("first_epss_top", "FIRST.org EPSS Top Risks") {
                (
                    Vec::new(),
                    disabled_health(
                        "first_epss_top",
                        "FIRST.org EPSS Top Risks",
                        "Exploit Prediction",
                        "https://api.first.org/data/v1/epss?order=!epss&limit=25",
                    ),
                )
            } else {
                fetch_epss_top(&http).await
            }
        },
        async {
            if is_disabled("hn_security", "Hacker News Security Wire") {
                (
                    Vec::new(),
                    disabled_health(
                        "hn_security",
                        "Hacker News Security Wire",
                        "Community",
                        "https://hn.algolia.com",
                    ),
                )
            } else {
                fetch_hn_algolia(&http).await
            }
        },
        fetch_all_rss(&http, &disabled_feeds),
        fetch_custom_feeds(&custom_feeds),
    );

    let now = Utc::now();

    // Merge vulnerabilities collected in this sweep
    let mut merged_vulns: HashMap<String, Vulnerability> = HashMap::new();
    for v in kev_vulns
        .into_iter()
        .chain(nvd_vulns)
        .chain(gh_vulns)
        .chain(circl_vulns)
        .chain(osv_vulns)
        .chain(custom_outcome.vulns)
    {
        merge_vuln_into(&mut merged_vulns, v);
    }

    // Apply full CISA KEV catalog flag if CVE is in kev_set
    for v in merged_vulns.values_mut() {
        if kev_set.contains(&v.id) || v.aliases.iter().any(|a| kev_set.contains(a)) {
            v.is_kev = true;
        }
    }

    // Collect CVE IDs needing EPSS enrichment (prioritize recent & severe)
    let mut cve_candidates: Vec<(DateTime<Utc>, String)> = merged_vulns
        .values()
        .filter(|v| v.id.starts_with("CVE-") && v.epss_score.is_none())
        .map(|v| (v.published_at, v.id.clone()))
        .collect();
    cve_candidates.sort_by_key(|a| std::cmp::Reverse(a.0));
    let cve_ids_to_enrich: Vec<String> = cve_candidates
        .into_iter()
        .take(120)
        .map(|(_, id)| id)
        .collect();

    let (epss_map, epss_enrich_health) =
        if is_disabled("first_epss_enrich", "FIRST.org EPSS CVE Scorer") {
            (
                HashMap::new(),
                disabled_health(
                    "first_epss_enrich",
                    "FIRST.org EPSS CVE Scorer",
                    "Exploit Prediction",
                    "https://api.first.org/data/v1/epss",
                ),
            )
        } else {
            fetch_epss_batch(&http, &cve_ids_to_enrich).await
        };

    for (cve_id, (epss, pct)) in epss_map {
        if let Some(v) = merged_vulns.get_mut(&cve_id) {
            v.epss_score = Some(epss);
            v.epss_percentile = Some(pct);
        }
    }

    // Record EPSS samples in SQLite (outside lock) & gather delta baseline map
    let epss_samples: Vec<(String, f64, DateTime<Utc>)> = merged_vulns
        .values()
        .filter_map(|v| v.epss_score.map(|score| (v.id.clone(), score, now)))
        .collect();
    if !epss_samples.is_empty() {
        if let Err(e) = state.db.record_epss_samples(&epss_samples) {
            warn!("Failed recording EPSS history samples: {e}");
        }
    }

    // Gather all news items and cross-correlate exploit signals
    let mut all_news: Vec<ThreatNewsItem> = hn_news;
    all_news.extend(custom_outcome.news);
    let mut feed_healths: Vec<FeedHealth> = vec![
        kev_health,
        nvd_health,
        gh_health,
        circl_health,
        osv_health,
        epss_global_health,
        epss_enrich_health,
        infocon_health,
        ports_health,
        ips_health,
        feodo_health,
        phish_health,
        comp_health,
        hn_health,
    ];

    for (items, health) in rss_results {
        all_news.extend(items);
        feed_healths.push(health);
    }
    feed_healths.extend(custom_outcome.healths);

    // Analyze news & extract exploit-linked CVEs
    let mut exploit_cves: HashSet<String> = HashSet::new();
    for item in &mut all_news {
        analyze_news_item(item, &kev_set);
        if item.category == "Exploit PoC"
            || item
                .tags
                .iter()
                .any(|t| t == "Exploit PoC" || t == "Zero-Day")
        {
            for cve in &item.extracted_cves {
                exploit_cves.insert(cve.clone());
            }
        }
    }

    for v in merged_vulns.values_mut() {
        if exploit_cves.contains(&v.id) || v.aliases.iter().any(|a| exploit_cves.contains(a)) {
            v.has_public_exploit = true;
        }
        enrich_vulnerability(v, now);
    }

    // Compute EPSS deltas against stored baseline across merged CVEs before committing
    let current_epss_scores: HashMap<String, f64> = merged_vulns
        .values()
        .filter_map(|v| v.epss_score.map(|s| (v.id.clone(), s)))
        .collect();
    let epss_deltas = state.db.compute_epss_deltas(&current_epss_scores, now);

    // Commit everything into the store under write lock
    let (
        new_alerts,
        total_vulns,
        total_news,
        next_sweep_at,
        webhook_targets,
        dispatch_items,
        delta_to_save,
    ) = {
        let mut store = state.store.write().await;

        if !kev_set.is_empty() {
            store.kev_cve_set = kev_set;
        }

        for (id, v) in merged_vulns {
            if let Some(existing) = store.vulnerabilities.get_mut(&id) {
                let first_seen = existing.first_seen_at;
                *existing = merge_two_vulns(existing.clone(), v);
                existing.first_seen_at = first_seen;
                enrich_vulnerability(existing, now);
            } else {
                store.vulnerabilities.insert(id, v);
            }
        }

        // Apply EPSS 24h / 7d delta tracking and KEV countdown across all tracked CVEs
        {
            let store_ref = &mut *store;
            for v in store_ref.vulnerabilities.values_mut() {
                v.kev_days_remaining =
                    crate::analyzer::compute_kev_days_remaining(v.kev_due_date.as_deref(), now);
                if let Some((d24, d7)) = epss_deltas.get(&v.id) {
                    v.epss_delta_24h = *d24;
                    v.epss_delta_7d = *d7;
                    v.epss_spike = d24.is_some_and(|delta| delta >= 0.15);
                }
                if let Some(t) = store_ref.triage_map.get(&v.id) {
                    v.triage_status = t.status;
                    v.triage_notes = t.notes.clone();
                }
            }
        }

        for n in all_news {
            if let Some(existing) = store.news.get_mut(&n.id) {
                let first_seen = existing.first_seen_at;
                *existing = n;
                existing.first_seen_at = first_seen;
            } else {
                store.news.insert(n.id.clone(), n);
            }
        }

        // Update telemetry only when feeds succeeded (preserve previous non-empty data on transient errors)
        if let Some(status) = infocon {
            store.telemetry.infocon_status = status;
        }
        if !top_ports.is_empty() {
            store.telemetry.top_attacked_ports = top_ports;
        }
        if !top_ips.is_empty() {
            store.telemetry.top_attacking_ips = top_ips;
        }
        if !botnet_c2s.is_empty() {
            store.telemetry.botnet_c2s = botnet_c2s;
        }
        if !phish_urls.is_empty() {
            store.telemetry.phishing_urls = phish_urls;
            store.telemetry.phishing_total_count = phish_total;
        }
        if !comp_sample.is_empty() {
            store.telemetry.compromised_ips_sample = comp_sample;
            store.telemetry.compromised_ips_total_count = comp_total;
            store.compromised_ips_set = comp_set;
        }
        if !top_epss_global.is_empty() {
            store.telemetry.top_epss_global = top_epss_global;
        }

        // Merge BYO custom IOC indicators safely
        if !custom_outcome.ioc_ips.is_empty() {
            for ip in custom_outcome.ioc_ips {
                if store.compromised_ips_set.insert(ip.clone()) {
                    store.telemetry.compromised_ips_total_count += 1;
                    if store.telemetry.compromised_ips_sample.len() < 400 {
                        store.telemetry.compromised_ips_sample.push(ip);
                    }
                }
            }
        }
        if !custom_outcome.phish_urls.is_empty() {
            let existing: HashSet<String> = store
                .telemetry
                .phishing_urls
                .iter()
                .map(|p| p.url.clone())
                .collect();
            for ph in custom_outcome.phish_urls {
                if !existing.contains(&ph.url) && store.telemetry.phishing_urls.len() < 500 {
                    store.telemetry.phishing_urls.push(ph);
                    store.telemetry.phishing_total_count += 1;
                }
            }
        }

        // Persist custom feed statuses back into config
        for (feed_id, status, cnt, checked) in custom_outcome.status_updates {
            if let Some(cf) = store
                .feed_settings
                .custom_feeds
                .iter_mut()
                .find(|f| f.id == feed_id)
            {
                cf.last_status = Some(status);
                cf.last_item_count = cnt;
                cf.last_checked = Some(checked);
            }
        }

        // Correlate My Stack BEFORE alerts and AI brief so stack exposure drives triage & alerts
        let stack_summary = {
            let store_ref = &mut *store;
            correlate_stack(&mut store_ref.vulnerabilities, &store_ref.my_stack)
        };

        feed_healths.sort_by(|a, b| {
            a.category
                .cmp(&b.category)
                .then_with(|| a.name.cmp(&b.name))
        });
        store.feed_health = feed_healths;

        let rules_snapshot = store.rules.clone();
        let new_alerts = evaluate_alerts(&mut store, &rules_snapshot, now);

        // Compute sweep delta ("What Changed Since Last Check")
        let mut new_cves: Vec<String> = store
            .vulnerabilities
            .keys()
            .filter(|id| !prev_cve_ids.is_empty() && !prev_cve_ids.contains(*id))
            .cloned()
            .collect();
        new_cves.sort();
        new_cves.truncate(40);

        let mut new_kevs: Vec<String> = store
            .vulnerabilities
            .values()
            .filter(|v| v.is_kev && !prev_kev_ids.is_empty() && !prev_kev_ids.contains(&v.id))
            .map(|v| v.id.clone())
            .collect();
        new_kevs.sort();

        let mut new_stack_hits: Vec<String> = if stack_summary.configured {
            store
                .vulnerabilities
                .values()
                .filter(|v| !v.matched_stack.is_empty() && !prev_stack_ids.contains(&v.id))
                .map(|v| v.id.clone())
                .collect()
        } else {
            Vec::new()
        };
        new_stack_hits.sort();

        let mut epss_spikes: Vec<EpssSpike> = store
            .vulnerabilities
            .values()
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
        epss_spikes.sort_by(|a, b| {
            b.delta_24h_pct
                .partial_cmp(&a.delta_24h_pct)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        epss_spikes.truncate(15);

        let delta = SweepDelta {
            sweep_at: now,
            new_cves,
            new_kevs,
            new_stack_hits,
            epss_spikes,
            new_alerts_count: new_alerts.len(),
            reviewed: false,
        };
        let has_changes = !delta.new_cves.is_empty()
            || !delta.new_kevs.is_empty()
            || !delta.new_stack_hits.is_empty()
            || !delta.epss_spikes.is_empty()
            || delta.new_alerts_count > 0;
        let delta_to_save = if has_changes || store.latest_delta.is_none() {
            store.latest_delta = Some(delta.clone());
            Some(delta)
        } else {
            None
        };

        store.ai_brief = generate_ai_brief(&store, now);

        store.last_sweep_at = Some(now);
        let interval = store.rules.poll_interval_secs.max(60);
        let next_at = now + chrono::Duration::seconds(interval as i64);
        store.next_sweep_at = Some(next_at);
        store.total_sweeps += 1;
        store.initialized = true;
        store.prune();

        if let Err(e) = state.persist_store(&store) {
            warn!("Failed to persist threat store: {}", e);
        }

        let webhook_targets: Vec<_> = store
            .webhooks
            .iter()
            .filter(|w| w.enabled)
            .cloned()
            .collect();
        let dispatch_items = if !webhook_targets.is_empty() && !new_alerts.is_empty() {
            build_dispatch_items(&new_alerts, &store.vulnerabilities)
        } else {
            Vec::new()
        };

        (
            new_alerts,
            store.vulnerabilities.len(),
            store.news.len(),
            next_at,
            webhook_targets,
            dispatch_items,
            delta_to_save,
        )
    };

    if let Some(delta) = delta_to_save {
        if let Err(e) = state.db.record_sweep_delta(&delta) {
            warn!("Failed recording sweep delta: {e}");
        }
    }

    // Emit SSE alerts individually so frontend shows live banner + toast immediately
    let new_alert_count = new_alerts.len();
    for alert in new_alerts {
        let _ = state.sse_tx.send(SseEvent::NewAlert(alert));
    }

    // Dispatch matching outbound webhooks outside any lock
    if !webhook_targets.is_empty() && !dispatch_items.is_empty() {
        let results = dispatch_webhooks_batch(webhook_targets, dispatch_items).await;
        if !results.is_empty() {
            let mut store = state.store.write().await;
            for (hook_id, ok, msg) in results {
                if let Some(hook) = store.webhooks.iter_mut().find(|w| w.id == hook_id) {
                    hook.last_sent_at = Some(Utc::now());
                    hook.last_status = Some(msg);
                    if ok {
                        hook.failure_count = 0;
                    } else {
                        hook.failure_count = hook.failure_count.saturating_add(1);
                    }
                }
            }
            let _ = state.persist_store(&store);
        }
    }

    let _ = state.sse_tx.send(SseEvent::SweepCompleted {
        completed_at: now,
        new_alerts: new_alert_count,
        total_vulns,
        total_news,
        next_sweep_at,
    });

    state.sweep_in_progress.store(false, Ordering::SeqCst);
    info!(
        "Sweep complete: {} vulns, {} news, {} new alerts",
        total_vulns, total_news, new_alert_count
    );
}

fn disabled_health(id: &str, name: &str, category: &str, url: &str) -> FeedHealth {
    FeedHealth {
        id: id.to_string(),
        name: name.to_string(),
        category: category.to_string(),
        url: url.to_string(),
        status: "DISABLED".to_string(),
        http_status: None,
        latency_ms: 0,
        items_fetched: 0,
        last_success_at: None,
        last_error: Some("Disabled in Feed Settings".to_string()),
    }
}

#[derive(Default)]
struct CustomFeedOutcome {
    vulns: Vec<Vulnerability>,
    news: Vec<ThreatNewsItem>,
    ioc_ips: Vec<String>,
    phish_urls: Vec<PhishingUrl>,
    healths: Vec<FeedHealth>,
    status_updates: Vec<(String, String, usize, DateTime<Utc>)>,
}

/// Fetches enabled user-configured BYO feeds strictly through DNS-pinned public HTTPS SSRF guard.
async fn fetch_custom_feeds(feeds: &[CustomFeedConfig]) -> CustomFeedOutcome {
    let mut outcome = CustomFeedOutcome::default();
    if feeds.is_empty() {
        return outcome;
    }

    for feed in feeds {
        let t0 = Instant::now();
        let now = Utc::now();
        let mut health = base_health(&feed.id, &feed.name, "Custom Feed", &feed.url);

        let validated =
            match validate_outbound_url(&feed.url, OutboundUrlPolicy::StrictPublicHttps).await {
                Ok(v) => v,
                Err(e) => {
                    health.status = "ERROR".to_string();
                    health.last_error = Some(format!("Blocked by SSRF policy: {e}"));
                    outcome
                        .status_updates
                        .push((feed.id.clone(), format!("Blocked: {e}"), 0, now));
                    outcome.healths.push(health);
                    continue;
                }
            };

        let client = match build_pinned_http_client(&validated, REQUEST_TIMEOUT, USER_AGENT) {
            Ok(c) => c,
            Err(e) => {
                health.status = "ERROR".to_string();
                health.last_error = Some(e.clone());
                outcome.status_updates.push((feed.id.clone(), e, 0, now));
                outcome.healths.push(health);
                continue;
            }
        };

        let resp =
            match tokio::time::timeout(REQUEST_TIMEOUT, client.get(validated.url).send()).await {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => {
                    let msg = e.without_url().to_string();
                    health.status = "ERROR".to_string();
                    health.latency_ms = t0.elapsed().as_millis() as u64;
                    health.last_error = Some(msg.clone());
                    outcome.status_updates.push((feed.id.clone(), msg, 0, now));
                    outcome.healths.push(health);
                    continue;
                }
                Err(_) => {
                    health.status = "ERROR".to_string();
                    health.latency_ms = t0.elapsed().as_millis() as u64;
                    health.last_error = Some("Request timeout".to_string());
                    outcome
                        .status_updates
                        .push((feed.id.clone(), "Timeout".into(), 0, now));
                    outcome.healths.push(health);
                    continue;
                }
            };

        let code = resp.status().as_u16();
        health.http_status = Some(code);
        if !resp.status().is_success() {
            health.status = "ERROR".to_string();
            health.latency_ms = t0.elapsed().as_millis() as u64;
            health.last_error = Some(format!("HTTP {code}"));
            outcome
                .status_updates
                .push((feed.id.clone(), format!("HTTP {code}"), 0, now));
            outcome.healths.push(health);
            continue;
        }

        let bytes = match read_bounded_bytes(resp, MAX_FEED_BYTES).await {
            Ok(b) => b,
            Err(e) => {
                health.status = "ERROR".to_string();
                health.latency_ms = t0.elapsed().as_millis() as u64;
                health.last_error = Some(e.clone());
                outcome.status_updates.push((feed.id.clone(), e, 0, now));
                outcome.healths.push(health);
                continue;
            }
        };

        health.latency_ms = t0.elapsed().as_millis() as u64;
        let mut count = 0usize;
        match feed.kind {
            CustomFeedKind::RssAtom => {
                if let Ok(parsed) = feed_rs::parser::parse(&bytes[..]) {
                    for entry in parsed.entries.into_iter().take(40) {
                        let title = entry
                            .title
                            .map(|t| strip_html_and_clean(&t.content))
                            .unwrap_or_default();
                        if title.is_empty() {
                            continue;
                        }
                        let link = entry
                            .links
                            .into_iter()
                            .next()
                            .and_then(|l| sanitize_http_url(&l.href))
                            .unwrap_or_else(|| feed.url.clone());
                        let summary = entry
                            .summary
                            .map(|s| s.content)
                            .or_else(|| entry.content.and_then(|c| c.body))
                            .map(|s| strip_html_and_clean(&s))
                            .unwrap_or_default();
                        let pub_dt = entry.published.or(entry.updated).unwrap_or(now);
                        outcome.news.push(ThreatNewsItem {
                            id: format!("custom-{}-{}", feed.id, entry.id),
                            source: feed.name.clone(),
                            category: "Custom Advisory".to_string(),
                            title,
                            summary: truncate_str(&summary, 500),
                            url: link,
                            published_at: pub_dt,
                            first_seen_at: now,
                            extracted_cves: Vec::new(),
                            severity: Severity::Info,
                            ai_risk_score: 0,
                            tags: vec!["Custom Feed".to_string()],
                            is_vulnerability_news: false,
                            is_ai_related: false,
                            ai_triage_note: String::new(),
                        });
                        count += 1;
                    }
                    health.status = "OK".to_string();
                } else {
                    health.status = "ERROR".to_string();
                    health.last_error = Some("Invalid RSS/Atom XML".to_string());
                }
            }
            CustomFeedKind::IocText => {
                let text = String::from_utf8_lossy(&bytes);
                for line in text.lines().take(500) {
                    let trimmed = line.split('#').next().unwrap_or("").trim();
                    if trimmed.is_empty() || trimmed.starts_with(';') {
                        continue;
                    }
                    if trimmed.parse::<std::net::IpAddr>().is_ok() {
                        outcome.ioc_ips.push(trimmed.to_string());
                        count += 1;
                    } else if let Some(u) = sanitize_http_url(trimmed) {
                        let domain = url::Url::parse(&u)
                            .ok()
                            .and_then(|p| p.host_str().map(str::to_string))
                            .unwrap_or_default();
                        outcome.phish_urls.push(PhishingUrl {
                            url: u,
                            domain,
                            suspected_brand: Some(feed.name.clone()),
                        });
                        count += 1;
                    }
                }
                health.status = "OK".to_string();
            }
            CustomFeedKind::Stix21 => {
                if let Ok(val) = serde_json::from_slice::<Value>(&bytes) {
                    if let Some(objs) = val.get("objects").and_then(|o| o.as_array()) {
                        for obj in objs.iter().take(400) {
                            let otype = obj.get("type").and_then(|t| t.as_str()).unwrap_or("");
                            if otype == "vulnerability" {
                                let name = obj.get("name").and_then(|n| n.as_str()).unwrap_or("");
                                if name.to_ascii_uppercase().starts_with("CVE-") {
                                    let desc = obj
                                        .get("description")
                                        .and_then(|d| d.as_str())
                                        .unwrap_or("");
                                    outcome.vulns.push(custom_cve_stub(
                                        &name.to_ascii_uppercase(),
                                        desc,
                                        &feed.name,
                                        now,
                                    ));
                                    count += 1;
                                }
                            } else if otype == "indicator" {
                                let pattern =
                                    obj.get("pattern").and_then(|p| p.as_str()).unwrap_or("");
                                if let Some(val_str) = extract_stix_pattern_literal(pattern) {
                                    if val_str.parse::<std::net::IpAddr>().is_ok() {
                                        outcome.ioc_ips.push(val_str);
                                        count += 1;
                                    } else if let Some(u) = sanitize_http_url(&val_str) {
                                        let domain = url::Url::parse(&u)
                                            .ok()
                                            .and_then(|p| p.host_str().map(str::to_string))
                                            .unwrap_or_default();
                                        outcome.phish_urls.push(PhishingUrl {
                                            url: u,
                                            domain,
                                            suspected_brand: Some(feed.name.clone()),
                                        });
                                        count += 1;
                                    }
                                }
                            }
                        }
                        health.status = "OK".to_string();
                    } else {
                        health.status = "ERROR".to_string();
                        health.last_error = Some("Expected STIX 2.1 Bundle with objects[]".into());
                    }
                } else {
                    health.status = "ERROR".to_string();
                    health.last_error = Some("Invalid STIX JSON".into());
                }
            }
            CustomFeedKind::MispJson => {
                if let Ok(val) = serde_json::from_slice::<Value>(&bytes) {
                    let attrs = val
                        .pointer("/Event/Attribute")
                        .and_then(|a| a.as_array())
                        .or_else(|| val.get("Attribute").and_then(|a| a.as_array()));
                    if let Some(arr) = attrs {
                        for attr in arr.iter().take(500) {
                            let atype = attr.get("type").and_then(|t| t.as_str()).unwrap_or("");
                            let aval = attr
                                .get("value")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .trim();
                            if aval.is_empty() {
                                continue;
                            }
                            if matches!(atype, "ip-src" | "ip-dst")
                                && aval.parse::<std::net::IpAddr>().is_ok()
                            {
                                outcome.ioc_ips.push(aval.to_string());
                                count += 1;
                            } else if atype == "url" {
                                if let Some(u) = sanitize_http_url(aval) {
                                    let domain = url::Url::parse(&u)
                                        .ok()
                                        .and_then(|p| p.host_str().map(str::to_string))
                                        .unwrap_or_default();
                                    outcome.phish_urls.push(PhishingUrl {
                                        url: u,
                                        domain,
                                        suspected_brand: Some(feed.name.clone()),
                                    });
                                    count += 1;
                                }
                            } else if atype == "vulnerability"
                                && aval.to_ascii_uppercase().starts_with("CVE-")
                            {
                                let comment =
                                    attr.get("comment").and_then(|c| c.as_str()).unwrap_or("");
                                outcome.vulns.push(custom_cve_stub(
                                    &aval.to_ascii_uppercase(),
                                    comment,
                                    &feed.name,
                                    now,
                                ));
                                count += 1;
                            }
                        }
                        health.status = "OK".to_string();
                    } else {
                        health.status = "ERROR".to_string();
                        health.last_error = Some("Expected MISP Event.Attribute[] JSON".into());
                    }
                } else {
                    health.status = "ERROR".to_string();
                    health.last_error = Some("Invalid MISP JSON".into());
                }
            }
        }

        health.items_fetched = count;
        if health.status == "OK" {
            health.last_success_at = Some(now);
            outcome.status_updates.push((
                feed.id.clone(),
                format!("OK ({count} items)"),
                count,
                now,
            ));
        } else {
            let err = health.last_error.clone().unwrap_or_else(|| "ERROR".into());
            outcome.status_updates.push((feed.id.clone(), err, 0, now));
        }
        outcome.healths.push(health);
    }

    outcome
}

fn custom_cve_stub(
    cve_id: &str,
    desc: &str,
    source_name: &str,
    now: DateTime<Utc>,
) -> Vulnerability {
    Vulnerability {
        id: cve_id.to_string(),
        aliases: Vec::new(),
        title: if desc.trim().is_empty() {
            cve_id.to_string()
        } else {
            truncate_str(desc, 120)
        },
        description: truncate_str(desc, 1200),
        severity: Severity::High,
        cvss_score: None,
        cvss_vector: None,
        epss_score: None,
        epss_percentile: None,
        ai_risk_score: 0,
        ai_score_factors: Vec::new(),
        ai_summary: String::new(),
        is_kev: false,
        kev_date_added: None,
        kev_due_date: None,
        kev_required_action: None,
        forensic_triage: None,
        ransomware_use: false,
        has_public_exploit: false,
        is_ai_related: false,
        vendor: None,
        product: None,
        ecosystem: None,
        patched_version: None,
        cwes: Vec::new(),
        mitre_tactics: Vec::new(),
        attack_vectors: Vec::new(),
        sources: vec![source_name.to_string()],
        references: Vec::new(),
        published_at: now,
        updated_at: now,
        first_seen_at: now,
        epss_delta_24h: None,
        epss_delta_7d: None,
        epss_spike: false,
        kev_days_remaining: None,
        matched_stack: Vec::new(),
        triage_status: TriageStatus::New,
        triage_notes: String::new(),
    }
}

fn extract_stix_pattern_literal(pattern: &str) -> Option<String> {
    let start = pattern.find('\'')?;
    let rest = &pattern[start + 1..];
    let end = rest.find('\'')?;
    Some(rest[..end].trim().to_string())
}

fn merge_vuln_into(map: &mut HashMap<String, Vulnerability>, incoming: Vulnerability) {
    if let Some(existing) = map.remove(&incoming.id) {
        let merged = merge_two_vulns(existing, incoming);
        map.insert(merged.id.clone(), merged);
    } else {
        map.insert(incoming.id.clone(), incoming);
    }
}

fn merge_two_vulns(mut a: Vulnerability, b: Vulnerability) -> Vulnerability {
    for alias in b.aliases {
        if !a.aliases.contains(&alias) && alias != a.id {
            a.aliases.push(alias);
        }
    }
    if b.title.len() > a.title.len()
        && !b.title.is_empty()
        && (a.title.starts_with("CVE-") || a.title.starts_with("GHSA-"))
    {
        a.title = b.title;
    }
    if b.description.len() > a.description.len() {
        a.description = b.description;
    }
    if b.severity.rank() > a.severity.rank() {
        a.severity = b.severity;
    }
    if (a.cvss_score.is_none() || b.cvss_score.unwrap_or(0.0) > a.cvss_score.unwrap_or(0.0))
        && b.cvss_score.is_some()
    {
        a.cvss_score = b.cvss_score;
    }
    if a.cvss_vector.is_none() {
        a.cvss_vector = b.cvss_vector;
    }
    if a.epss_score.is_none() {
        a.epss_score = b.epss_score;
        a.epss_percentile = b.epss_percentile;
    }
    a.is_kev |= b.is_kev;
    if a.kev_date_added.is_none() {
        a.kev_date_added = b.kev_date_added;
    }
    if a.kev_due_date.is_none() {
        a.kev_due_date = b.kev_due_date;
    }
    if a.kev_required_action.is_none() {
        a.kev_required_action = b.kev_required_action;
    }
    if a.forensic_triage.is_none() {
        a.forensic_triage = b.forensic_triage;
    }
    a.ransomware_use |= b.ransomware_use;
    a.has_public_exploit |= b.has_public_exploit;
    a.is_ai_related |= b.is_ai_related;
    if a.vendor.is_none() {
        a.vendor = b.vendor;
    }
    if a.product.is_none() {
        a.product = b.product;
    }
    if a.ecosystem.is_none() {
        a.ecosystem = b.ecosystem;
    }
    if a.patched_version.is_none() {
        a.patched_version = b.patched_version;
    }
    for cwe in b.cwes {
        if !a.cwes.contains(&cwe) {
            a.cwes.push(cwe);
        }
    }
    for src in b.sources {
        if !a.sources.contains(&src) {
            a.sources.push(src);
        }
    }
    for r in b.references {
        if !a.references.contains(&r) && a.references.len() < 12 {
            a.references.push(r);
        }
    }
    if b.published_at < a.published_at {
        a.published_at = b.published_at;
    }
    if b.updated_at > a.updated_at {
        a.updated_at = b.updated_at;
    }
    a
}

// =========================================================================
// Feed 1: CISA KEV
// =========================================================================
async fn fetch_cisa_kev(
    http: &reqwest::Client,
) -> (Vec<Vulnerability>, HashSet<String>, FeedHealth) {
    let url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    let t0 = Instant::now();
    let mut health = base_health(
        "cisa_kev",
        "CISA Known Exploited Vulnerabilities",
        "Vulnerability DB",
        url,
    );

    match send_get_json(http, url).await {
        Ok((status, val)) => {
            health.http_status = Some(status);
            health.latency_ms = t0.elapsed().as_millis() as u64;
            let mut kev_set = HashSet::new();
            let mut list = val
                .get("vulnerabilities")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();

            for item in &list {
                if let Some(cve) = item.get("cveID").and_then(|x| x.as_str()) {
                    kev_set.insert(cve.to_ascii_uppercase());
                }
            }

            list.sort_by(|a, b| {
                let da = a.get("dateAdded").and_then(|x| x.as_str()).unwrap_or("");
                let db = b.get("dateAdded").and_then(|x| x.as_str()).unwrap_or("");
                db.cmp(da)
            });

            let now = Utc::now();
            let mut vulns = Vec::new();
            for item in list.into_iter().take(200) {
                let cve_id = match item.get("cveID").and_then(|x| x.as_str()) {
                    Some(c) if !c.is_empty() => c.to_ascii_uppercase(),
                    _ => continue,
                };
                let vendor = item
                    .get("vendorProject")
                    .and_then(|x| x.as_str())
                    .map(str::to_string);
                let product = item
                    .get("product")
                    .and_then(|x| x.as_str())
                    .map(str::to_string);
                let title = item
                    .get("vulnerabilityName")
                    .and_then(|x| x.as_str())
                    .unwrap_or(&cve_id)
                    .to_string();
                let desc = item
                    .get("shortDescription")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                let date_added = item
                    .get("dateAdded")
                    .and_then(|x| x.as_str())
                    .map(str::to_string);
                let due_date = item
                    .get("dueDate")
                    .and_then(|x| x.as_str())
                    .map(str::to_string);
                let req_action = item
                    .get("requiredAction")
                    .and_then(|x| x.as_str())
                    .map(str::to_string);
                let triage = item
                    .get("forensicTriage")
                    .and_then(|x| x.as_str())
                    .map(str::to_string);
                let ransomware = item
                    .get("knownRansomwareCampaignUse")
                    .and_then(|x| x.as_str())
                    .map(|s| s.eq_ignore_ascii_case("Known"))
                    .unwrap_or(false);
                let cwes: Vec<String> = item
                    .get("cwes")
                    .and_then(|x| x.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|c| c.as_str().map(|s| s.to_ascii_uppercase()))
                            .collect()
                    })
                    .unwrap_or_default();
                let mut refs = vec![format!("https://nvd.nist.gov/vuln/detail/{}", cve_id)];
                if let Some(notes) = item.get("notes").and_then(|x| x.as_str()) {
                    for part in notes.split(';') {
                        let p = part.trim();
                        if let Some(idx) = p.find("https://") {
                            let url_part = p[idx..].split_whitespace().next().unwrap_or("");
                            if let Some(safe_url) = sanitize_http_url(url_part) {
                                if !refs.iter().any(|r| r == &safe_url) {
                                    refs.push(safe_url);
                                }
                            }
                        }
                    }
                }
                let published = date_added
                    .as_deref()
                    .and_then(parse_date_loose)
                    .unwrap_or(now);

                vulns.push(Vulnerability {
                    id: cve_id,
                    aliases: Vec::new(),
                    title,
                    description: desc,
                    severity: Severity::Critical,
                    cvss_score: None,
                    cvss_vector: None,
                    epss_score: None,
                    epss_percentile: None,
                    ai_risk_score: 0,
                    ai_score_factors: Vec::new(),
                    ai_summary: String::new(),
                    is_kev: true,
                    kev_date_added: date_added,
                    kev_due_date: due_date,
                    kev_required_action: req_action,
                    forensic_triage: triage,
                    ransomware_use: ransomware,
                    has_public_exploit: true,
                    is_ai_related: false,
                    vendor,
                    product,
                    ecosystem: None,
                    patched_version: None,
                    cwes,
                    mitre_tactics: Vec::new(),
                    attack_vectors: Vec::new(),
                    sources: vec!["CISA KEV".to_string()],
                    references: refs,
                    published_at: published,
                    updated_at: published,
                    first_seen_at: now,
                    epss_delta_24h: None,
                    epss_delta_7d: None,
                    epss_spike: false,
                    kev_days_remaining: None,
                    matched_stack: Vec::new(),
                    triage_status: TriageStatus::New,
                    triage_notes: String::new(),
                });
            }

            health.status = "OK".to_string();
            health.items_fetched = kev_set.len();
            health.last_success_at = Some(now);
            (vulns, kev_set, health)
        }
        Err((status, err)) => {
            health.http_status = status;
            health.latency_ms = t0.elapsed().as_millis() as u64;
            health.status = "ERROR".to_string();
            health.last_error = Some(err);
            (Vec::new(), HashSet::new(), health)
        }
    }
}

// =========================================================================
// Feed 2: NIST NVD API 2.0 (past 7 days)
// =========================================================================
async fn fetch_nvd_recent(http: &reqwest::Client) -> (Vec<Vulnerability>, FeedHealth) {
    let now = Utc::now();
    let start = (now - chrono::Duration::days(7))
        .format("%Y-%m-%dT%H:%M:%S.000")
        .to_string();
    let end = now.format("%Y-%m-%dT%H:%M:%S.000").to_string();
    let url = format!(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={}&pubEndDate={}&resultsPerPage=80",
        start, end
    );
    let display_url = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    let t0 = Instant::now();
    let mut health = base_health(
        "nvd_api",
        "NIST NVD CVE 2.0 (7-Day)",
        "Vulnerability DB",
        display_url,
    );

    match send_get_json(http, &url).await {
        Ok((status, val)) => {
            health.http_status = Some(status);
            health.latency_ms = t0.elapsed().as_millis() as u64;
            let items = val
                .get("vulnerabilities")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let mut vulns = Vec::new();
            for entry in items {
                let cve = match entry.get("cve") {
                    Some(c) => c,
                    None => continue,
                };
                let id = match cve.get("id").and_then(|x| x.as_str()) {
                    Some(s) => s.to_ascii_uppercase(),
                    None => continue,
                };
                let desc = cve
                    .get("descriptions")
                    .and_then(|d| d.as_array())
                    .and_then(|arr| {
                        arr.iter()
                            .find(|item| item.get("lang").and_then(|l| l.as_str()) == Some("en"))
                            .or_else(|| arr.first())
                    })
                    .and_then(|d| d.get("value"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let (cvss_score, cvss_vector, sev_opt) = extract_nvd_cvss(cve.get("metrics"));
                let severity = sev_opt
                    .or_else(|| cvss_score.map(Severity::from_cvss))
                    .unwrap_or(Severity::Medium);

                let cwes: Vec<String> = cve
                    .get("weaknesses")
                    .and_then(|w| w.as_array())
                    .map(|arr| {
                        arr.iter()
                            .flat_map(|item| {
                                item.get("description")
                                    .and_then(|d| d.as_array())
                                    .into_iter()
                                    .flatten()
                            })
                            .filter_map(|d| d.get("value").and_then(|v| v.as_str()))
                            .filter(|s| s.starts_with("CWE-"))
                            .map(|s| s.to_string())
                            .collect()
                    })
                    .unwrap_or_default();

                let refs: Vec<String> = cve
                    .get("references")
                    .and_then(|r| r.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|x| {
                                x.get("url")
                                    .and_then(|u| u.as_str())
                                    .and_then(sanitize_http_url)
                            })
                            .take(6)
                            .collect()
                    })
                    .unwrap_or_else(|| vec![format!("https://nvd.nist.gov/vuln/detail/{}", id)]);

                let published = cve
                    .get("published")
                    .and_then(|p| p.as_str())
                    .and_then(parse_date_loose)
                    .unwrap_or(now);
                let updated = cve
                    .get("lastModified")
                    .and_then(|p| p.as_str())
                    .and_then(parse_date_loose)
                    .unwrap_or(published);

                let title = if desc.is_empty() {
                    id.clone()
                } else {
                    truncate_str(&desc, 120)
                };

                vulns.push(Vulnerability {
                    id,
                    aliases: Vec::new(),
                    title,
                    description: desc,
                    severity,
                    cvss_score,
                    cvss_vector,
                    epss_score: None,
                    epss_percentile: None,
                    ai_risk_score: 0,
                    ai_score_factors: Vec::new(),
                    ai_summary: String::new(),
                    is_kev: false,
                    kev_date_added: None,
                    kev_due_date: None,
                    kev_required_action: None,
                    forensic_triage: None,
                    ransomware_use: false,
                    has_public_exploit: false,
                    is_ai_related: false,
                    vendor: None,
                    product: None,
                    ecosystem: None,
                    patched_version: None,
                    cwes,
                    mitre_tactics: Vec::new(),
                    attack_vectors: Vec::new(),
                    sources: vec!["NIST NVD".to_string()],
                    references: refs,
                    published_at: published,
                    updated_at: updated,
                    first_seen_at: now,
                    epss_delta_24h: None,
                    epss_delta_7d: None,
                    epss_spike: false,
                    kev_days_remaining: None,
                    matched_stack: Vec::new(),
                    triage_status: TriageStatus::New,
                    triage_notes: String::new(),
                });
            }

            health.status = "OK".to_string();
            health.items_fetched = vulns.len();
            health.last_success_at = Some(now);
            (vulns, health)
        }
        Err((status, err)) => {
            health.http_status = status;
            health.latency_ms = t0.elapsed().as_millis() as u64;
            health.status = "ERROR".to_string();
            health.last_error = Some(err);
            (Vec::new(), health)
        }
    }
}

fn extract_nvd_cvss(metrics: Option<&Value>) -> (Option<f64>, Option<String>, Option<Severity>) {
    let m = match metrics {
        Some(v) => v,
        None => return (None, None, None),
    };
    for key in [
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ] {
        if let Some(arr) = m.get(key).and_then(|x| x.as_array()) {
            if let Some(first) = arr.first() {
                let data = first.get("cvssData");
                let score = data
                    .and_then(|d| d.get("baseScore"))
                    .and_then(|s| s.as_f64());
                let vector = data
                    .and_then(|d| d.get("vectorString"))
                    .and_then(|s| s.as_str())
                    .map(str::to_string);
                let sev = data
                    .and_then(|d| d.get("baseSeverity"))
                    .or_else(|| first.get("baseSeverity"))
                    .and_then(|s| s.as_str())
                    .map(Severity::from_str_loose);
                if score.is_some() {
                    return (score, vector, sev);
                }
            }
        }
    }
    (None, None, None)
}

// =========================================================================
// Feed 3: GitHub Security Advisories
// =========================================================================
async fn fetch_github_advisories(http: &reqwest::Client) -> (Vec<Vulnerability>, FeedHealth) {
    let url = "https://api.github.com/advisories?per_page=50";
    let t0 = Instant::now();
    let mut health = base_health(
        "github_advisories",
        "GitHub Security Advisories",
        "Vulnerability DB",
        url,
    );
    let now = Utc::now();

    let resp = tokio::time::timeout(
        REQUEST_TIMEOUT,
        http.get(url)
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", USER_AGENT)
            .send(),
    )
    .await;

    match resp {
        Ok(Ok(r)) => {
            let status = r.status().as_u16();
            health.http_status = Some(status);
            health.latency_ms = t0.elapsed().as_millis() as u64;
            if !r.status().is_success() {
                health.status = "ERROR".to_string();
                health.last_error = Some(format!("HTTP {}", status));
                return (Vec::new(), health);
            }
            let bytes = match read_bounded_bytes(r, MAX_FEED_BYTES).await {
                Ok(b) => b,
                Err(err) => {
                    health.status = "ERROR".to_string();
                    health.last_error = Some(err);
                    return (Vec::new(), health);
                }
            };
            match serde_json::from_slice::<Value>(&bytes) {
                Ok(Value::Array(arr)) => {
                    let mut vulns = Vec::new();
                    for item in arr {
                        let ghsa = item
                            .get("ghsa_id")
                            .and_then(|x| x.as_str())
                            .unwrap_or("")
                            .to_string();
                        let cve_opt = item
                            .get("cve_id")
                            .and_then(|x| x.as_str())
                            .filter(|s| !s.is_empty())
                            .map(|s| s.to_ascii_uppercase());
                        let id = cve_opt.clone().unwrap_or_else(|| ghsa.clone());
                        if id.is_empty() {
                            continue;
                        }
                        let mut aliases = Vec::new();
                        if cve_opt.is_some() && !ghsa.is_empty() {
                            aliases.push(ghsa);
                        }
                        let title = item
                            .get("summary")
                            .and_then(|x| x.as_str())
                            .unwrap_or(&id)
                            .to_string();
                        let desc = item
                            .get("description")
                            .and_then(|x| x.as_str())
                            .unwrap_or(&title)
                            .to_string();
                        let sev_str = item
                            .get("severity")
                            .and_then(|x| x.as_str())
                            .unwrap_or("medium");
                        let severity = Severity::from_str_loose(sev_str);
                        let cvss_score = item.pointer("/cvss/score").and_then(|x| x.as_f64());
                        let cvss_vector = item
                            .pointer("/cvss/vector_string")
                            .and_then(|x| x.as_str())
                            .map(str::to_string);
                        let cwes: Vec<String> = item
                            .get("cwes")
                            .and_then(|x| x.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|c| {
                                        c.get("cwe_id").and_then(|v| v.as_str()).map(str::to_string)
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();

                        let first_vuln = item
                            .get("vulnerabilities")
                            .and_then(|v| v.as_array())
                            .and_then(|a| a.first());
                        let ecosystem = first_vuln
                            .and_then(|v| v.pointer("/package/ecosystem"))
                            .and_then(|x| x.as_str())
                            .map(str::to_string);
                        let product = first_vuln
                            .and_then(|v| v.pointer("/package/name"))
                            .and_then(|x| x.as_str())
                            .map(str::to_string);
                        let patched = first_vuln
                            .and_then(|v| v.get("first_patched_version"))
                            .and_then(|x| x.as_str())
                            .map(str::to_string);

                        let html_url = item
                            .get("html_url")
                            .and_then(|x| x.as_str())
                            .and_then(sanitize_http_url)
                            .into_iter()
                            .collect();
                        let published = item
                            .get("published_at")
                            .and_then(|x| x.as_str())
                            .and_then(parse_date_loose)
                            .unwrap_or(now);
                        let updated = item
                            .get("updated_at")
                            .and_then(|x| x.as_str())
                            .and_then(parse_date_loose)
                            .unwrap_or(published);

                        vulns.push(Vulnerability {
                            id,
                            aliases,
                            title,
                            description: truncate_str(&desc, 1200),
                            severity,
                            cvss_score,
                            cvss_vector,
                            epss_score: None,
                            epss_percentile: None,
                            ai_risk_score: 0,
                            ai_score_factors: Vec::new(),
                            ai_summary: String::new(),
                            is_kev: false,
                            kev_date_added: None,
                            kev_due_date: None,
                            kev_required_action: None,
                            forensic_triage: None,
                            ransomware_use: false,
                            has_public_exploit: false,
                            is_ai_related: false,
                            vendor: None,
                            product,
                            ecosystem,
                            patched_version: patched,
                            cwes,
                            mitre_tactics: Vec::new(),
                            attack_vectors: Vec::new(),
                            sources: vec!["GitHub Advisory".to_string()],
                            references: html_url,
                            published_at: published,
                            updated_at: updated,
                            first_seen_at: now,
                            epss_delta_24h: None,
                            epss_delta_7d: None,
                            epss_spike: false,
                            kev_days_remaining: None,
                            matched_stack: Vec::new(),
                            triage_status: TriageStatus::New,
                            triage_notes: String::new(),
                        });
                    }
                    health.status = "OK".to_string();
                    health.items_fetched = vulns.len();
                    health.last_success_at = Some(now);
                    (vulns, health)
                }
                Ok(_) => {
                    health.status = "ERROR".to_string();
                    health.last_error = Some("Unexpected JSON shape".to_string());
                    (Vec::new(), health)
                }
                Err(e) => {
                    health.status = "ERROR".to_string();
                    health.last_error = Some(e.to_string());
                    (Vec::new(), health)
                }
            }
        }
        Ok(Err(e)) => {
            health.latency_ms = t0.elapsed().as_millis() as u64;
            health.status = "ERROR".to_string();
            health.last_error = Some(e.without_url().to_string());
            (Vec::new(), health)
        }
        Err(_) => {
            health.latency_ms = t0.elapsed().as_millis() as u64;
            health.status = "ERROR".to_string();
            health.last_error = Some("Request timeout".to_string());
            (Vec::new(), health)
        }
    }
}

// =========================================================================
// Feed 4: CIRCL Vulnerability Lookup (mixed OSV/CVE schema)
// =========================================================================
async fn fetch_circl_recent(http: &reqwest::Client) -> (Vec<Vulnerability>, FeedHealth) {
    let url = "https://cve.circl.lu/api/last/40";
    let t0 = Instant::now();
    let mut health = base_health(
        "circl_cve",
        "CIRCL Vulnerability Feed",
        "Vulnerability DB",
        url,
    );
    let now = Utc::now();

    match send_get_json(http, url).await {
        Ok((status, Value::Array(arr))) => {
            health.http_status = Some(status);
            health.latency_ms = t0.elapsed().as_millis() as u64;
            let mut vulns = Vec::new();
            for item in arr {
                if let Some(v) = parse_osv_or_cve_json(&item, "CIRCL Lookup", false, now) {
                    vulns.push(v);
                }
            }
            health.status = "OK".to_string();
            health.items_fetched = vulns.len();
            health.last_success_at = Some(now);
            (vulns, health)
        }
        Ok((status, _)) => {
            health.http_status = Some(status);
            health.latency_ms = t0.elapsed().as_millis() as u64;
            health.status = "ERROR".to_string();
            health.last_error = Some("Expected JSON array".to_string());
            (Vec::new(), health)
        }
        Err((status, err)) => {
            health.http_status = status;
            health.latency_ms = t0.elapsed().as_millis() as u64;
            health.status = "ERROR".to_string();
            health.last_error = Some(err);
            (Vec::new(), health)
        }
    }
}

// =========================================================================
// Feed 5: Google OSV.dev AI / LLM Supply-Chain Watchlist
// =========================================================================
async fn fetch_osv_ai_watchlist(http: &reqwest::Client) -> (Vec<Vulnerability>, FeedHealth) {
    let url = "https://api.osv.dev/v1/querybatch";
    let t0 = Instant::now();
    let mut health = base_health(
        "osv_ai",
        "OSV.dev AI/ML Supply Chain",
        "AI Supply Chain",
        url,
    );
    let now = Utc::now();

    let packages = [
        "langchain",
        "langchain-core",
        "transformers",
        "torch",
        "vllm",
        "litellm",
        "gradio",
        "ray",
        "mlflow",
        "openai",
        "mcp",
        "picklescan",
    ];
    let queries: Vec<Value> = packages
        .iter()
        .map(|name| serde_json::json!({ "package": { "name": name, "ecosystem": "PyPI" } }))
        .collect();
    let body = serde_json::json!({ "queries": queries });

    let resp = tokio::time::timeout(
        REQUEST_TIMEOUT,
        http.post(url)
            .header("User-Agent", USER_AGENT)
            .json(&body)
            .send(),
    )
    .await;

    let mut id_set = HashSet::new();
    let mut ids = Vec::new();

    match resp {
        Ok(Ok(r)) => {
            let status = r.status().as_u16();
            health.http_status = Some(status);
            if !r.status().is_success() {
                health.latency_ms = t0.elapsed().as_millis() as u64;
                health.status = "ERROR".to_string();
                health.last_error = Some(format!("HTTP {}", status));
                return (Vec::new(), health);
            }
            let bytes = match read_bounded_bytes(r, MAX_FEED_BYTES).await {
                Ok(b) => b,
                Err(err) => {
                    health.latency_ms = t0.elapsed().as_millis() as u64;
                    health.status = "ERROR".to_string();
                    health.last_error = Some(err);
                    return (Vec::new(), health);
                }
            };
            if let Ok(val) = serde_json::from_slice::<Value>(&bytes) {
                if let Some(results) = val.get("results").and_then(|x| x.as_array()) {
                    for res in results {
                        if let Some(vulns) = res.get("vulns").and_then(|x| x.as_array()) {
                            // Take up to 4 newest-listed per package (often sorted chronologically so take tail!)
                            for entry in vulns.iter().rev().take(4) {
                                if let Some(vid) = entry.get("id").and_then(|x| x.as_str()) {
                                    if id_set.insert(vid.to_string()) {
                                        ids.push(vid.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(Err(e)) => {
            health.latency_ms = t0.elapsed().as_millis() as u64;
            health.status = "ERROR".to_string();
            health.last_error = Some(e.without_url().to_string());
            return (Vec::new(), health);
        }
        Err(_) => {
            health.latency_ms = t0.elapsed().as_millis() as u64;
            health.status = "ERROR".to_string();
            health.last_error = Some("Timeout".to_string());
            return (Vec::new(), health);
        }
    }

    ids.truncate(22);
    let client = http.clone();
    let fetched: Vec<Option<Vulnerability>> = stream::iter(ids)
        .map(|vid| {
            let c = client.clone();
            async move {
                let vurl = format!("https://api.osv.dev/v1/vulns/{}", vid);
                match send_get_json(&c, &vurl).await {
                    Ok((_, val)) => parse_osv_or_cve_json(&val, "OSV AI Watchlist", true, now),
                    Err(_) => None,
                }
            }
        })
        .buffer_unordered(6)
        .collect()
        .await;

    let vulns: Vec<Vulnerability> = fetched.into_iter().flatten().collect();
    health.latency_ms = t0.elapsed().as_millis() as u64;
    health.status = "OK".to_string();
    health.items_fetched = vulns.len();
    health.last_success_at = Some(now);
    (vulns, health)
}

fn parse_osv_or_cve_json(
    item: &Value,
    source_name: &str,
    force_ai: bool,
    now: DateTime<Utc>,
) -> Option<Vulnerability> {
    // Handle CVE 5.0 records if CIRCL returns one
    if let Some(meta) = item.get("cveMetadata") {
        let cve_id = meta
            .get("cveId")
            .and_then(|x| x.as_str())?
            .to_ascii_uppercase();
        let cna = item.pointer("/containers/cna");
        let desc = cna
            .and_then(|c| c.get("descriptions"))
            .and_then(|d| d.as_array())
            .and_then(|arr| arr.first())
            .and_then(|d| d.get("value"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let title = cna
            .and_then(|c| c.get("title"))
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| truncate_str(&desc, 120));
        let vendor = cna
            .and_then(|c| c.get("affected"))
            .and_then(|a| a.as_array())
            .and_then(|arr| arr.first())
            .and_then(|x| x.get("vendor"))
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let product = cna
            .and_then(|c| c.get("affected"))
            .and_then(|a| a.as_array())
            .and_then(|arr| arr.first())
            .and_then(|x| x.get("product"))
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let published = meta
            .get("datePublished")
            .and_then(|x| x.as_str())
            .and_then(parse_date_loose)
            .unwrap_or(now);
        let refs: Vec<String> = cna
            .and_then(|c| c.get("references"))
            .and_then(|r| r.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| {
                        x.get("url")
                            .and_then(|u| u.as_str())
                            .and_then(sanitize_http_url)
                    })
                    .take(5)
                    .collect()
            })
            .unwrap_or_default();

        return Some(Vulnerability {
            id: cve_id,
            aliases: Vec::new(),
            title,
            description: truncate_str(&desc, 1200),
            severity: Severity::Medium,
            cvss_score: None,
            cvss_vector: None,
            epss_score: None,
            epss_percentile: None,
            ai_risk_score: 0,
            ai_score_factors: Vec::new(),
            ai_summary: String::new(),
            is_kev: false,
            kev_date_added: None,
            kev_due_date: None,
            kev_required_action: None,
            forensic_triage: None,
            ransomware_use: false,
            has_public_exploit: false,
            is_ai_related: force_ai,
            vendor,
            product,
            ecosystem: None,
            patched_version: None,
            cwes: Vec::new(),
            mitre_tactics: Vec::new(),
            attack_vectors: Vec::new(),
            sources: vec![source_name.to_string()],
            references: refs,
            published_at: published,
            updated_at: published,
            first_seen_at: now,
            epss_delta_24h: None,
            epss_delta_7d: None,
            epss_spike: false,
            kev_days_remaining: None,
            matched_stack: Vec::new(),
            triage_status: TriageStatus::New,
            triage_notes: String::new(),
        });
    }

    // Standard OSV / PYSEC / GHSA schema
    let raw_id = item.get("id").and_then(|x| x.as_str())?.to_string();
    let aliases_all: Vec<String> = item
        .get("aliases")
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_ascii_uppercase()))
                .collect()
        })
        .unwrap_or_default();
    let cve_alias = aliases_all.iter().find(|a| a.starts_with("CVE-")).cloned();
    let id = if raw_id.to_ascii_uppercase().starts_with("CVE-") {
        raw_id.to_ascii_uppercase()
    } else if let Some(c) = cve_alias {
        c
    } else {
        raw_id.clone()
    };

    let mut aliases = aliases_all;
    if raw_id != id && !aliases.contains(&raw_id) {
        aliases.push(raw_id.clone());
    }
    aliases.retain(|a| a != &id);

    let details = item
        .get("details")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let summary = item
        .get("summary")
        .and_then(|x| x.as_str())
        .map(str::to_string)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            if details.is_empty() {
                id.clone()
            } else {
                truncate_str(&details, 120)
            }
        });

    let affected_first = item
        .get("affected")
        .and_then(|a| a.as_array())
        .and_then(|a| a.first());
    let ecosystem = affected_first
        .and_then(|a| a.pointer("/package/ecosystem"))
        .and_then(|x| x.as_str())
        .map(str::to_string);
    let product = affected_first
        .and_then(|a| a.pointer("/package/name"))
        .and_then(|x| x.as_str())
        .map(str::to_string);
    let patched = affected_first
        .and_then(|a| a.get("ranges"))
        .and_then(|r| r.as_array())
        .and_then(|arr| arr.first())
        .and_then(|r| r.get("events"))
        .and_then(|e| e.as_array())
        .and_then(|events| {
            events
                .iter()
                .find_map(|ev| ev.get("fixed").and_then(|f| f.as_str()))
        })
        .map(str::to_string);

    let cvss_vector = item
        .get("severity")
        .and_then(|s| s.as_array())
        .and_then(|arr| arr.first())
        .and_then(|s| s.get("score"))
        .and_then(|v| v.as_str())
        .map(str::to_string);

    let db_sev = item
        .pointer("/database_specific/severity")
        .and_then(|x| x.as_str())
        .map(Severity::from_str_loose)
        .unwrap_or(Severity::High);

    let refs: Vec<String> = item
        .get("references")
        .and_then(|r| r.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| {
                    x.get("url")
                        .and_then(|u| u.as_str())
                        .and_then(sanitize_http_url)
                })
                .take(6)
                .collect()
        })
        .unwrap_or_default();

    let published = item
        .get("published")
        .and_then(|x| x.as_str())
        .and_then(parse_date_loose)
        .unwrap_or(now);
    let updated = item
        .get("modified")
        .and_then(|x| x.as_str())
        .and_then(parse_date_loose)
        .unwrap_or(published);

    let cwes: Vec<String> = item
        .pointer("/database_specific/cwe_ids")
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_ascii_uppercase()))
                .collect()
        })
        .unwrap_or_default();

    Some(Vulnerability {
        id,
        aliases,
        title: summary,
        description: truncate_str(if details.is_empty() { "" } else { &details }, 1200),
        severity: db_sev,
        cvss_score: None,
        cvss_vector,
        epss_score: None,
        epss_percentile: None,
        ai_risk_score: 0,
        ai_score_factors: Vec::new(),
        ai_summary: String::new(),
        is_kev: false,
        kev_date_added: None,
        kev_due_date: None,
        kev_required_action: None,
        forensic_triage: None,
        ransomware_use: false,
        has_public_exploit: false,
        is_ai_related: force_ai,
        vendor: None,
        product,
        ecosystem,
        patched_version: patched,
        cwes,
        mitre_tactics: Vec::new(),
        attack_vectors: Vec::new(),
        sources: vec![source_name.to_string()],
        references: refs,
        published_at: published,
        updated_at: updated,
        first_seen_at: now,
        epss_delta_24h: None,
        epss_delta_7d: None,
        epss_spike: false,
        kev_days_remaining: None,
        matched_stack: Vec::new(),
        triage_status: TriageStatus::New,
        triage_notes: String::new(),
    })
}

// =========================================================================
// Feed 6 & 7: FIRST.org EPSS Global Top + CVE Batch Enrichment
// =========================================================================
async fn fetch_epss_top(http: &reqwest::Client) -> (Vec<EpssTopThreat>, FeedHealth) {
    let url = "https://api.first.org/data/v1/epss?order=!epss&limit=25";
    let t0 = Instant::now();
    let mut health = base_health(
        "first_epss_top",
        "FIRST.org EPSS Top Risks",
        "Exploit Prediction",
        url,
    );
    let now = Utc::now();

    match send_get_json(http, url).await {
        Ok((status, val)) => {
            health.http_status = Some(status);
            health.latency_ms = t0.elapsed().as_millis() as u64;
            let items = parse_epss_data(&val);
            health.status = "OK".to_string();
            health.items_fetched = items.len();
            health.last_success_at = Some(now);
            (items, health)
        }
        Err((status, err)) => {
            health.http_status = status;
            health.latency_ms = t0.elapsed().as_millis() as u64;
            health.status = "ERROR".to_string();
            health.last_error = Some(err);
            (Vec::new(), health)
        }
    }
}

async fn fetch_epss_batch(
    http: &reqwest::Client,
    cve_ids: &[String],
) -> (HashMap<String, (f64, f64)>, FeedHealth) {
    let base_url = "https://api.first.org/data/v1/epss";
    let t0 = Instant::now();
    let mut health = base_health(
        "first_epss_enrich",
        "FIRST.org EPSS CVE Scorer",
        "Exploit Prediction",
        base_url,
    );
    let now = Utc::now();
    let mut out = HashMap::new();

    if cve_ids.is_empty() {
        health.status = "OK".to_string();
        health.last_success_at = Some(now);
        return (out, health);
    }

    let chunks: Vec<String> = cve_ids.chunks(40).map(|c| c.join(",")).collect();
    let mut last_status = None;
    let mut last_err = None;

    for chunk in chunks {
        let url = format!("{}?cve={}", base_url, chunk);
        match send_get_json(http, &url).await {
            Ok((status, val)) => {
                last_status = Some(status);
                for item in parse_epss_data(&val) {
                    out.insert(item.cve, (item.epss, item.percentile));
                }
            }
            Err((status, err)) => {
                last_status = status;
                last_err = Some(err);
            }
        }
    }

    health.http_status = last_status;
    health.latency_ms = t0.elapsed().as_millis() as u64;
    if out.is_empty() && last_err.is_some() {
        health.status = "ERROR".to_string();
        health.last_error = last_err;
    } else {
        health.status = "OK".to_string();
        health.items_fetched = out.len();
        health.last_success_at = Some(now);
    }
    (out, health)
}

fn parse_epss_data(val: &Value) -> Vec<EpssTopThreat> {
    val.get("data")
        .and_then(|d| d.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|item| {
                    let cve = item
                        .get("cve")
                        .and_then(|x| x.as_str())?
                        .to_ascii_uppercase();
                    let epss = val_to_f64(item.get("epss"))?;
                    let percentile = val_to_f64(item.get("percentile")).unwrap_or(0.0);
                    let date = item
                        .get("date")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string();
                    Some(EpssTopThreat {
                        cve,
                        epss,
                        percentile,
                        date,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

// =========================================================================
// Feeds 8-10: SANS ISC INFOCON, Top Ports, Top Attackers
// =========================================================================
async fn fetch_sans_infocon(http: &reqwest::Client) -> (Option<String>, FeedHealth) {
    let url = "https://isc.sans.edu/api/infocon?json";
    let t0 = Instant::now();
    let mut health = base_health(
        "sans_infocon",
        "SANS ISC INFOCON Status",
        "Network Telemetry",
        url,
    );
    let now = Utc::now();

    match send_get_json(http, url).await {
        Ok((status, val)) => {
            health.http_status = Some(status);
            health.latency_ms = t0.elapsed().as_millis() as u64;
            let st = val
                .get("status")
                .and_then(|s| s.as_str())
                .map(str::to_string);
            health.status = "OK".to_string();
            health.items_fetched = if st.is_some() { 1 } else { 0 };
            health.last_success_at = Some(now);
            (st, health)
        }
        Err((status, err)) => {
            health.http_status = status;
            health.latency_ms = t0.elapsed().as_millis() as u64;
            health.status = "ERROR".to_string();
            health.last_error = Some(err);
            (None, health)
        }
    }
}

async fn fetch_sans_top_ports(http: &reqwest::Client) -> (Vec<PortAttack>, FeedHealth) {
    let url = "https://isc.sans.edu/api/topports/records/12?json";
    let t0 = Instant::now();
    let mut health = base_health(
        "sans_ports",
        "SANS ISC Top Attacked Ports",
        "Network Telemetry",
        url,
    );
    let now = Utc::now();

    match send_get_json(http, url).await {
        Ok((status, val)) => {
            health.http_status = Some(status);
            health.latency_ms = t0.elapsed().as_millis() as u64;
            let mut ports = Vec::new();

            // PITFALL HANDLED: SANS returns {"0":{...}, "1":{...}, "date":"...", "limit":12}
            if let Some(obj) = val.as_object() {
                for (_, entry) in obj {
                    if let Some(p_obj) = entry.as_object() {
                        if let Some(port) = val_to_u64(p_obj.get("targetport")) {
                            let port_u16 = port as u16;
                            ports.push(PortAttack {
                                rank: val_to_u64(p_obj.get("rank")).unwrap_or(0) as u32,
                                port: port_u16,
                                service_name: well_known_port_name(port_u16).to_string(),
                                records: val_to_u64(p_obj.get("records")).unwrap_or(0),
                                targets: val_to_u64(p_obj.get("targets")).unwrap_or(0),
                                sources: val_to_u64(p_obj.get("sources")).unwrap_or(0),
                            });
                        }
                    }
                }
            }
            ports.sort_by(|a, b| a.rank.cmp(&b.rank).then_with(|| b.records.cmp(&a.records)));
            health.status = "OK".to_string();
            health.items_fetched = ports.len();
            health.last_success_at = Some(now);
            (ports, health)
        }
        Err((status, err)) => {
            health.http_status = status;
            health.latency_ms = t0.elapsed().as_millis() as u64;
            health.status = "ERROR".to_string();
            health.last_error = Some(err);
            (Vec::new(), health)
        }
    }
}

async fn fetch_sans_top_ips(http: &reqwest::Client) -> (Vec<AttackerIp>, FeedHealth) {
    let url = "https://isc.sans.edu/api/sources/attacks/20?json";
    let t0 = Instant::now();
    let mut health = base_health(
        "sans_ips",
        "SANS ISC Top Attacking IPs",
        "Network Telemetry",
        url,
    );
    let now = Utc::now();

    match send_get_json(http, url).await {
        Ok((status, Value::Array(arr))) => {
            health.http_status = Some(status);
            health.latency_ms = t0.elapsed().as_millis() as u64;
            let ips: Vec<AttackerIp> = arr
                .iter()
                .filter_map(|item| {
                    let ip = item.get("ip").and_then(|x| x.as_str())?.to_string();
                    Some(AttackerIp {
                        ip,
                        attacks: val_to_u64(item.get("attacks")).unwrap_or(0),
                        count: val_to_u64(item.get("count")).unwrap_or(0),
                        first_seen: item
                            .get("firstseen")
                            .and_then(|x| x.as_str())
                            .unwrap_or("")
                            .to_string(),
                        last_seen: item
                            .get("lastseen")
                            .and_then(|x| x.as_str())
                            .unwrap_or("")
                            .to_string(),
                    })
                })
                .collect();
            health.status = "OK".to_string();
            health.items_fetched = ips.len();
            health.last_success_at = Some(now);
            (ips, health)
        }
        Ok((status, _)) => {
            health.http_status = Some(status);
            health.latency_ms = t0.elapsed().as_millis() as u64;
            health.status = "ERROR".to_string();
            health.last_error = Some("Expected array".to_string());
            (Vec::new(), health)
        }
        Err((status, err)) => {
            health.http_status = status;
            health.latency_ms = t0.elapsed().as_millis() as u64;
            health.status = "ERROR".to_string();
            health.last_error = Some(err);
            (Vec::new(), health)
        }
    }
}

// =========================================================================
// Feeds 11-13: Feodo Tracker Botnet C2, OpenPhish, Emerging Threats
// =========================================================================
async fn fetch_feodo_c2(http: &reqwest::Client) -> (Vec<BotnetC2>, FeedHealth) {
    let url = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json";
    let t0 = Instant::now();
    let mut health = base_health(
        "feodo_c2",
        "abuse.ch Feodo Botnet C2s",
        "IOC & Malware",
        url,
    );
    let now = Utc::now();

    match send_get_json(http, url).await {
        Ok((status, Value::Array(arr))) => {
            health.http_status = Some(status);
            health.latency_ms = t0.elapsed().as_millis() as u64;
            let c2s: Vec<BotnetC2> = arr
                .iter()
                .filter_map(|item| {
                    let ip_address = item.get("ip_address").and_then(|x| x.as_str())?.to_string();
                    Some(BotnetC2 {
                        ip_address,
                        port: val_to_u64(item.get("port")).unwrap_or(0) as u16,
                        status: item
                            .get("status")
                            .and_then(|x| x.as_str())
                            .unwrap_or("unknown")
                            .to_string(),
                        hostname: item
                            .get("hostname")
                            .and_then(|x| x.as_str())
                            .map(str::to_string),
                        as_number: val_to_u64(item.get("as_number")),
                        as_name: item
                            .get("as_name")
                            .and_then(|x| x.as_str())
                            .map(str::to_string),
                        country: item
                            .get("country")
                            .and_then(|x| x.as_str())
                            .map(str::to_string),
                        malware: item
                            .get("malware")
                            .and_then(|x| x.as_str())
                            .unwrap_or("Botnet")
                            .to_string(),
                        first_seen: item
                            .get("first_seen")
                            .and_then(|x| x.as_str())
                            .map(str::to_string),
                        last_online: item
                            .get("last_online")
                            .and_then(|x| x.as_str())
                            .map(str::to_string),
                    })
                })
                .collect();
            health.status = "OK".to_string();
            health.items_fetched = c2s.len();
            health.last_success_at = Some(now);
            (c2s, health)
        }
        Ok((status, _)) => {
            health.http_status = Some(status);
            health.latency_ms = t0.elapsed().as_millis() as u64;
            health.status = "ERROR".to_string();
            health.last_error = Some("Expected array".to_string());
            (Vec::new(), health)
        }
        Err((status, err)) => {
            health.http_status = status;
            health.latency_ms = t0.elapsed().as_millis() as u64;
            health.status = "ERROR".to_string();
            health.last_error = Some(err);
            (Vec::new(), health)
        }
    }
}

async fn fetch_openphish(http: &reqwest::Client) -> (Vec<PhishingUrl>, usize, FeedHealth) {
    let url = "https://openphish.com/feed.txt";
    let t0 = Instant::now();
    let mut health = base_health(
        "openphish",
        "OpenPhish Live Phishing Feed",
        "IOC & Malware",
        url,
    );
    let now = Utc::now();

    match send_get_text(http, url).await {
        Ok((status, text)) => {
            health.http_status = Some(status);
            health.latency_ms = t0.elapsed().as_millis() as u64;
            let lines: Vec<&str> = text
                .lines()
                .map(str::trim)
                .filter(|l| l.starts_with("http"))
                .collect();
            let total = lines.len();
            let sample: Vec<PhishingUrl> = lines
                .into_iter()
                .take(80)
                .map(|raw_url| {
                    let domain = url::Url::parse(raw_url)
                        .ok()
                        .and_then(|u| u.host_str().map(str::to_string))
                        .unwrap_or_else(|| "unknown".to_string());
                    let lower = raw_url.to_ascii_lowercase();
                    let brand = if lower.contains("microsoft")
                        || lower.contains("office")
                        || lower.contains("outlook")
                    {
                        Some("Microsoft".to_string())
                    } else if lower.contains("google") || lower.contains("gmail") {
                        Some("Google".to_string())
                    } else if lower.contains("paypal") {
                        Some("PayPal".to_string())
                    } else if lower.contains("apple") || lower.contains("icloud") {
                        Some("Apple".to_string())
                    } else if lower.contains("amazon") || lower.contains("aws") {
                        Some("Amazon / AWS".to_string())
                    } else if lower.contains("docusign") {
                        Some("DocuSign".to_string())
                    } else if lower.contains("github") {
                        Some("GitHub".to_string())
                    } else if lower.contains("meta")
                        || lower.contains("facebook")
                        || lower.contains("instagram")
                    {
                        Some("Meta".to_string())
                    } else {
                        None
                    };
                    PhishingUrl {
                        url: raw_url.to_string(),
                        domain,
                        suspected_brand: brand,
                    }
                })
                .collect();

            health.status = "OK".to_string();
            health.items_fetched = total;
            health.last_success_at = Some(now);
            (sample, total, health)
        }
        Err((status, err)) => {
            health.http_status = status;
            health.latency_ms = t0.elapsed().as_millis() as u64;
            health.status = "ERROR".to_string();
            health.last_error = Some(err);
            (Vec::new(), 0, health)
        }
    }
}

async fn fetch_emerging_threats(
    http: &reqwest::Client,
) -> (HashSet<String>, Vec<String>, usize, FeedHealth) {
    let url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt";
    let t0 = Instant::now();
    let mut health = base_health(
        "et_compromised",
        "Emerging Threats Compromised IPs",
        "IOC & Malware",
        url,
    );
    let now = Utc::now();

    match send_get_text(http, url).await {
        Ok((status, text)) => {
            health.http_status = Some(status);
            health.latency_ms = t0.elapsed().as_millis() as u64;
            let mut set = HashSet::new();
            let mut sample = Vec::new();
            for line in text.lines() {
                let l = line.trim();
                if l.is_empty() || l.starts_with('#') {
                    continue;
                }
                if set.insert(l.to_string()) && sample.len() < 100 {
                    sample.push(l.to_string());
                }
            }
            let total = set.len();
            health.status = "OK".to_string();
            health.items_fetched = total;
            health.last_success_at = Some(now);
            (set, sample, total, health)
        }
        Err((status, err)) => {
            health.http_status = status;
            health.latency_ms = t0.elapsed().as_millis() as u64;
            health.status = "ERROR".to_string();
            health.last_error = Some(err);
            (HashSet::new(), Vec::new(), 0, health)
        }
    }
}

// =========================================================================
// Feed 14+: Hacker News Cybersecurity Wire (Algolia) + 11 RSS/Atom Feeds
// =========================================================================
async fn fetch_hn_algolia(http: &reqwest::Client) -> (Vec<ThreatNewsItem>, FeedHealth) {
    let url = "https://hn.algolia.com/api/v1/search_by_date?query=CVE+OR+zero-day+OR+vulnerability+OR+ransomware&tags=story&hitsPerPage=30";
    let t0 = Instant::now();
    let mut health = base_health(
        "hn_security",
        "Hacker News Security Wire",
        "Community",
        "https://hn.algolia.com",
    );
    let now = Utc::now();

    match send_get_json(http, url).await {
        Ok((status, val)) => {
            health.http_status = Some(status);
            health.latency_ms = t0.elapsed().as_millis() as u64;
            let hits = val
                .get("hits")
                .and_then(|x| x.as_array())
                .cloned()
                .unwrap_or_default();
            let mut items = Vec::new();
            for h in hits {
                let obj_id = match h.get("objectID").and_then(|x| x.as_str()) {
                    Some(id) => id,
                    None => continue,
                };
                let title = h
                    .get("title")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if title.is_empty() {
                    continue;
                }
                let hn_discussion = format!("https://news.ycombinator.com/item?id={}", obj_id);
                let link = h
                    .get("url")
                    .and_then(|x| x.as_str())
                    .and_then(sanitize_http_url)
                    .unwrap_or_else(|| hn_discussion.clone());
                let points = h.get("points").and_then(|x| x.as_u64()).unwrap_or(0);
                let comments = h.get("num_comments").and_then(|x| x.as_u64()).unwrap_or(0);
                let published = h
                    .get("created_at")
                    .and_then(|x| x.as_str())
                    .and_then(parse_date_loose)
                    .unwrap_or(now);

                items.push(ThreatNewsItem {
                    id: format!("hn:{}", obj_id),
                    source: "Hacker News".to_string(),
                    category: "Community".to_string(),
                    title,
                    summary: format!(
                        "Community security discussion ({} points, {} comments).",
                        points, comments
                    ),
                    url: link,
                    published_at: published,
                    first_seen_at: now,
                    extracted_cves: Vec::new(),
                    severity: Severity::Info,
                    ai_risk_score: 0,
                    tags: Vec::new(),
                    is_vulnerability_news: false,
                    is_ai_related: false,
                    ai_triage_note: String::new(),
                });
            }
            health.status = "OK".to_string();
            health.items_fetched = items.len();
            health.last_success_at = Some(now);
            (items, health)
        }
        Err((status, err)) => {
            health.http_status = status;
            health.latency_ms = t0.elapsed().as_millis() as u64;
            health.status = "ERROR".to_string();
            health.last_error = Some(err);
            (Vec::new(), health)
        }
    }
}

async fn fetch_all_rss(
    http: &reqwest::Client,
    disabled_feeds: &HashSet<String>,
) -> Vec<(Vec<ThreatNewsItem>, FeedHealth)> {
    let futs = RSS_FEEDS.iter().map(|def| async move {
        let skipped = disabled_feeds.contains(&def.id.to_ascii_lowercase())
            || disabled_feeds.contains(&def.name.to_ascii_lowercase());
        if skipped {
            (
                Vec::new(),
                disabled_health(def.id, def.name, def.category, def.url),
            )
        } else {
            fetch_single_rss(http, def).await
        }
    });
    futures::future::join_all(futs).await
}

async fn fetch_single_rss(
    http: &reqwest::Client,
    def: &RssFeedDef,
) -> (Vec<ThreatNewsItem>, FeedHealth) {
    let t0 = Instant::now();
    let mut health = base_health(def.id, def.name, def.category, def.url);
    let now = Utc::now();

    let resp = tokio::time::timeout(
        REQUEST_TIMEOUT,
        http.get(def.url)
            .header("User-Agent", USER_AGENT)
            .header(
                "Accept",
                "application/rss+xml, application/atom+xml, application/xml, text/xml, */*",
            )
            .send(),
    )
    .await;

    match resp {
        Ok(Ok(r)) => {
            let status = r.status().as_u16();
            health.http_status = Some(status);
            if !r.status().is_success() {
                health.latency_ms = t0.elapsed().as_millis() as u64;
                health.status = "ERROR".to_string();
                health.last_error = Some(format!("HTTP {}", status));
                return (Vec::new(), health);
            }
            match read_bounded_bytes(r, MAX_FEED_BYTES).await {
                Ok(bytes) => {
                    health.latency_ms = t0.elapsed().as_millis() as u64;
                    match feed_rs::parser::parse(&bytes[..]) {
                        Ok(feed) => {
                            let mut items = Vec::new();
                            for entry in feed.entries.into_iter().take(40) {
                                let title = entry
                                    .title
                                    .map(|t| strip_html_and_clean(&t.content))
                                    .unwrap_or_default();
                                if title.is_empty() {
                                    continue;
                                }
                                let link = entry
                                    .links
                                    .into_iter()
                                    .next()
                                    .and_then(|l| sanitize_http_url(&l.href))
                                    .unwrap_or_else(|| def.url.to_string());
                                let raw_summary = entry
                                    .summary
                                    .map(|s| s.content)
                                    .or_else(|| entry.content.and_then(|c| c.body))
                                    .unwrap_or_default();
                                let clean_summary =
                                    truncate_str(&strip_html_and_clean(&raw_summary), 420);
                                let published = entry.published.or(entry.updated).unwrap_or(now);

                                let id_basis = if !entry.id.is_empty() {
                                    entry.id
                                } else {
                                    format!("{}:{}", link, title)
                                };
                                let item_id = format!("{}:{}", def.id, id_basis);

                                items.push(ThreatNewsItem {
                                    id: item_id,
                                    source: def.name.to_string(),
                                    category: def.category.to_string(),
                                    title,
                                    summary: if clean_summary.is_empty() {
                                        format!("Published by {}", def.name)
                                    } else {
                                        clean_summary
                                    },
                                    url: link,
                                    published_at: published,
                                    first_seen_at: now,
                                    extracted_cves: Vec::new(),
                                    severity: Severity::Info,
                                    ai_risk_score: 0,
                                    tags: Vec::new(),
                                    is_vulnerability_news: false,
                                    is_ai_related: false,
                                    ai_triage_note: String::new(),
                                });
                            }
                            health.status = "OK".to_string();
                            health.items_fetched = items.len();
                            health.last_success_at = Some(now);
                            (items, health)
                        }
                        Err(e) => {
                            health.status = "ERROR".to_string();
                            health.last_error = Some(format!("Feed parse error: {}", e));
                            (Vec::new(), health)
                        }
                    }
                }
                Err(e) => {
                    health.latency_ms = t0.elapsed().as_millis() as u64;
                    health.status = "ERROR".to_string();
                    health.last_error = Some(e.to_string());
                    (Vec::new(), health)
                }
            }
        }
        Ok(Err(e)) => {
            health.latency_ms = t0.elapsed().as_millis() as u64;
            health.status = "ERROR".to_string();
            health.last_error = Some(e.without_url().to_string());
            (Vec::new(), health)
        }
        Err(_) => {
            health.latency_ms = t0.elapsed().as_millis() as u64;
            health.status = "ERROR".to_string();
            health.last_error = Some("Request timeout".to_string());
            (Vec::new(), health)
        }
    }
}

// =========================================================================
// Helpers
// =========================================================================
fn base_health(id: &str, name: &str, category: &str, url: &str) -> FeedHealth {
    FeedHealth {
        id: id.to_string(),
        name: name.to_string(),
        category: category.to_string(),
        url: url.to_string(),
        status: "PENDING".to_string(),
        http_status: None,
        latency_ms: 0,
        items_fetched: 0,
        last_success_at: None,
        last_error: None,
    }
}

async fn read_bounded_bytes(
    mut resp: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    if let Some(len) = resp.content_length() {
        if len > max_bytes as u64 {
            return Err(format!("Response exceeded {} byte limit", max_bytes));
        }
    }
    let mut buf = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| format!("Stream read error: {}", e.without_url()))?
    {
        if buf.len().saturating_add(chunk.len()) > max_bytes {
            return Err(format!("Response exceeded {} byte limit", max_bytes));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

async fn send_get_json(
    http: &reqwest::Client,
    url: &str,
) -> Result<(u16, Value), (Option<u16>, String)> {
    let resp = tokio::time::timeout(
        REQUEST_TIMEOUT,
        http.get(url).header("User-Agent", USER_AGENT).send(),
    )
    .await
    .map_err(|_| (None, "Request timeout".to_string()))?
    .map_err(|e| (None, e.without_url().to_string()))?;

    let status = resp.status().as_u16();
    if !resp.status().is_success() {
        return Err((Some(status), format!("HTTP {}", status)));
    }
    let bytes = read_bounded_bytes(resp, MAX_FEED_BYTES)
        .await
        .map_err(|e| (Some(status), e))?;
    let val = serde_json::from_slice::<Value>(&bytes)
        .map_err(|e| (Some(status), format!("JSON decode error: {}", e)))?;
    Ok((status, val))
}

async fn send_get_text(
    http: &reqwest::Client,
    url: &str,
) -> Result<(u16, String), (Option<u16>, String)> {
    let resp = tokio::time::timeout(
        REQUEST_TIMEOUT,
        http.get(url).header("User-Agent", USER_AGENT).send(),
    )
    .await
    .map_err(|_| (None, "Request timeout".to_string()))?
    .map_err(|e| (None, e.without_url().to_string()))?;

    let status = resp.status().as_u16();
    if !resp.status().is_success() {
        return Err((Some(status), format!("HTTP {}", status)));
    }
    let bytes = read_bounded_bytes(resp, MAX_FEED_BYTES)
        .await
        .map_err(|e| (Some(status), e))?;
    Ok((status, String::from_utf8_lossy(&bytes).into_owned()))
}

fn val_to_f64(v: Option<&Value>) -> Option<f64> {
    match v? {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse::<f64>().ok(),
        _ => None,
    }
}

fn val_to_u64(v: Option<&Value>) -> Option<u64> {
    match v? {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.trim().parse::<u64>().ok(),
        _ => None,
    }
}

fn parse_date_loose(raw: &str) -> Option<DateTime<Utc>> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    if let Ok(dt) = DateTime::parse_from_rfc2822(s) {
        return Some(dt.with_timezone(&Utc));
    }
    for fmt in [
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
    ] {
        if let Ok(ndt) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(Utc.from_utc_datetime(&ndt));
        }
    }
    if let Ok(nd) = NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        let ndt = nd.and_hms_opt(12, 0, 0)?;
        return Some(Utc.from_utc_datetime(&ndt));
    }
    None
}

fn well_known_port_name(port: u16) -> &'static str {
    match port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        111 => "RPCbind",
        123 => "NTP",
        135 => "MS-RPC",
        139 => "NetBIOS",
        143 => "IMAP",
        161 => "SNMP",
        389 => "LDAP",
        443 => "HTTPS",
        445 => "SMB",
        502 => "Modbus ICS",
        587 => "SMTP-TLS",
        993 => "IMAPS",
        1433 => "MSSQL",
        1521 => "Oracle DB",
        2049 => "NFS",
        2222 => "SSH-Alt",
        2375 => "Docker API",
        3306 => "MySQL",
        3389 => "RDP",
        5060 => "SIP",
        5432 => "PostgreSQL",
        5900 => "VNC",
        6379 => "Redis",
        8000 => "HTTP-Alt",
        8080 => "HTTP-Proxy",
        8443 => "HTTPS-Alt",
        9200 => "Elasticsearch",
        11211 => "Memcached",
        27017 => "MongoDB",
        _ => "TCP/UDP",
    }
}
