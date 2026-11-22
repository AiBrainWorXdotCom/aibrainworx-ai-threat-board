# Changelog

All notable changes to **AiBrainWorX AI CyberSecurity Threat Analysis Board** are documented here.

## v0.2.0 (2026-11-22)

### Security-First Architecture Upgrades
- **Embedded SQLite Storage (WAL + FTS5):** Replaced flat JSON persistence with ACID-safe SQLite (`rusqlite` bundled), `0600` Unix permissions, FTS5 full-text CVE search, and automatic one-time migration from `data/threat_store.json`.
- **DNS-Pinned SSRF Defense:** Resolved hostname IPs prior to connect, blocked IPv4-mapped IPv6 (`::ffff:127.0.0.1`), RFC1918, ULA, CGNAT, and cloud metadata IPs (`169.254.169.254`, `100.100.100.200`), disabled redirects, and pinned `reqwest` sockets for AI providers, custom feeds, and webhooks.
- **OS Keychain Secret Vault (`keyring` v3):** Optional native persistence via Windows Credential Manager, macOS Keychain, and Linux Secret Service for AI API keys and webhook HMAC secrets (RAM-only remains default).
- **OPSEC Redact Mode & Defanged Sharing:** One-click top-bar toggle masks attacker IPs, C2 endpoints, and hostnames on screen (`198.51.xxx.xxx`), enforces `hxxp(s)://` / `[.]` defanging for phishing URLs, and neutralizes Excel formula injection on CSV exports.
- **Unicode & Markdown Defense-in-Depth:** Strips invisible Unicode Tags (`U+E0000..=U+E007F`) and bidi overrides from prompts and feeds; blocks `<script>` tags, remote tracking images, and `javascript:`/`data:` URIs on both backend and frontend.
- **Read-Only Wallboard, Offline Air-Gapped & Auth Token Modes:** Added `--wallboard` (`403` on mutations), `--offline` (zero outbound feed traffic), and automatic non-loopback `AUTH_TOKEN` enforcement (`Bearer` / `HttpOnly; SameSite=Strict` cookie).

### Product & SOC Workflow Features
- **Single-File Binary Deployment (`rust-embed`):** Production frontend compiles cleanly inside the Rust binary (`./aibrainworx-threat-board`) plus multi-stage non-root `Dockerfile`.
- **My Stack (100% Local SBOM & Lockfile Correlation):** Parses CycloneDX JSON, SPDX JSON, `package-lock.json`, `package.json`, `Cargo.lock`, `Cargo.toml`, `requirements.txt`, `pyproject.toml`, `go.mod`, and `pom.xml` plus vendor/product watchlists locally and surfaces matches across KPIs, AI briefs, explorer, and alerts.
- **EPSS 24h/7d Velocity Deltas, KEV SLA Countdowns & Sweep Diffs:** Tracks EPSS score spikes (`+15%` 24h), CISA KEV overdue/due-soon countdown pills, and unreviewed *What Changed* sweep summaries.
- **Per-CVE SOC Triage Workflow:** Track `New`, `Investigating`, `Mitigated`, `False Positive`, and `Accepted` states with analyst notes persisted in SQLite.
- **Enterprise Exports & Bulk IOC Triage:** Per-CVE Markdown/JSON/STIX 2.1 dossiers, bulk CSV/STIX 2.1 vulnerability exports, EDL/`nftables`/`pf`/CSV firewall blocklists, SHA-256 verified secret-stripped offline snapshots, and batch IOC triage up to 200 indicators.
- **Outbound Webhooks & BYO Custom Feeds:** SSRF-safe Slack, Discord, Microsoft Teams, and generic HMAC-SHA256 webhooks alongside toggleable built-in feeds and BYO RSS/Atom, IOC text, STIX 2.1, and MISP JSON feeds.
- **Static Synthetic Demo Mode:** `VITE_DEMO_MODE=1` GitHub Pages build using strictly RFC 5737 documentation IPs and `.invalid` domains.

## v0.1.0 (Initial Open-Source Release)
- Live concurrent 25-source public CTI & threat feed sweep in Rust (`axum 0.8` + `tokio`).
- Meta Astryx UI sharp dark obsidian SOC dashboard, SSE alerts, Investigation Drawer, and 13-provider local/cloud BYO AI analyst.
