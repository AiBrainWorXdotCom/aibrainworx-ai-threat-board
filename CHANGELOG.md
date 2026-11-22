# Changelog

All notable changes to **AiBrainWorX AI CyberSecurity Threat Analysis Board** are documented here.

## v0.4.0 (2026-11-22)

### A2UI 1.0 Interactive SOC Surfaces
- **Declarative A2UI 1.0 Protocol Engine & Validator (`backend/src/a2ui.rs`):** Emits validated A2UI 1.0 `agent_to_renderer` message envelopes (`createSurface`, `updateDataModel`, `updateComponents`, catalog `aibrainworx.soc.v1`) with RFC 6901 `@path` JSON Pointer data bindings, strict component/action allowlists, cycle/depth/node limits, and invisible-Unicode / dangerous-URI stripping.
- **Intent-Adaptive SOC Surfaces:** Automatically tailors layouts across CISA KEV & Ransomware, AI/ML Supply-Chain, Network Perimeter & IOCs, Breaking Advisories & PoCs, My Stack Exposure, CVE Deep-Dive, and Threat Overview queries using word-boundary intent classification.
- **Zero-Bloat React A2UI 1.0 Renderer (`frontend/src/components/A2uiRenderer.tsx`):** Maps allowlisted catalog primitives directly to native Meta Astryx UI + Recharts widgets — KPI strips, urgency banners, interactive CVE triage tables (`Inspect`, live SQLite `Investigate`/`Mitigate`, `STIX 2.1`), risk & port bar charts, checkable Containment Playbooks (`X/Y DONE`), correlated advisory cards, and OPSEC-aware Botnet C2 panels with defanged copy.
- **AI Threat Analyst & Deep AI Triage Upgrades:** Added 3-way **Interactive A2UI | Markdown | A2UI JSON** mode switching (preserving local checklist/triage state across switches), a **My Stack Exposure** analyst preset prompt, compact A2UI 1.0 Deep Triage surfaces inside `InvestigationDrawer`, optional external-LLM `a2ui-patch` integration with Rust-verified telemetry binding, and full A2UI 1.0 support in `VITE_DEMO_MODE=1` static Demo Mode.

## v0.3.0 (2026-11-22)

### Local Authentication, Hardened Sessions & Offline TOTP 2FA
- **First-Run Local Admin Setup & SOC Login Screen:** Added a dedicated dark-SOC First-Run Admin Setup wizard (live 4-segment password strength meter, ≥10-character minimum) and Sign-In screen enabled by default on both loopback and LAN binds.
- **Argon2id Password Hashing:** Passwords are hashed locally with OWASP-recommended Argon2id parameters (`m=19456, t=2, p=1`, 128-bit CSPRNG salt) and verified in constant time (with dummy Argon2id verification for unknown usernames to resist timing enumeration).
- **256-Bit Ephemeral HttpOnly Sessions (`auth_sessions`):** Issues CSPRNG 256-bit `HttpOnly; SameSite=Strict` cookies (auto-`Secure` behind HTTPS), persists only `SHA-256` token hashes in SQLite (excluded from offline snapshots), supports active session listing, one-click revocation of other sessions, and immediate server-side revocation on logout or password rotation.
- **Brute-Force Rate Limiting & Lockout:** Enforces progressive per-client/username lockout (`60s → 5m → 15m`) returning `429 Too Many Requests` + `Retry-After` after 5 failed attempts.
- **Offline RFC 6238 TOTP 2FA & Recovery Codes:** Built-in authenticator app enrollment with **100% locally generated base64 SVG QR codes** (zero external network calls), ±30s drift tolerance with replay-step protection, and 8 single-use hashed recovery codes.
- **Account Security Modal & Recovery Flags:** Manage 2FA, password rotation, and active sessions from the `@username` top-bar control; use `--reset-auth` for local CLI credential recovery or `--no-auth` for explicit loopback-only (`127.0.0.1`) kiosk bypass (ignored on non-loopback binds).

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
