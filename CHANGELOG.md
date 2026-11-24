# Changelog

All notable changes to **AiBrainWorX AI CyberSecurity Threat Analysis Board** are documented here.

## v0.6.1 (2026-11-24)

### Comprehensive Security Hardening Release (48 Rust Security & Regression Tests)
- **SSRF & Outbound HTTP Hardening (`backend/src/security.rs`, `feeds.rs`, `ai_providers.rs`):**
  - Fixed trailing-dot FQDN DNS-rebinding TOCTOU mismatch (`https://host./...`) by canonicalizing domain hostnames directly inside `ValidatedUrl.url` before socket pinning so `reqwest` lookup keys always match `resolve_to_addrs`.
  - Expanded IPv4/IPv6 SSRF blocking to reject NAT64 (`64:ff9b::/96`, `64:ff9b:1::/48`), 6to4 (`2002::/16`), Teredo (`2001:0000::/32`), deprecated IPv4-compatible (`::x.x.x.x`), IPv4-translated (`::ffff:0:x.x.x.x`), site-local (`fec0::/10`), discard (`100::/64`), benchmark (`2001:2::/48`), ORCHID (`2001:10::/28`, `2001:20::/28`), IPv4 Class E (`240.0.0.0/4`), and `192.0.0.0/24`.
  - Replaced blind multi-redirect HTTP fetches on built-in threat feeds with per-hop SSRF-validated, DNS-pinned `send_ssrf_safe_get` / `send_ssrf_safe_post_json` helpers (`Policy::none()` + `.no_proxy()`) so compromised mirrors cannot redirect to loopback, RFC1918, or cloud metadata endpoints, and disabled implicit `HTTP_PROXY`/`HTTPS_PROXY` bypasses on all pinned clients.
- **Auth, Non-Loopback Exposure & Rate-Limiting Hardening (`backend/src/main.rs`, `routes.rs`):**
  - Closed unauthenticated first-boot `/api/auth/setup` takeover race on non-loopback / token-protected instances: when `AUTH_TOKEN` is configured (or auto-generated on non-loopback boot), `POST /api/auth/setup` now strictly requires matching `AUTH_TOKEN` via `Authorization: Bearer`, session cookie, or `setup_token`.
  - Stopped logging raw auto-generated bootstrap `AUTH_TOKEN` credentials to stdout; writes the full token with restrictive `0600`/owner-only permissions to `<data_dir>/.bootstrap_auth_token` and logs only a masked preview + file path.
  - Eliminated login brute-force rate-limiter bypass via spoofed `X-Forwarded-For` / `User-Agent` rotation by keying rate limits strictly from TCP peer `ConnectInfo<SocketAddr>` (ignoring proxy headers and `X-Forwarded-Proto` unless explicitly opted in via `--trust-proxy` / `TRUST_PROXY_HEADERS=1`).
  - Added `--allowed-hosts` / `ALLOWED_HOSTS` explicit Host allowlist for wildcard `--bind 0.0.0.0` / `::` DNS-rebinding protection, tightened exact `Origin` host+port matching, and extended `Cache-Control: no-store` to `/api/cti/*`, `/api/iocs/pcap`, `/api/my-stack`, and `/api/ai/*`.
- **At-Rest Secret Vault & Webhook Replay Protection (`backend/src/security.rs`, `storage.rs`, `webhooks.rs`, `routes.rs`):**
  - Added authenticated **AES-256-GCM (`LocalFieldVault`)** encryption with field-bound AAD for local SQLite 2FA TOTP seeds (`totp_secret_b32`) and Slack/Discord/Teams webhook bearer URLs, backed by `ABW_VAULT_KEY` or OS Native Keychain (`keyring` v3, with `0600` keyfile fallback in headless containers) and seamless backward-compatible upgrade of pre-v0.6.1 DBs. Added best-effort owner-only NTFS ACL hardening on Windows alongside POSIX `0600` on SQLite DB/WAL/SHM files.
  - Made OS Keychain persistence for webhook HMAC signing secrets strictly opt-in (`save_secret_to_keychain`, RAM-only by default — consistent with AI and CTI keys).
  - Upgraded outbound webhooks with timestamped replay protection (`X-AiBrainWorX-Timestamp`, `X-AiBrainWorX-Delivery-Id`, and `X-AiBrainWorX-Signature-256: t=<ts>,id=<uuid>,v1=<hmac_sha256(secret, "{ts}.{id}.{body}")>`), verification helper (`verify_webhook_delivery_hmac_sha256`), fail-closed signing, and zero-downtime secret/URL rotation via `PUT /api/webhooks/{id}`.
- **A2UI, Markdown Sanitizer, Prompt Framing & Parser Hardening (`a2ui.rs`, `A2uiRenderer.tsx`, `opsec.ts`, `analyzer.rs`, `pcap.rs`, `stack.rs`, `export.rs`):**
  - Upgraded both Rust and React Markdown sanitizers to strip all raw HTML tags (not just a narrow denylist), block reference-style images (`![alt][ref]`), sanitize reference link definitions (`[1]: javascript:...`), and reject angle-bracketed / HTML-entity-encoded / protocol-relative dangerous URIs.
  - Aligned Rust A2UI component render-tree depth validation (`MAX_COMPONENT_TREE_DEPTH = 6`) with React, allowlisted KPI `tone` CSS classes, blocked `__proto__`/`constructor`/`prototype` keys in RFC 6901 `resolvePointer`, and extended OPSEC display redaction across KPI/chart labels.
  - Made `<untrusted_telemetry_data>` breakout neutralization case-insensitive (`(?i)`) in `analyzer.rs`.
  - Bounded PCAPNG Interface Description Blocks (`MAX_PCAPNG_INTERFACES = 1_024`) and total blocks (`MAX_PCAPNG_BLOCKS = 300_000`) with overflow-safe `checked_add`, offloaded PCAP parsing to `tokio::task::spawn_blocking` outside `ThreatStore` locks, added `MAX_COMPONENTS` & recursion caps + `OnceLock` regex caching across SBOM/lockfile parsers, filtered private/loopback/metadata IPs out of EDL/`pf`/`nftables` firewall exports, and fixed STIX 2.1 `ipv4-addr`/`ipv6-addr` pattern typing.

## v0.6.0 (2026-11-23)

### Optional BYO CTI Enrichment Hub, Private OTX Pulse Sync & 24h SQLite Cache
- **Optional 4-Provider CTI Enrichment Engine (`backend/src/cti.rs`):** Added opt-in on-demand indicator enrichment across **AlienVault / LevelBlue OTX**, **GreyNoise Community** (works out of the box with no API key, plus optional key for higher limits), **AbuseIPDB v2**, and **VirusTotal v3** — zero sign-ups required unless you explicitly configure a key.
- **Hard Privacy Guard & DNS-Pinned HTTPS:** Automatically refuses to send RFC1918 private IPs, loopback, link-local, CGNAT, ULA, or `.local` / `.internal` / `.lan` / `.home` / `.corp` / `.arpa` / `.invalid` hostnames to any external CTI API (`400 Bad Request`). Every provider call uses DNS-pinned, zero-redirect `https://` (`build_pinned_http_client`) and `#[serde(skip)]` keys stored in session RAM by default (or optional OS Keychain via `keyring` v3).
- **Private Local OTX Subscribed Pulse Sync:** Syncs your subscribed AlienVault/LevelBlue OTX pulses into local SQLite (`otx_pulses`, capped at `15,000` indicators per pulse) with optional hourly auto-sync during feed sweeps — automatically correlating **Network IOC Verifier** lookups and **Wireshark `.pcap`/`.pcapng`** captures locally without extra API calls.
- **24-Hour SQLite Enrichment Cache (`cti_enrichment_cache`):** Caches external provider lookup results in local SQLite (auto-pruned at 500 entries, excluded from secret-stripped snapshots) so repeat IOC lookups return instantaneously with a **`SQLITE CACHED (24H)`** badge without burning daily API quotas — with **`Force Refresh`** and **`Clear Cache`** controls.
- **Feeds & Alerts Hub + Inline Network IOC Enrichment UI (`frontend/src/components/CtiEnrichmentHub.tsx`):** Added the 4-provider configuration/test hub inside **Feeds & Alerts** and one-click **`Enrich (OTX / GN / VT)`** buttons across the IOC Verifier, Wireshark PCAP Flagged Hits, Top External Talkers, and Feodo Botnet C2 tables with full **OPSEC Redact Mode** and **Demo Mode** parity.

## v0.5.0 (2026-11-22)

### Wireshark Offline `.pcap` / `.pcapng` Threat Triage & Display Filters
- **Zero-Dependency Pure-Rust PCAP/PCAPNG Parser (`backend/src/pcap.rs`):** Parses classic `.pcap` (LE/BE, µs/ns) and modern Wireshark `.pcapng` (SHB, IDB, EPB, SPB) strictly in memory with zero `unsafe`, zero `tshark`, zero Npcap/root, `25 MB` max upload cap, `250,000` packet cap, and 16-hop DNS compression-pointer loop protection.
- **L2–L7 Protocol Extraction & Live CTI Correlation:** Decodes Ethernet (+ 802.1Q VLAN), Linux SLL/SLL2, Raw IP, Loopback → IPv4/IPv6 → TCP/UDP → DNS `QNAME`, TLS ClientHello SNI, and cleartext HTTP `Host`/`User-Agent`, cross-checking every extracted indicator against live Feodo Botnet C2s, SANS ISC Top Attackers, Emerging Threats Compromised IPs, and OpenPhish domains.
- **Behavioral Heuristics & A2UI 1.0 PCAP Incident Surface:** Detects SYN port scans, high-entropy DNS tunneling suspects, and cleartext FTP/Telnet/HTTP protocols; renders results as an interactive A2UI 1.0 surface (KPI strip, Top Destination Ports Recharts bar chart, containment checklist) plus Flagged Hits, Observed Hosts, and Top External Talkers tables inside **Network IOCs**.
- **One-Click Wireshark Display Filters & AI Analyst Handoff:** Added `GET /api/iocs/wireshark-filter`, `GET /api/iocs/export?format=wireshark`, `POST /api/iocs/pcap`, `POST /api/iocs/pcap/sample` (1-click real binary `.pcap` test + Demo Mode support), per-row `Copy WS Filter` buttons across Feodo C2s and PCAP hits, full OPSEC IP & domain masking (`redactWiresharkFilter`), and one-click **`Analyze PCAP with AI Analyst`** handoff.

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
