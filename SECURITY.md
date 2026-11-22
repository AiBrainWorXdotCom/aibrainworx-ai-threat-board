# Security Architecture & Vulnerability Disclosure Policy

## Threat Model & Local-First Posture

**AiBrainWorX AI CyberSecurity Threat Analysis Board (v0.5.0)** runs locally on your workstation or inside a locked-down private container. Security controls prioritize local operational privacy, strong local authentication, declarative zero-HTML agentic UI, memory-safe offline packet triage, SSRF containment, credential isolation, and untrusted telemetry sanitization:

1. **Local Argon2id Authentication, Ephemeral Sessions & Offline TOTP 2FA:**
   - Authentication is enabled by default even on `127.0.0.1:8080`. On first run, the browser opens the **First-Run Admin Setup** wizard (`POST /api/auth/setup`, permanently locked with `403` once an account exists).
   - Passwords are stored exclusively as **Argon2id** hashes (`m=19456, t=2, p=1`, 128-bit CSPRNG salt) in local SQLite (`auth_users`, never exported in snapshots), with dummy Argon2id verification on missing usernames to prevent timing enumeration.
   - Sign-in issues a 256-bit CSPRNG session token in an `HttpOnly; SameSite=Strict` cookie (`abw_session`, plus `Secure` when behind HTTPS); only `SHA-256(token)` is stored in `auth_sessions`, enabling instant server-side revocation on logout, password change, or "Sign Out Other Sessions".
   - Progressive brute-force lockout (`60s → 5m → 15m`, `429 Retry-After`) activates after 5 failed attempts. Optional **RFC 6238 TOTP 2FA** renders QR codes 100% locally as inline base64 SVGs with replay-step tracking and 8 single-use hashed recovery codes.
   - Local loopback kiosk bypass (`--no-auth`) is strictly rejected on non-loopback binds (`0.0.0.0` / LAN). `Host` header validation (`403` on DNS rebinding), `Origin`/`Sec-Fetch-Site` checks, and `AUTH_TOKEN` Bearer automation support remain enforced across `/api/*`. Use `--reset-auth` locally if emergency credential reset is required.

2. **DNS-Pinned SSRF Defense & Zero-Redirect Outbound Clients:**
   - All user-supplied outbound URLs (BYO AI providers, BYO custom threat feeds, and outbound webhooks) pass `security::validate_outbound_url` before any socket opens.
   - Hostnames are resolved via DNS and every returned IP (including unmapped `::ffff:x.x.x.x` IPv4-mapped IPv6 addresses) is validated before pinning the resolved addresses directly into a zero-redirect `reqwest` client (`Policy::none()` + `resolve_to_addrs`) to block DNS-rebinding TOCTOU and 302 redirect pivots.
   - Custom feeds and webhooks enforce strict `https://` public IPs only (blocking loopback, RFC1918, ULA, CGNAT, link-local, and cloud metadata IPs like `169.254.169.254` / `100.100.100.200`).
   - Private LAN AI servers (e.g., `192.168.x.x` Ollama/LM Studio) are blocked unless explicitly opted into via `allow_lan_endpoints`, and link-local/metadata ranges remain unconditionally blocked.

3. **Secret Isolation & Optional OS Keychain Vault:**
   - AI provider API keys and webhook HMAC signing secrets are marked `#[serde(skip)]` and are **never** written to SQLite, `data/`, API responses, logs, or offline snapshots.
   - Slack/Discord/Teams webhook bearer URLs are masked (`url_masked`) on all API read responses.
   - Users may optionally opt into OS native Keychain storage (`keyring` v3: Windows Credential Manager, macOS Keychain, Linux Secret Service). Session RAM remains the default.

4. **Embedded SQLite Storage (`WAL` + `FTS5`) & Offline Snapshots:**
   - Local intelligence persists in `data/threat_board.db` with `WAL` journaling and restrictive `0600` POSIX permissions.
   - Portable Offline Snapshots exclude secrets (`ai_config` keys, webhooks) and verify a deterministic `SHA-256` digest prior to ingestion.

5. **Untrusted Feed, Prompt Injection & Markdown Sanitization:**
   - External telemetry passed to LLMs is delimited inside `<untrusted_telemetry_data>` boundaries with explicit system prompt instructions and invisible Unicode stripping (`U+E0000..=U+E007F` Tags, bidi overrides, zero-width & C0/C1 controls).
   - Both Rust backend and React frontend sanitize returned Markdown before display: blocking `<script>`, `<iframe>`, `<svg>`, remote Markdown images (`![alt](url)` tracking pixels), and non-`http(s)` URI schemes (`javascript:`, `data:`, `file:`).
   - Strict `Content-Security-Policy` headers (`script-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'`) and `Cache-Control: no-store` protect sensitive endpoints and `index.html`.

6. **A2UI 1.0 Declarative UI Security Boundary (`aibrainworx.soc.v1`):**
   - **Zero Raw HTML / Zero Code Execution:** AI Threat Analyst and Deep AI Triage emit declarative A2UI 1.0 JSON envelopes (`createSurface`, `updateDataModel`, `updateComponents`, `@path` bindings) rather than executable markup. Both `backend/src/a2ui.rs` and `frontend/src/components/A2uiRenderer.tsx` enforce a static component allowlist — unknown or unapproved component types are dropped silently.
   - **Strict Non-Destructive Action Allowlist:** Client-side actions dispatched from A2UI surfaces are restricted to `open_cve`, `set_triage` (disabled in `--wallboard` read-only mode), `export_stix`, `export_md`, `navigate_tab`, and `copy_text`. AI-emitted UI actions can never access authentication/2FA, API keys, webhooks, alert rules, or arbitrary outbound URLs.
   - **Anti-DoS & Sanitization:** `validate_and_sanitize_a2ui` enforces protocol version (`1.0`), trusted catalog ID (`aibrainworx.soc.v1`), maximum component count (`40`), recursion depth (`8`), acyclic component graph verification, invisible-Unicode stripping, and `javascript:`/`data:`/`vbscript:` URI blocking. External LLMs may only supply validated `a2ui-patch` text/playbook hints while all CVE and network metrics stay Rust-verified in `dataModel`.
   - **OPSEC Parity:** `A2uiRenderer` honors **OPSEC Redact Mode** across KPI subtitles, banners, advisories, botnet C2 IPs/hostnames, copy actions, and raw `A2UI JSON` previews.

7. **Memory-Safe Offline Wireshark `.pcap`/`.pcapng` Triage (`backend/src/pcap.rs`):**
   - **Zero `unsafe`, Zero `tshark`, Zero Root:** Captures are decoded entirely in pure memory-safe Rust with checked slice indexing — no live promiscuous sniffing, no `Npcap` driver install, and no shelling out to C-based `tshark` dissectors on untrusted captures.
   - **RAM-Only & Strict Anti-DoS Bounds:** Raw capture bytes are parsed strictly in memory and never persisted to SQLite or disk. Endpoints enforce a scoped `25 MB` Axum body limit (`POST /api/iocs/pcap`), `250,000` max packets per capture, `5,000` unique endpoint/domain caps, 16-hop DNS compression-pointer loop guards, and `403 Forbidden` in `--wallboard` read-only mode.
   - **OPSEC Masking Parity:** When **OPSEC Redact Mode** is active, extracted PCAP IPs, observed hostnames/SNIs, DNS anomaly strings, and rendered/copied Wireshark display filters are automatically masked (`198.51.xxx.xxx`, `"••••.invalid"`).

8. **OPSEC Redact Mode, Defanging, CSV Formula Neutralization & Air-Gapped Modes:**
   - **OPSEC Redact Mode** masks public attacker IPs, C2 endpoints, and phishing domains in the UI for safe screen-sharing and demos.
   - Phishing URLs render defanged (`hxxps://`, `[.]`) as non-clickable text.
   - Spreadsheet CSV exports escape leading `=`, `+`, `-`, `@`, `\t`, and `\r` characters to neutralize formula injection.
   - `--wallboard` enforces `403 Forbidden` on all configuration/mutation endpoints; `--offline` disables all outbound threat feed sweeps.

## Reporting a Vulnerability

Do **not** open public issues with exploitable local PoCs, real credentials, or sensitive threat telemetry. Report security issues responsibly via [GitHub Security Advisories](https://github.com/AiBrainWorXdotCom/aibrainworx-ai-threat-board/security/advisories/new).
