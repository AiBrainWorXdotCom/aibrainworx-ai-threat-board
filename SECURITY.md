# Security Architecture & Vulnerability Disclosure Policy

## Threat Model & Local-First Posture

**AiBrainWorX AI CyberSecurity Threat Analysis Board (v0.2.0)** runs locally on your workstation or inside a locked-down private container. Security controls prioritize local operational privacy, SSRF containment, credential isolation, and untrusted telemetry sanitization:

1. **Loopback Default + Non-Loopback Access Control:**
   - By default, the server binds strictly to `127.0.0.1:8080` with `Host` header validation (`403 Forbidden` on non-loopback `Host` headers to defeat DNS rebinding) and strict `Origin` / `Sec-Fetch-Site` enforcement.
   - Binding to any non-loopback address (`--bind 0.0.0.0` or LAN IP) or setting `AUTH_TOKEN` enforces constant-time Bearer token / `HttpOnly; SameSite=Strict` session-cookie authentication (`abw_session`) across `/api/*` endpoints (with only `/api/health` and `/api/auth/*` exempt).
   - If started non-loopback without `AUTH_TOKEN`, a cryptographically random 24-byte hex token is generated at startup via `getrandom`.

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

6. **OPSEC Redact Mode, Defanging, CSV Formula Neutralization & Air-Gapped Modes:**
   - **OPSEC Redact Mode** masks public attacker IPs, C2 endpoints, and phishing domains in the UI for safe screen-sharing and demos.
   - Phishing URLs render defanged (`hxxps://`, `[.]`) as non-clickable text.
   - Spreadsheet CSV exports escape leading `=`, `+`, `-`, `@`, `\t`, and `\r` characters to neutralize formula injection.
   - `--wallboard` enforces `403 Forbidden` on all configuration/mutation endpoints; `--offline` disables all outbound threat feed sweeps.

## Reporting a Vulnerability

Do **not** open public issues with exploitable local PoCs, real credentials, or sensitive threat telemetry. Report security issues responsibly via [GitHub Security Advisories](https://github.com/AiBrainWorXdotCom/aibrainworx-ai-threat-board/security/advisories/new).
