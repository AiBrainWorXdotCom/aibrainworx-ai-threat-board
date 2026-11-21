# Security Policy — AiBrainWorX CyberSecurity Threat Analysis Board

## Deployment & Threat Model

AiBrainWorX CyberSecurity Threat Analysis Board is designed as a **single-user local SOC workstation application** bound strictly to loopback (`127.0.0.1:8080` by default).

- **No Built-In Multi-User Authentication:** Do **not** expose this service directly to a public network, untrusted LAN, or shared multi-tenant host without placing it behind a TLS reverse proxy enforcing authentication and origin checks.
- **DNS Rebinding & CSRF Protections:** The server rejects requests whose `Host` header is not loopback (`127.0.0.1`, `localhost`, `[::1]`) and enforces an explicit loopback CORS allowlist alongside `Origin` / `Sec-Fetch-Site` validation on `/api/*`.

## API Key Handling Best Practices

- **Environment Variables Preferred:** For cloud AI providers (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `OPENROUTER_API_KEY`, `GROQ_API_KEY`, `DEEPSEEK_API_KEY`, `MISTRAL_API_KEY`, `XAI_API_KEY`, `CUSTOM_AI_API_KEY`), pass credentials via process environment variables.
- **Session-Only Memory Storage:** API keys entered in the **AI Models** UI are held in server RAM for the current process lifetime and are **never** written to `data/threat_store.json` or echoed in plaintext by `GET /api/ai/config`.
- **Endpoint Isolation:** Environment keys for built-in cloud presets are only attached when targeting each provider's official default endpoint URL, never on overridden `base_url` values, and HTTP redirects are disabled on outbound AI client calls.
- **Local Zero-Key Mode:** Running with `Built-in Rust Engine` or local runtimes (`Ollama`, `LM Studio`, `llama.cpp` / `vLLM`) keeps threat telemetry completely on your machine with zero cloud API keys required.

## Hardening Controls Included

- Strict HTTP security headers (`Content-Security-Policy` with `frame-ancestors 'none'`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy`).
- Header-based authentication (`x-goog-api-key`) for Gemini instead of query-string secrets, plus `.without_url()` error redaction across HTTP clients.
- `http://` / `https://` scheme validation and credential stripping on all ingested feed URLs and frontend external links.
- Bounded response body reads (2 MB cap for AI endpoints, 12 MB cap for public feeds) and 256 KB API JSON request body limits.
- Untrusted-telemetry boundary framing on prompts sent to external or local LLMs.

## Reporting a Vulnerability

If you discover a security issue in AiBrainWorX, please report it privately to the maintainers before opening a public issue so it can be verified and patched first.
