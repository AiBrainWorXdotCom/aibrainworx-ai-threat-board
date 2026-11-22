# Contributing to AiBrainWorX AI CyberSecurity Threat Analysis Board

Thank you for helping make open-source threat intelligence faster, safer, and local-first!

## Development Setup

1. Install **Rust** (`rustup`, stable toolchain with `rustfmt` and `clippy`) and **Node.js 20+** / `npm`.
2. On Linux desktops/CI, install D-Bus development headers so the `keyring` crate compiles:
   ```bash
   sudo apt-get install -y libdbus-1-dev pkg-config
   ```
3. Build the production frontend bundle (or run `npm run dev` on port `5173` with `DEV_MODE=1`):
   ```bash
   cd frontend && npm ci && npm run build
   ```
4. Verify backend formatting, linting, and tests:
   ```bash
   cd backend
   cargo fmt --check
   cargo clippy --all-targets -- -D warnings
   cargo test
   ```

## Security & Privacy Rules for Pull Requests

- Never commit real credentials, internal company IOCs, API keys, SQLite databases (`data/`), or screen recordings (`video/`).
- Outbound network fetchers MUST validate URLs via `crate::security::validate_outbound_url` + `build_pinned_http_client` (zero redirects) and enforce explicit byte limits.
- External telemetry or LLM outputs MUST be stripped via `strip_invisible_unicode` and `sanitize_llm_markdown`.
- Exported spreadsheets MUST escape formula-injection characters (`=`, `+`, `-`, `@`, `\t`, `\r`) via `csv_safe_cell`.
- Frontend UI work should preserve the Meta Astryx UI obsidian sharp (`0px`) design language and pass `npx tsc --noEmit` cleanly.
