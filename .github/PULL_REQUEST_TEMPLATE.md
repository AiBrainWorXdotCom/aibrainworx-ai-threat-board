## Summary
Describe the changes in this pull request.

## Verification Checklist
- [ ] `cd backend && cargo fmt --check` passes
- [ ] `cd backend && cargo clippy --all-targets -- -D warnings` passes
- [ ] `cd backend && cargo test` passes
- [ ] `cd frontend && npx tsc --noEmit && npm run build` passes
- [ ] Verified zero API keys, internal IPs, or SQLite/recording files included in git diff
