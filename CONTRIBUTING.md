# Contributing

1. Fork, create a branch, `make install`, make your change.
2. `make test policy redteam` must pass. Add tests for your change: one for the intended behaviour and, for any security
   control, one that proves a bypass attempt is blocked.
3. Design rules that review enforces:
   - **Fail closed.** Errors, timeouts, missing models and unreachable services deny; they never allow.
   - **No new trust.** Data from tools, documents, retrieved chunks and MCP servers is untrusted input.
   - **No secrets in logs, audit entries or error messages.** The ledger stores digests, not payloads.
   - **Strict parsing** of anything that configures security (unknown keys are errors).
4. Open a pull request using the template. Security-sensitive files are covered by `CODEOWNERS`.

Report vulnerabilities privately - see `SECURITY.md`.
