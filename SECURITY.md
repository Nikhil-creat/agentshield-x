# Security policy

AgentShield-X is a security product: a bypass, an unsafe default or a way to forge or silently alter the audit trail is a
vulnerability, not a normal bug.

## Reporting

Use **GitHub private vulnerability reporting**: *Security → Report a vulnerability* on this repository.
Please do not open a public issue or pull request for a suspected vulnerability or a detection bypass.

Include: affected version/commit, a minimal reproduction (the input text/image/call), what you expected, and impact.
You will get an acknowledgement within 5 working days. Fixes are developed in a private advisory and released with
a CVE/GHSA where appropriate; reporters are credited unless they prefer otherwise.

## What counts

In scope: authentication/authorization bypass, policy-engine or schema bypass, sandbox escape or hardening regression,
secret leakage through responses/logs/audit, ledger/checkpoint forgery or downgrade, HITL approval forgery, SSRF/egress
bypass, MCP-guard bypass, denial of service of the guard itself.

Known limits (documented, not vulnerabilities by themselves): detection of novel paraphrased prompt injection by the
rule/cue layer is incomplete - see `docs/THREAT_MODEL.md`. A *deterministic, reproducible* bypass of a documented control
is still in scope.

## Supported versions

Only the latest minor release receives security fixes while the project is pre-1.x-stable.

## Operator hygiene (summary)

Never commit `.env`, `secrets/` or `keys/`; rotate any key that was ever committed; keep ledger signing keys outside the
API container's writable storage; ship anchored checkpoints to storage the API cannot rewrite.
