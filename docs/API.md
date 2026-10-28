# HTTP API

All routes except `/healthz`, `/metrics`, `/console` and `/v1/identity/*` require `Authorization: Bearer <capability token>`.
Roles: `auditor` (audit, stats, AI-BOM), `security` (red-team). Bodies must be `application/json`.

| Method + path | Role | Purpose |
|---|---|---|
| `POST /v1/identity/challenge` | public | get a single-use nonce |
| `POST /v1/identity/token` | public | exchange a Schnorr proof for a capability token |
| `POST /v1/scan/text` | any | scan/heal text → `{verdict, score, healed, findings, text}` |
| `POST /v1/scan/rag` | any | scan retrieved chunks → per-chunk action (`pass`/`sanitized`/`quarantined`) |
| `POST /v1/scan/image` | any | multi-modal image scan → verdict + purified PNG (base64) |
| `POST /v1/tools/authorize` | any | policy decision for a tool call (may wait for human approval) |
| `POST /v1/tools/execute-python` | any | authorize then run code in the ephemeral sandbox |
| `GET /v1/hitl/{id}` / `POST /v1/hitl/{id}/decision` | approver | review and decide a pending approval (signed) |
| `GET /v1/audit/checkpoint` | auditor | signed Merkle checkpoint (+ public key) |
| `GET /v1/audit/proof/{seq}` | auditor | RFC-6962 inclusion proof |
| `GET /v1/aibom` | auditor | CycloneDX AI-BOM + compliance evidence map |
| `POST /v1/redteam/run` | security | run the mutation suite now |
| `GET /v1/stats`, `GET /v1/ledger/recent` | auditor | data for the console |
| `GET /console` | public (no data) | web security console |
| `GET /healthz`, `GET /metrics` | public | liveness, Prometheus metrics |

Verdicts: `allow`, `sanitized` (healed - forward the returned text only), `block`, `pending_approval` (awaiting a human; the response carries an `approval_id`).
Errors: 401 unauthenticated, 403 role, 413 too large, 415 not JSON, 429 rate-limited. Every decision is audited.
