# Runbook

## Chain verification fails (`/console` banner or `agentshield verify-ledger`)
1. Freeze writes to the ledger store; copy the JSONL and DB table for forensics.
2. `agentshield verify-ledger audit.jsonl --anchors anchors.jsonl --ed25519-pub ed.pub.pem --mldsa-pub pq.pub.pem`.
3. "leaf hash mismatch at N" → entry N was edited. "history rewritten" → a prefix was replaced after anchoring. "truncated" → entries removed.
4. Compare with the Postgres sink (append-only role) and Redis stream to find the divergent copy. Rotate signing keys after the incident.

## Spike in blocks / findings
Check `shield_findings_total` by category and the `/console` list. A single `actor` or `source` dominating is a poisoned source
or a compromised agent: revoke its scopes, quarantine the collection, review the sampled entries.

## Approvals piling up (`shield_hitl_pending`)
Timeouts resolve to DENY, so a backlog degrades availability, not safety. Check the webhook (Slack/Teams) delivery and the
approver roster; four-eyes needs two distinct approvers.

## Red-team detection drops (`shield_redteam_detection_rate` < 0.95)
A signature or normalizer change regressed. Run `agentshield redteam`; the failing mutators are listed. Do not lower the threshold.

## Rotating keys
`agentshield keygen --out new-keys` → deploy to `SHIELD_LEDGER_KEY_DIR` → restart. Keep the old public keys so historical
checkpoints and anchors stay verifiable. Rotate `SHIELD_TOKEN_KEY` (invalidates all tokens) and `SHIELD_APPROVAL_KEY` (invalidates pending approvals).

## MCP rug-pull alert (`mcp_rug_pull` ledger entry)
A server changed a tool definition after pinning. Review the diff; if legitimate, re-approve with `PinStore.approve` and save the pins file.
