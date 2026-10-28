# Coverage map: OWASP LLM Top 10 (2025) and MITRE ATLAS

"Covered" means a control exists and is tested; "Partial" means the control reduces risk but has known gaps.

| OWASP LLM risk | Status | Where | Limit |
|---|---|---|---|
| LLM01 Prompt injection | Partial | `signatures`, `text_normalizer`, `threat_hunter`, `self_heal`, `mcp_guard` | paraphrase generalization is weak without the learned classifier |
| LLM02 Sensitive information disclosure | Covered | secret/PII scan, response DLP in middleware, adapters redact LLM output | pattern-based; novel secret formats missed |
| LLM03 Supply chain | Partial | AI-BOM (CycloneDX 1.6), SBOM, cosign + provenance in release workflow, Trivy/pip-audit | model provenance depends on operator-supplied hashes |
| LLM04 Data and model poisoning | Partial | RAG drift/entropy, source allow-list, quarantine | no training-time defenses |
| LLM05 Improper output handling | Covered | response scan/redaction, schema-validated tool args | downstream sinks must still encode output |
| LLM06 Excessive agency | Covered | registry, scopes, ABAC, HITL, sandbox, dry-run forcing, clamps | quality depends on the policies you write |
| LLM07 System prompt leakage | Partial | leak signatures, healing, intent-divergence | cannot prevent leakage the model chooses to make |
| LLM08 Vector and embedding weaknesses | Partial | spotlighting, centroid drift, per-collection allow-list | no embedding-inversion defenses |
| LLM09 Misinformation | Not addressed | - | out of scope |
| LLM10 Unbounded consumption | Covered | size/rate limits, scan budgets, sandbox cgroups/ulimits/timeouts | tenant-level quotas are operator-defined |

| ATLAS technique (examples) | Control |
|---|---|
| AML.T0051 LLM prompt injection (direct/indirect) | text/RAG/MCP scanning, healing |
| AML.T0054 LLM jailbreak | multi-turn jailbreak hunter |
| AML.T0057 LLM data leakage | DLP, egress control |
| AML.T0053 LLM plugin compromise | MCP guard, registry, pinning |
| AML.T0010 ML supply chain compromise | AI-BOM, signed release artifacts |

Technique IDs are listed for orientation; verify them against the current ATLAS matrix before citing in an audit.
