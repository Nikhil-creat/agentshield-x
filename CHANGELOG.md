# Changelog

## 2.1.0
- **Project site** (`web/`, `scripts/build_site.py`): blueprint-style landing page + rendered docs, built with real engine results
  captured at build time, strict CSP, no third-party requests; deployed by the `Pages` workflow.
- **HTTP hardening** (`web.py`): security headers on every response, validated `X-Request-ID`, structured JSON access logs,
  `/readyz` and `/version`.
- Tooling: dev container, `uv` install target, `docs` extra, `make site`.
- Docs: GitHub Pages guide.

## 2.0.0
- Hybrid **Ed25519 + ML-DSA-65 (FIPS 204)** signed ledger checkpoints; the algorithm label is inside the signed message so a
  checkpoint cannot be relabelled to strip the post-quantum signature.
- **Checkpoint anchoring** (`anchor.py`): hash-chained signed anchors detect whole-history rewrites and truncation.
- **Policy-as-code**: strict YAML loader (`policies/tools.yaml`, `abac.yaml`), Rego policy + tests, `agentshield policy-validate`.
- **MCP guard**: stdio proxy with tool-poisoning detection, rug-pull pinning, result healing, denial of server-initiated
  `sampling`/`elicitation`, per-call authorization.
- **Framework adapters** (`Shield.tool`, `guard_llm`, `guard_retriever`) for LangGraph / CrewAI / AutoGen / plain function calling.
- `agentshield` **CLI** and a **web security console** (`/console`, strict CSP, no third-party assets).
- Environment-driven `bootstrap` (policy dir, persistent keys, anchoring).
- Repo hardening: CI, CodeQL, Trivy, gitleaks, SBOM, cosign + provenance on release, Dependabot.

## 1.0.0
- Initial release: multi-modal scanning, RAG sanitizer, threat hunters, RBAC/ABAC + HITL, sandbox (Docker/Kubernetes),
  Merkle audit ledger, ZK identity, AI-BOM, red-team harness, Helm/Cilium/Tetragon manifests.
