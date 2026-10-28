# AgentShield-X: Architecture Blueprint

Zero-trust security and governance fabric for LLM / RAG / multi-agent systems. **Deny by default; every
scanner failure, timeout, missing model or unreachable human resolves to BLOCK/DENY.**

## 1. Data flow

```
                        ┌──────────────────────────────────────────────────────────────┐
   user / agent ──HTTP──►  TIER 0  AgentShieldMiddleware (ASGI)                         │
   (Bearer cap-token)   │  auth(401) · rate-limit(429) · size(413) · JSON-only(415)    │
                        │  walk every JSON string ─► check_input   ◄── rewrite body    │
                        │  response DLP: redact secrets in JSON responses              │
                        └───────────────┬──────────────────────────────────────────────┘
                                        ▼
   ┌─────────────────────────── TIER 1: PERCEPTUAL SANITIZATION ───────────────────────────┐
   │ text_normalizer  zero-width/bidi/tag-char strip · NFKC · homoglyph repair · flood cap   │
   │                  └─► hidden payloads decoded (Unicode tags, zero-width binary)          │
   │ signatures       injection/jailbreak/leak/exfil/tool-forgery · rot13/reversed/base64/   │
   │                  spaced/leet decoding · secrets & Luhn-valid cards                      │
   │ text_classifier  optional learned (ONNX) classifier  ◄── paraphrase coverage           │
   │ RagSanitizer     indirect injection · entropy/compression · drift z-score · spotlight   │
   │ VisionScanner    limits · OCR (visible+amplified) · LSB stego · QR · trailing bytes ·   │
   │                  metadata · noise heuristic · ONNX CNN guard · purify (median+posterize)│
   └───────────────┬────────────────────────────────────────────────────────────────────────┘
                   ▼  score = noisy-OR(findings)      ≥heal: self-heal & re-scan   ≥block: BLOCK
   ┌─────────────────────────── TIER 2: AGENTIC THREAT HUNTING + POLICY ───────────────────┐
   │ concurrent hunters (per-hunter timeout, failure = finding):                             │
   │   IntentDivergence · Jailbreak (multi-turn, split-payload) · PrivilegedTool (SSRF,      │
   │   traversal, secrets, AST) · ClassifierHunter                                           │
   │ PolicyEngine: registry → JSON-schema → RBAC scope/role → ABAC (deny-overrides)          │
   │               → egress allow-list → OPA (fail-closed)                                   │
   │ RiskEngine 0..1 (priors + evidence)  ──►  Self-heal args (drop/clamp/dry-run)           │
   │ ApprovalGateway (HITL): signed callbacks · four-eyes · timeout = DENY                   │
   └───────────────┬────────────────────────────────────────────────────────────────────────┘
                   ▼  only ALLOW / SANITIZED / human-approved calls
   ┌─────────────────────────── TIER 3: EPHEMERAL SANDBOX ────────────────────────────────┐
   │ AST pre-flight (advisory) → fresh container/pod per run:                               │
   │   --network none · --cap-drop ALL · --read-only · no-new-privileges · non-root ·       │
   │   cgroup mem/cpu/pids · ulimits · tmpfs noexec · no mounts · code on stdin · gVisor    │
   │ Backends: Docker(DinD) | Kubernetes pod (RuntimeClass gvisor, Cilium air-gap policy)   │
   │ Kernel: Tetragon TracingPolicy (in-kernel SIGKILL) + SyscallPolicy/EbpfSyscallMonitor  │
   └───────────────┬────────────────────────────────────────────────────────────────────────┘
                   ▼
   ┌─────────────────────────── TIER 4: AUDIT · IDENTITY · COMPLIANCE ───────────────────┐
   │ AuditLedger: RFC-6962 Merkle tree + hash chain + Ed25519 signed checkpoints; digests   │
   │   only (no payloads); sinks: JSONL · Postgres(RLS, append-only) · Redis Stream         │
   │ ZKIdentity: Schnorr proof-of-knowledge (nonce/audience/scope-bound) → HMAC cap-token;  │
   │   LLM sees only pseudonym + scope names                                                │
   │ AIBOM: CycloneDX 1.6 ML-BOM + EU AI Act / NIST AI RMF / ISO 42001 evidence map         │
   │ ContinuousRedTeam: seeded mutation fuzzing → detection/FP gauges                       │
   └───────────────────────────────────────────────────────────────────────────────────────┘
   Observability: Prometheus /metrics · optional OpenTelemetry spans
```

## 2. Module map

| Deliverable | File |
|---|---|
| Middleware interceptor + threat scoring | `agentshield/agent_shield_middleware.py`, `pipeline.py`, `risk.py` |
| Multi-modal CNN scanner | `agentshield/vision_cnn_scanner.py` |
| Threat hunters + RAG sanitizer | `agentshield/threat_hunter.py`, `signatures.py`, `text_normalizer.py` |
| Docker execution manager | `agentshield/sandbox_manager.py` (+ `ebpf_monitor.py`) |
| Merkle audit ledger | `agentshield/audit_merkle_ledger.py` |
| ZK identity | `agentshield/zk_identity.py` |
| Policy / HITL / self-heal | `policy_engine.py`, `hitl.py`, `self_heal.py` |
| AI-BOM / red-team | `ai_bom.py`, `redteam.py` |
| Manifests | `docker-compose.yml`, `deploy/`, `db/`, `charts/agentshield-x/`, `deploy/tetragon/` |
| Tests | `tests/test_security_pipeline.py` (179 tests) |
| Paraphrase benchmark | `evals/paraphrase_eval.py` |

## 3. Honest limits

* **Semantic coverage.** Signature/cue layers catch known evasion families (100% on the bundled red-team
  corpus) but only **2/10 on unseen paraphrases** (`evals/paraphrase_eval.py`, 1/27 benign false positives).
  Enable a learned classifier (`text_classifier.py`; no weights shipped) for real paraphrase coverage. The hard
  guarantees (deny-by-default tools, schema/RBAC/ABAC, HITL, sandbox) do **not** depend on text detection.
* **ZK identity** is pseudonymous Schnorr authentication, not an anonymous-credential system (sessions are
  linkable). Use BBS+/zk-SNARK credentials behind the same interface for unlinkable attributes. The pure-Python
  prover is variable-time; clients should use libsecp256k1.
* **Vision.** No CNN weights ship; train on your own corpus (`build_visual_guard_model`/`export_onnx`).
  Heuristics detect common constructions, not all adversarial perturbations.
* **"Sub-millisecond".** Measured ~0.2 ms for short benign text on one core; image/OCR scans take hundreds of ms.
* **DinD needs `privileged`.** Contained to an internal network; prefer the Kubernetes/gVisor path in production.
* **Static code screening is advisory** (trivially evadable); containment comes from the sandbox layers.

## 9. v2 additions

| Capability | Module | Notes |
|---|---|---|
| Hybrid post-quantum checkpoints | `audit_merkle_ledger.py` | Ed25519 + ML-DSA-65 (FIPS 204); `alg` is inside the signed bytes so a checkpoint cannot be relabelled to drop the PQ signature |
| External anchoring | `anchor.py` | hash-chained signed checkpoints; `verify_anchors` detects whole-history rewrites and truncation that self-consistent ledgers cannot |
| Policy-as-code | `policy_loader.py`, `policies/` | strict YAML (unknown keys are errors), Rego mirror in `policies/rego`; invalid policy aborts startup |
| MCP guard | `mcp_guard.py` | stdio proxy: tool-poisoning scan, rug-pull pinning, result healing, denies server `sampling`/`elicitation`, per-call authorization |
| Framework adapters | `adapters.py` | `Shield.tool`, `guard_llm`, `guard_retriever`; framework-agnostic (LangGraph/CrewAI/AutoGen glue is the app's) |
| CLI | `cli.py` | scan, verify-ledger, policy-validate, redteam, aibom, keygen, serve, mcp-proxy |
| Console | `console.py`, `static/console.html` | single static page, CSP hashes computed at runtime, text-only DOM insertion, no third-party assets |
| Bootstrap | `bootstrap.py` | env-driven assembly (policy dir, persistent keys, anchoring) |

Further reading: `docs/THREAT_MODEL.md`, `docs/COVERAGE.md`, `docs/DEPLOYMENT.md`, `docs/RUNBOOK.md`.
