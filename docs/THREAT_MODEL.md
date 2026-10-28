# Threat model

## Assets
Model context window and system prompt; tool/credential authority; user and tenant data; the audit trail; signing keys;
the guard's own configuration (policies, pins, thresholds).

## Trust boundaries
| Boundary | Trust | Control |
|---|---|---|
| Client → API | none | bearer capability token (HMAC), rate limit, size cap, JSON-only, per-string scan |
| Retrieved documents / web / tool output / MCP server | none (data, never instructions) | normalization, signatures, spotlighting, quarantine, healing |
| Model output → tool call | none | registry → schema → RBAC → ABAC → egress → OPA → HITL |
| Tool call → code execution | none | ephemeral container/pod, no network, no mounts, kernel policy |
| API → ledger/DB | partial | digests only, signed checkpoints, append-only DB role, external anchors |
| Operator → config | trusted but fallible | strict loaders (typos are errors), fail-closed startup |

## Adversaries and what stops them
| Adversary goal | Mechanism | Residual risk |
|---|---|---|
| Direct prompt injection / jailbreak | signature + cue co-occurrence, multi-turn and split-payload hunters, healing | **Novel paraphrases can evade rule/cue layers** (measured: 2/10 fresh paraphrases caught). Mitigate with the learned classifier hook and least-privilege tools |
| Obfuscated injection (homoglyph, zero-width, Unicode tags, leet, rot13, reversed, base64) | normalizer + decoders | Unknown encodings |
| Indirect injection via RAG/tools | spotlighting, entropy/drift, source allow-list, result healing | Same paraphrase limit; spotlighting reduces but cannot guarantee model obedience |
| Image-borne instructions | OCR (visible + contrast-amplified), LSB, QR, metadata, trailing bytes, purify re-encode | Text rendered to defeat OCR; adversarial pixels without the ONNX guard |
| Confused-deputy tool abuse | schema + scope + role + ABAC + HITL, SSRF/traversal/secret hunters | Over-broad scopes granted by the operator |
| Exfiltration over network | egress allow-list, sandbox `--network none`, Cilium/Squid | Covert channels via allowed hosts |
| Sandbox escape | hardened argv, gVisor RuntimeClass, Tetragon | Kernel/runtime 0-days; **not exercised in CI** |
| MCP tool poisoning / rug pull / server sampling abuse | strict metadata scan, fingerprint pinning, denied `sampling`/`elicitation` | Malicious-but-clean-looking tools; first-use trust (TOFU) |
| Audit tampering by an insider with DB access | Merkle + chain + signed checkpoints + external anchors | Attacker who also controls anchor storage **and** signing keys |
| Quantum adversary forging checkpoints | hybrid Ed25519 + ML-DSA-65, alg inside signed bytes | Both algorithms must be broken |
| Identity replay | single-use, audience/nonce/scope-bound Schnorr proofs | Pseudonymous authentication only - **not** anonymous credentials |
| Approval spoofing | HMAC-signed decisions, four-eyes, timeout = deny, GET never mutates | Compromised approver account |
| DoS of the guard | size/rate caps, scan time budgets, bounded decoders | Resource exhaustion by many valid tenants |

## Explicit non-goals
Not a compliance certification (the AI-BOM evidence map is evidence, not attestation). Not a substitute for least
privilege, secret management or network segmentation. Not a guarantee against model misbehaviour.

## Verified vs. unverified
See the verification table in `README.md`. In short: logic is unit-tested; real container isolation, Postgres/Redis,
Kubernetes/Cilium/Tetragon, OPA and the FastAPI wiring were not exercised in the build environment and are covered by CI jobs
or require your cluster.
