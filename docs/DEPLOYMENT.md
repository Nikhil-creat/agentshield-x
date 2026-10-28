# Deployment

> Status: the compose file validates with `docker compose config`; the Helm chart, Cilium and Tetragon policies are
> YAML-parsed and linted in CI but were **not applied to a cluster** by the author. Treat first deployment as a staging exercise.

## 0. Secrets and keys
```bash
cp .env.example .env                 # then replace every CHANGE_ME with: openssl rand -hex 32
python -m agentshield keygen --out keys   # Ed25519 + ML-DSA-65 ledger keys, approval + pepper secrets (0600)
```
`.env`, `secrets/` and `keys/` are gitignored. Mount `keys/` read-only into the API container and set
`SHIELD_LEDGER_KEY_DIR`; keep the private keys out of any volume the API can write to.

## 1. Docker Compose (single host)
```bash
docker compose up --build -d
curl -s localhost:8080/healthz
open http://localhost:8080/console        # paste an auditor token
```
Networks: `edge` (published port), `data` (Postgres/Redis, internal), `sandbox` (internal, no internet), `egress` (proxy only).
Optional gVisor: set `SHIELD_SANDBOX_RUNTIME=runsc` after installing `runsc` in the dind image. Optional allow-listed egress for
sandboxes: `docker compose --profile egress up`.

## 2. Kubernetes (Helm)
Prerequisites: Cilium CNI (for the air-gap `CiliumNetworkPolicy`), Tetragon (for the kernel `TracingPolicy`), a gVisor `RuntimeClass`.
```bash
helm lint charts/agentshield-x
helm template agentshield charts/agentshield-x | less      # read it before applying
helm install agentshield charts/agentshield-x -n agentshield --create-namespace \
  --set image.repository=ghcr.io/nikhil-creat/agentshield-x --set image.tag=v2.2.0
```
The chart runs sandboxes as short-lived pods (`KubernetesSandboxManager`) in a dedicated namespace with RBAC limited to
create/delete/get on pods there.

## 3. Policies
`policies/tools.yaml` and `abac.yaml` are loaded at startup via `SHIELD_POLICY_DIR` (set in the image). An invalid file stops the
process - there is no fallback to defaults. Validate in CI with `agentshield policy-validate policies`.
Optional OPA sidecar: load `policies/rego/authz.rego` and configure `OpaClient` (any error denies).

## 4. Audit integrity in production
Set `SHIELD_ANCHOR_PATH` and ship the file to storage the API cannot rewrite (object-lock bucket, separate account, transparency log).
Verify on a schedule: `agentshield verify-ledger audit.jsonl --anchors anchors.jsonl --ed25519-pub ... --mldsa-pub ...`.

## 5. Observability
Scrape `/metrics`; import `docs/dashboards/agentshield-grafana.json`; load `docs/alerts/agentshield.rules.yml` into Prometheus.

## 6. Put an agent behind it
```python
from agentshield.adapters import Shield
shield = Shield(pipeline, principal, session_id="s1")
@shield.tool("search_docs")
async def search_docs(query: str) -> str: ...
```
For MCP servers: `agentshield mcp-proxy --subject alice --scope tools.search --pins pins.json -- npx some-mcp-server`.
