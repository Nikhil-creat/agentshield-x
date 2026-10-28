"""Automated AI-BOM: a CycloneDX 1.6-style ML-BOM generated from live system state.

Tracks model weights (content hash), datasets, prompt templates, RAG sources, tools, and the
Python dependency closure (``importlib.metadata``). Each snapshot is hashed and recorded in the
Merkle ledger so a regulator can prove *which* BOM was in force at a given time.

Compliance output is an **evidence map**: which AgentShield controls produce artifacts relevant to
EU AI Act / NIST AI RMF / ISO 42001 clauses. It is not a conformity assessment or certification.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import sys
import time
import uuid
from dataclasses import dataclass, field
from importlib import metadata
from typing import Any, Iterable

from .audit_merkle_ledger import AuditLedger
from .policy_engine import ToolRegistry

COMPLIANCE_MAP: dict[str, list[dict[str, str]]] = {
    "EU AI Act": [
        {"ref": "Art. 9", "topic": "Risk management system", "evidence": "risk scores per request/tool call; continuous red-team detection-rate metric"},
        {"ref": "Art. 10", "topic": "Data and data governance", "evidence": "RAG source allow-list, drift analysis, dataset entries in AI-BOM"},
        {"ref": "Art. 11/Annex IV", "topic": "Technical documentation", "evidence": "AI-BOM snapshot hash + architecture document"},
        {"ref": "Art. 12", "topic": "Record-keeping", "evidence": "append-only Ed25519-checkpointed Merkle audit ledger with inclusion proofs"},
        {"ref": "Art. 14", "topic": "Human oversight", "evidence": "HITL gateway: signed, four-eyes, deny-on-timeout approvals recorded in ledger"},
        {"ref": "Art. 15", "topic": "Accuracy, robustness, cybersecurity", "evidence": "input/RAG/vision scanners, sandbox isolation, red-team suite results"},
    ],
    "NIST AI RMF": [
        {"ref": "GOVERN 1", "topic": "Policies & accountability", "evidence": "deny-by-default tool registry, RBAC/ABAC rules as code"},
        {"ref": "MAP 4", "topic": "Third-party / supply chain risk", "evidence": "AI-BOM components with hashes and licenses"},
        {"ref": "MEASURE 2.7", "topic": "Security & resilience evaluated", "evidence": "automated red-team run reports"},
        {"ref": "MEASURE 2.8", "topic": "Transparency & accountability risks", "evidence": "ledger + decision reasons attached to every verdict"},
        {"ref": "MANAGE 2/4", "topic": "Risk treatment & incident response", "evidence": "self-healing loop, kill-on-violation sandbox monitor, approvals"},
    ],
    "ISO/IEC 42001": [
        {"ref": "A.6.2.8", "topic": "AI system recording of event logs", "evidence": "Merkle ledger"},
        {"ref": "A.7", "topic": "Data for AI systems", "evidence": "RAG sanitization + dataset records"},
        {"ref": "A.9", "topic": "Use of AI systems / human oversight", "evidence": "HITL approvals"},
        {"ref": "A.10", "topic": "Third-party and customer relationships", "evidence": "AI-BOM, egress allow-lists"},
        {"ref": "6.1", "topic": "Actions to address risks", "evidence": "risk engine thresholds, red-team gate in CI"},
    ],
}


def sha256_file(path: str, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while b := f.read(chunk):
            h.update(b)
    return h.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass
class Component:
    kind: str  # model | dataset | prompt | rag-source | tool | library
    name: str
    version: str = ""
    sha256: str = ""
    supplier: str = ""
    license: str = ""
    properties: dict[str, str] = field(default_factory=dict)


class AIBOM:
    def __init__(self, system_name: str = "agentshield-x", system_version: str = "2.1.0") -> None:
        self.system = (system_name, system_version)
        self._c: dict[tuple[str, str], Component] = {}

    # --- registration ------------------------------------------------------
    def add(self, c: Component) -> None:
        self._c[(c.kind, c.name)] = c

    def add_model(self, name: str, path: str | None = None, version: str = "", supplier: str = "", license: str = "", **props: str) -> None:
        digest = sha256_file(path) if path and os.path.isfile(path) else ""
        self.add(Component("model", name, version, digest, supplier, license, {"path": path or "", "weights_present": str(bool(digest)).lower(), **props}))

    def add_dataset(self, name: str, path: str | None = None, version: str = "", **props: str) -> None:
        digest = sha256_file(path) if path and os.path.isfile(path) else ""
        self.add(Component("dataset", name, version, digest, properties=props))

    def add_prompt_template(self, name: str, template: str, version: str = "") -> None:
        self.add(Component("prompt", name, version, sha256_text(template)))

    def add_rag_source(self, uri: str, trusted: bool, collection: str = "default", version: str = "") -> None:
        self.add(Component("rag-source", uri, version, properties={"trusted": str(trusted).lower(), "collection": collection}))

    def add_tools(self, registry: ToolRegistry) -> None:
        for n in registry.names():
            spec = registry.get(n)
            assert spec is not None
            digest = sha256_text(json.dumps(dict(spec.schema), sort_keys=True))
            self.add(Component("tool", n, "", digest, properties={"effect": spec.effect.value, "scope": spec.required_scope,
                                                                    "approval": str(spec.needs_approval).lower()}))

    def add_python_dependencies(self, only: Iterable[str] | None = None) -> None:
        wanted = {o.lower() for o in only} if only else None
        for d in metadata.distributions():
            name = d.metadata["Name"]
            if not name or (wanted and name.lower() not in wanted):
                continue
            self.add(Component("library", name, d.version or "", supplier=(d.metadata["Author"] or ""), license=(d.metadata["License-Expression"] or d.metadata["License"] or "")[:80]))

    # --- export ------------------------------------------------------------
    def components(self) -> list[Component]:
        return sorted(self._c.values(), key=lambda c: (c.kind, c.name))

    def to_cyclonedx(self) -> dict[str, Any]:
        ctype = {"model": "machine-learning-model", "dataset": "data", "prompt": "data", "rag-source": "data", "tool": "application", "library": "library"}
        comps = []
        for c in self.components():
            e: dict[str, Any] = {"type": ctype[c.kind], "bom-ref": f"{c.kind}:{c.name}", "name": c.name}
            if c.version:
                e["version"] = c.version
            if c.sha256:
                e["hashes"] = [{"alg": "SHA-256", "content": c.sha256}]
            if c.supplier:
                e["supplier"] = {"name": c.supplier}
            if c.license:
                e["licenses"] = [{"license": {"name": c.license}}]
            e["properties"] = [{"name": "agentshield:kind", "value": c.kind}, *({"name": f"agentshield:{k}", "value": v} for k, v in sorted(c.properties.items()))]
            comps.append(e)
        return {
            "bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
            "metadata": {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                         "component": {"type": "application", "name": self.system[0], "version": self.system[1]},
                         "properties": [{"name": "python", "value": sys.version.split()[0]}, {"name": "platform", "value": platform.platform()}]},
            "components": comps,
        }

    def snapshot(self, ledger: AuditLedger | None = None, actor: str = "system") -> dict[str, Any]:
        """BOM + compliance evidence map; digest is recorded in the ledger when one is given."""
        bom = self.to_cyclonedx()
        canonical = json.dumps({k: v for k, v in bom.items() if k not in ("serialNumber",)}, sort_keys=True, separators=(",", ":"))
        digest = sha256_text(canonical)
        entry = None
        if ledger is not None:
            e = ledger.append("ai_bom", actor, canonical.encode(), {"components": len(bom["components"]), "digest": digest})
            entry = e.seq
        return {"bom": bom, "digest": digest, "ledger_seq": entry, "compliance_evidence": COMPLIANCE_MAP,
                "disclaimer": "Evidence mapping only; not a conformity assessment or certification."}
