"""Dependency-free Prometheus-format metrics + optional OpenTelemetry spans."""

from __future__ import annotations

import contextlib
import threading
from typing import Any, Iterator

_BUCKETS = (0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5)


def _fmt_labels(names: tuple[str, ...], values: tuple[str, ...]) -> str:
    if not names:
        return ""
    inner = ",".join(f'{n}="{str(v).replace(chr(92), chr(92)*2).replace(chr(34), chr(92)+chr(34))}"' for n, v in zip(names, values))
    return "{" + inner + "}"


class _Metric:
    kind = "untyped"

    def __init__(self, name: str, doc: str, labels: tuple[str, ...] = ()) -> None:
        self.name, self.doc, self.labels = name, doc, labels
        self._lock = threading.Lock()


class Counter(_Metric):
    kind = "counter"

    def __init__(self, *a: Any, **k: Any) -> None:
        super().__init__(*a, **k)
        self._v: dict[tuple[str, ...], float] = {}

    def inc(self, *label_values: str, amount: float = 1.0) -> None:
        with self._lock:
            self._v[label_values] = self._v.get(label_values, 0.0) + amount

    def render(self) -> list[str]:
        return [f"{self.name}{_fmt_labels(self.labels, k)} {v}" for k, v in sorted(self._v.items())]

    def snapshot(self) -> dict[tuple[str, ...], float]:
        """Thread-safe copy of the current values (used by the console)."""
        with self._lock:
            return dict(self._v)


class Gauge(Counter):
    kind = "gauge"

    def set(self, value: float, *label_values: str) -> None:
        with self._lock:
            self._v[label_values] = value


class Histogram(_Metric):
    kind = "histogram"

    def __init__(self, *a: Any, buckets: tuple[float, ...] = _BUCKETS, **k: Any) -> None:
        super().__init__(*a, **k)
        self.buckets = buckets
        self._counts: dict[tuple[str, ...], list[int]] = {}
        self._sum: dict[tuple[str, ...], float] = {}

    def observe(self, value: float, *label_values: str) -> None:
        with self._lock:
            c = self._counts.setdefault(label_values, [0] * (len(self.buckets) + 1))
            for i, b in enumerate(self.buckets):
                if value <= b:
                    c[i] += 1
            c[-1] += 1
            self._sum[label_values] = self._sum.get(label_values, 0.0) + value

    def render(self) -> list[str]:
        out: list[str] = []
        for k, c in sorted(self._counts.items()):
            for b, n in zip(self.buckets, c):
                out.append(f"{self.name}_bucket{_fmt_labels(self.labels + ('le',), k + (str(b),))} {n}")
            out.append(f"{self.name}_bucket{_fmt_labels(self.labels + ('le',), k + ('+Inf',))} {c[-1]}")
            out.append(f"{self.name}_sum{_fmt_labels(self.labels, k)} {self._sum[k]}")
            out.append(f"{self.name}_count{_fmt_labels(self.labels, k)} {c[-1]}")
        return out


class Registry:
    def __init__(self) -> None:
        self._m: list[_Metric] = []

    def add(self, m: _Metric) -> Any:
        self._m.append(m)
        return m

    def render(self) -> str:
        lines: list[str] = []
        for m in self._m:
            lines += [f"# HELP {m.name} {m.doc}", f"# TYPE {m.name} {m.kind}"]
            lines += m.render()  # type: ignore[attr-defined]
        return "\n".join(lines) + "\n"


REGISTRY = Registry()
REQUESTS = REGISTRY.add(Counter("shield_requests_total", "Requests by verdict", ("route", "verdict")))
FINDINGS = REGISTRY.add(Counter("shield_findings_total", "Findings by category", ("category",)))
SCAN_SECONDS = REGISTRY.add(Histogram("shield_scan_seconds", "Scan latency", ("stage",)))
HITL_PENDING = REGISTRY.add(Gauge("shield_hitl_pending", "Pending human approvals"))
HITL_OUTCOMES = REGISTRY.add(Counter("shield_hitl_outcomes_total", "Approval outcomes", ("status",)))
SANDBOX_RUNS = REGISTRY.add(Counter("shield_sandbox_runs_total", "Sandbox runs by outcome", ("outcome",)))
REDTEAM_RATE = REGISTRY.add(Gauge("shield_redteam_detection_rate", "Latest red-team detection rate", ("suite",)))
LEDGER_SIZE = REGISTRY.add(Gauge("shield_audit_ledger_entries", "Entries in the Merkle ledger"))


@contextlib.contextmanager
def span(name: str, **attrs: Any) -> Iterator[Any]:
    """OpenTelemetry span when the SDK is installed; otherwise a no-op."""
    try:
        from opentelemetry import trace  # type: ignore[import-not-found]
    except ImportError:
        yield None
        return
    with trace.get_tracer("agentshield-x").start_as_current_span(name) as sp:
        for k, v in attrs.items():
            sp.set_attribute(k, v if isinstance(v, (str, int, float, bool)) else str(v))
        yield sp
