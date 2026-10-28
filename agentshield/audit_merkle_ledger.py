"""Cryptographic audit ledger: append-only, hash-chained, RFC 6962 Merkle tree.

* Every entry is a leaf: ``H(0x00 || canonical_json(entry))``; interior nodes are
  ``H(0x01 || left || right)`` (domain separation prevents leaf/node confusion).
* Entries are *also* hash-chained (``prev`` = previous leaf hash) so a deleted or
  re-ordered record is detectable even without the tree.
* Checkpoints (size, root, timestamp) are signed with Ed25519, so auditors verify
  with a public key and never need a shared secret.
* By default only a SHA-256 digest of each payload is stored (no prompts / PII in
  the log). Set ``digest_key`` to use HMAC digests, which resist dictionary
  attacks against low-entropy prompts at the cost of key-dependent verification.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

_EMPTY_ROOT = hashlib.sha256(b"").digest()


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str).encode()


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    """Largest power of two strictly less than n (n >= 2)."""
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


def merkle_root(hashes: list[bytes]) -> bytes:
    """RFC 6962 Merkle Tree Hash over already-hashed leaves."""
    n = len(hashes)
    if n == 0:
        return _EMPTY_ROOT
    if n == 1:
        return hashes[0]
    k = _split(n)
    return node_hash(merkle_root(hashes[:k]), merkle_root(hashes[k:]))


def inclusion_path(index: int, hashes: list[bytes]) -> list[bytes]:
    """Audit path for leaf ``index`` (RFC 6962 section 2.1.1)."""
    n = len(hashes)
    if n <= 1:
        return []
    k = _split(n)
    if index < k:
        return inclusion_path(index, hashes[:k]) + [merkle_root(hashes[k:])]
    return inclusion_path(index - k, hashes[k:]) + [merkle_root(hashes[:k])]


def verify_inclusion(leaf: bytes, index: int, size: int, path: list[bytes], root: bytes) -> bool:
    """Verify an audit path (RFC 9162 section 2.1.3.2)."""
    if index >= size or size == 0:
        return False
    fn, sn, r = index, size - 1, leaf
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and hmac.compare_digest(r, root)


@dataclass(frozen=True, slots=True)
class LedgerEntry:
    seq: int
    ts: float
    kind: str
    actor: str
    payload_digest: str
    meta: dict[str, Any]
    prev: str
    leaf: str  # hex of leaf hash

    def body(self) -> dict[str, Any]:
        """The exact object that is hashed (everything except ``leaf``)."""
        d = asdict(self)
        d.pop("leaf")
        return d


@dataclass(frozen=True, slots=True)
class SignedCheckpoint:
    size: int
    root: str
    ts: float
    signature: str  # hex Ed25519 over the canonical checkpoint message (see ``checkpoint_message``)
    pq_signature: str = ""  # hex ML-DSA-65 (FIPS 204) over the same message; empty unless hybrid
    alg: str = "ed25519"  # "ed25519" | "ed25519+mldsa65"; part of the signed message => strip/downgrade attacks fail


def checkpoint_message(size: int, root: str, ts: float, alg: str = "ed25519") -> bytes:
    """Canonical bytes that are signed. The hybrid algorithm name is *inside* the message, so removing the
    post-quantum signature and relabelling the checkpoint as plain Ed25519 invalidates the Ed25519 signature too."""
    body: dict[str, Any] = {"size": size, "root": root, "ts": ts}
    if alg != "ed25519":
        body["alg"] = alg
    return _canonical(body)


class LedgerSink(Protocol):
    def write(self, entry: LedgerEntry) -> None: ...


class JsonlSink:
    """Append-only JSONL sink (fsync per write when ``durable``)."""

    def __init__(self, path: str, durable: bool = False) -> None:
        self._f = open(path, "a", encoding="utf-8")
        self._durable = durable

    def write(self, entry: LedgerEntry) -> None:
        self._f.write(json.dumps(asdict(entry), sort_keys=True) + "\n")
        self._f.flush()
        if self._durable:
            os.fsync(self._f.fileno())

    def close(self) -> None:
        self._f.close()


class AuditLedger:
    """Thread-safe append-only Merkle ledger."""

    def __init__(
        self,
        signing_key: Ed25519PrivateKey | None = None,
        *,
        digest_key: bytes | None = None,
        sinks: list[LedgerSink] | None = None,
        keep_entries: bool = True,
        clock: Callable[[], float] = time.time,
        pq_key: Any | None = None,
    ) -> None:
        """``pq_key``: optional ``mldsa.MLDSA65PrivateKey``. When set, checkpoints are hybrid-signed
        (Ed25519 + ML-DSA-65) so the audit trail stays verifiable if Ed25519 is ever broken by a quantum adversary."""
        self._key = signing_key or Ed25519PrivateKey.generate()
        self._pq = pq_key
        self._digest_key = digest_key
        self._sinks = list(sinks or [])
        self._keep = keep_entries
        self._clock = clock
        self._lock = threading.Lock()
        self._leaves: list[bytes] = []
        self._entries: list[LedgerEntry] = []
        self._frontier: list[tuple[int, bytes]] = []  # perfect subtrees (height, hash)
        self._prev = "0" * 64

    # ---- digesting -------------------------------------------------------
    def digest(self, payload: Any) -> str:
        data = payload if isinstance(payload, (bytes, bytearray)) else _canonical(payload)
        if self._digest_key:
            return hmac.new(self._digest_key, bytes(data), hashlib.sha256).hexdigest()
        return hashlib.sha256(bytes(data)).hexdigest()

    # ---- append ----------------------------------------------------------
    def append(self, kind: str, actor: str, payload: Any, meta: dict[str, Any] | None = None) -> LedgerEntry:
        """Record an event. ``payload`` is digested; only ``meta`` is stored verbatim."""
        digest = self.digest(payload)
        with self._lock:
            seq = len(self._leaves)
            entry = LedgerEntry(seq, self._clock(), kind, actor, digest, dict(meta or {}), self._prev, "")
            lh = leaf_hash(_canonical(entry.body()))
            entry = LedgerEntry(**{**entry.body(), "leaf": lh.hex()})
            self._push(lh)
            if self._keep:
                self._entries.append(entry)
            self._prev = entry.leaf
            err: Exception | None = None
            for sink in self._sinks:  # isolate sinks: one failing must not leave the others with a gap
                try:
                    sink.write(entry)
                except Exception as e:  # noqa: BLE001
                    err = err or e
            if err is not None:
                raise err  # fail closed: the audited operation must not proceed unrecorded
        return entry

    def _push(self, lh: bytes) -> None:
        """Add a leaf and maintain the O(log n) frontier of perfect subtrees."""
        self._leaves.append(lh)
        self._frontier.append((0, lh))
        while len(self._frontier) >= 2 and self._frontier[-1][0] == self._frontier[-2][0]:
            h2, r = self._frontier.pop()
            h1, l = self._frontier.pop()
            self._frontier.append((h1 + 1, node_hash(l, r)))

    def add_sink(self, sink: LedgerSink) -> None:
        with self._lock:
            self._sinks.append(sink)

    def restore(self, entries: list[LedgerEntry]) -> None:
        """Resume from persisted history. Raises ``ValueError`` if it fails verification
        (edit, deletion, reordering) - callers must treat that as a tamper alarm and refuse to start."""
        ok, msg = verify_entries(entries)
        if not ok:
            raise ValueError(f"persisted audit ledger failed verification: {msg}")
        with self._lock:
            if self._leaves:
                raise ValueError("restore() only valid on an empty ledger")
            for e in entries:
                self._push(bytes.fromhex(e.leaf))
                if self._keep:
                    self._entries.append(e)
                self._prev = e.leaf

    # ---- queries ---------------------------------------------------------
    @property
    def size(self) -> int:
        return len(self._leaves)

    def root(self) -> bytes:
        with self._lock:
            if not self._frontier:
                return _EMPTY_ROOT
            r = self._frontier[-1][1]
            for _, h in reversed(self._frontier[:-1]):
                r = node_hash(h, r)
            return r

    def entry(self, seq: int) -> LedgerEntry:
        return self._entries[seq]

    def inclusion_proof(self, seq: int) -> dict[str, Any]:
        with self._lock:
            if not 0 <= seq < len(self._leaves):
                raise IndexError(seq)
            leaves = list(self._leaves)
        path = inclusion_path(seq, leaves)
        return {
            "seq": seq,
            "size": len(leaves),
            "leaf": leaves[seq].hex(),
            "path": [p.hex() for p in path],
            "root": merkle_root(leaves).hex(),
        }

    @staticmethod
    def verify_proof(proof: dict[str, Any]) -> bool:
        return verify_inclusion(
            bytes.fromhex(proof["leaf"]), proof["seq"], proof["size"],
            [bytes.fromhex(p) for p in proof["path"]], bytes.fromhex(proof["root"]),
        )

    # ---- signing ---------------------------------------------------------
    def checkpoint(self) -> SignedCheckpoint:
        size, root, ts = self.size, self.root().hex(), self._clock()
        alg = "ed25519+mldsa65" if self._pq is not None else "ed25519"
        msg = checkpoint_message(size, root, ts, alg)
        pq = self._pq.sign(msg).hex() if self._pq is not None else ""
        return SignedCheckpoint(size, root, ts, self._key.sign(msg).hex(), pq, alg)

    @property
    def public_keys_pem(self) -> dict[str, bytes]:
        """All verification keys (PEM, SubjectPublicKeyInfo), keyed by algorithm."""
        out = {"ed25519": self.public_key_pem}
        if self._pq is not None:
            out["mldsa65"] = self._pq.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        return out

    @staticmethod
    def verify_checkpoint_hybrid(cp: SignedCheckpoint, ed_public: Ed25519PublicKey, pq_public: Any) -> bool:
        """Strict verifier: the checkpoint must be hybrid AND both signatures must verify."""
        if cp.alg != "ed25519+mldsa65" or not cp.pq_signature:
            return False
        msg = checkpoint_message(cp.size, cp.root, cp.ts, cp.alg)
        try:
            ed_public.verify(bytes.fromhex(cp.signature), msg)
            pq_public.verify(bytes.fromhex(cp.pq_signature), msg)
            return True
        except (InvalidSignature, ValueError, Exception):  # noqa: BLE001 - any failure => reject
            return False

    @property
    def public_key_pem(self) -> bytes:
        return self._key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @staticmethod
    def verify_checkpoint(cp: SignedCheckpoint, public_key: Ed25519PublicKey) -> bool:
        try:
            public_key.verify(bytes.fromhex(cp.signature), checkpoint_message(cp.size, cp.root, cp.ts, cp.alg))
            return True
        except (InvalidSignature, ValueError):
            return False

    # ---- integrity -------------------------------------------------------
    def verify_integrity(self) -> tuple[bool, str]:
        """Recompute chain + root from stored entries. Detects edits, deletions, reordering."""
        return verify_entries(self._entries, self.root())


def verify_entries(entries: list[LedgerEntry], expected_root: bytes | None = None) -> tuple[bool, str]:
    """Stand-alone verifier for exported ledgers."""
    prev = "0" * 64
    leaves: list[bytes] = []
    for i, e in enumerate(entries):
        if e.seq != i:
            return False, f"sequence gap at {i}"
        if e.prev != prev:
            return False, f"hash-chain break at {i}"
        lh = leaf_hash(_canonical(e.body()))
        if lh.hex() != e.leaf:
            return False, f"leaf hash mismatch at {i}"
        leaves.append(lh)
        prev = e.leaf
    root = merkle_root(leaves)
    if expected_root is not None and not hmac.compare_digest(root, expected_root):
        return False, "root mismatch"
    return True, "ok"


def load_jsonl(path: str) -> list[LedgerEntry]:
    out: list[LedgerEntry] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                out.append(LedgerEntry(**json.loads(line)))
    return out


class _QueueSink:
    """Base for async sinks: ``write`` is sync + non-blocking; a background task drains the queue.

    A full queue raises ``asyncio.QueueFull`` into ``AuditLedger.append`` => the audited operation fails
    (fail closed: we never silently drop audit records). Records are also in the in-process ledger and the
    JSONL sink, so a transient outage delays persistence but does not lose the tamper-evident chain.
    """

    def __init__(self, maxsize: int = 100_000) -> None:
        import asyncio

        self._q: "asyncio.Queue[LedgerEntry]" = asyncio.Queue(maxsize=maxsize)

    def write(self, entry: LedgerEntry) -> None:
        self._q.put_nowait(entry)

    def _drain(self, limit: int) -> list[LedgerEntry]:
        rows = [self._q.get_nowait() for _ in range(min(limit, self._q.qsize()))]
        return rows


class PostgresSink(_QueueSink):  # pragma: no cover - requires asyncpg + running Postgres (not exercised in unit tests)
    """Batching sink into the RLS-protected ``audit_log`` table (see ``db/init.sql``)."""

    def __init__(self, dsn: str, ledger_id: str | None = None, batch: int = 100) -> None:
        super().__init__()
        self._dsn, self._batch = dsn, batch
        self.ledger_id = ledger_id or os.environ.get("HOSTNAME", "ledger-0")

    async def run(self) -> None:
        import asyncio
        import asyncpg

        pool = None
        while pool is None:
            try:
                pool = await asyncpg.create_pool(self._dsn, min_size=1, max_size=4)
            except Exception:  # noqa: BLE001 - DB not up yet: keep buffering, retry
                await asyncio.sleep(2.0)
        while True:
            first = await self._q.get()
            rows = [first, *self._drain(self._batch - 1)]
            try:
                async with pool.acquire() as con:
                    await con.executemany(
                        "INSERT INTO audit_log(ledger_id,seq,ts,kind,actor,payload_digest,meta,prev,leaf) "
                        "VALUES($1,$2,to_timestamp($3),$4,$5,$6,$7::jsonb,$8,$9) ON CONFLICT DO NOTHING",
                        [(self.ledger_id, e.seq, e.ts, e.kind, e.actor, e.payload_digest, json.dumps(e.meta), e.prev, e.leaf) for e in rows])
            except Exception:  # noqa: BLE001 - re-queue and back off; never drop
                for e in rows:
                    self._q.put_nowait(e)
                await asyncio.sleep(2.0)


class RedisStreamSink(_QueueSink):  # pragma: no cover - requires redis + running Redis (not exercised in unit tests)
    """Publishes ledger entries to a capped Redis Stream (event bus for SIEM / downstream consumers)."""

    def __init__(self, url: str, stream: str = "shield:events", maxlen: int = 100_000) -> None:
        super().__init__()
        self._url, self._stream, self._maxlen = url, stream, maxlen

    async def run(self) -> None:
        import asyncio
        import redis.asyncio as aioredis

        r = aioredis.from_url(self._url, decode_responses=True)
        while True:
            e = await self._q.get()
            try:
                await r.xadd(self._stream, {"seq": e.seq, "kind": e.kind, "actor": e.actor, "digest": e.payload_digest,
                                            "leaf": e.leaf, "meta": json.dumps(e.meta)}, maxlen=self._maxlen, approximate=True)
            except Exception:  # noqa: BLE001
                self._q.put_nowait(e)
                await asyncio.sleep(2.0)
