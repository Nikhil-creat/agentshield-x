"""Zero-knowledge identity + capability tokens.

What this actually provides
---------------------------
* A non-interactive **Schnorr proof of knowledge** (Fiat-Shamir) over secp256k1.
  The user proves they hold the secret key behind a registered public identity
  commitment, bound to a server nonce, an audience and the exact scopes being
  requested. The secret never leaves the client; the proof cannot be replayed
  (single-use nonce) or re-targeted (context is part of the challenge hash).
* The verifier maps a *pseudonym* (``sha256(pubkey)[:16]``) to entitlements held
  server-side, then mints a short-lived HMAC capability token. The LLM context only
  ever sees the pseudonym + scope names, never names, e-mails or corporate IDs.

What it does *not* provide
--------------------------
This is pseudonymous authentication, not an anonymous-credential system: the
server can link repeated sessions of the same key. For unlinkable attribute
predicates ("clearance >= 2") use BBS+/Idemix/zk-SNARK credentials behind the same
``verify_and_issue`` interface. The pure-Python prover below is variable-time;
client SDKs should use libsecp256k1. The verifier handles only public values.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any

# --- secp256k1 -----------------------------------------------------------------
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
Point = tuple[int, int] | None
G: Point = (GX, GY)


def on_curve(pt: Point) -> bool:
    if pt is None:
        return False
    x, y = pt
    return 0 <= x < P and 0 <= y < P and (y * y - x * x * x - 7) % P == 0


def point_add(a: Point, b: Point) -> Point:
    if a is None:
        return b
    if b is None:
        return a
    (x1, y1), (x2, y2) = a, b
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if a == b:
        lam = 3 * x1 * x1 * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return x3, (lam * (x1 - x3) - y1) % P


def scalar_mult(k: int, pt: Point) -> Point:
    k %= N
    result: Point = None
    addend = pt
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def _pt_bytes(pt: Point) -> bytes:
    assert pt is not None
    return b"\x04" + pt[0].to_bytes(32, "big") + pt[1].to_bytes(32, "big")


def _pt_from_hex(h: str) -> Point:
    raw = bytes.fromhex(h)
    if len(raw) != 65 or raw[0] != 4:
        raise ValueError("expected 65-byte uncompressed point")
    pt = (int.from_bytes(raw[1:33], "big"), int.from_bytes(raw[33:], "big"))
    if not on_curve(pt):
        raise ValueError("point not on curve")
    return pt


def _challenge(Y: Point, R: Point, context: dict[str, Any]) -> int:
    ctx = json.dumps(context, sort_keys=True, separators=(",", ":")).encode()
    h = hashlib.sha256(b"agentshield-x/schnorr/v1\x00" + _pt_bytes(G) + _pt_bytes(Y) + _pt_bytes(R) + ctx).digest()
    return int.from_bytes(h, "big") % N


# --- prover (client side) -------------------------------------------------------
@dataclass(frozen=True)
class SchnorrProof:
    R: str  # hex uncompressed point
    s: str  # hex scalar


class ZKProver:
    """Client-side helper (also used by tests). Not constant-time; see module docstring."""

    def __init__(self, secret: int | None = None) -> None:
        self._x = secret if secret is not None else secrets.randbelow(N - 1) + 1
        if not 1 <= self._x < N:
            raise ValueError("secret out of range")
        self.public = scalar_mult(self._x, G)

    @property
    def public_hex(self) -> str:
        return _pt_bytes(self.public).hex()

    def prove(self, context: dict[str, Any]) -> SchnorrProof:
        r = secrets.randbelow(N - 1) + 1
        R = scalar_mult(r, G)
        c = _challenge(self.public, R, context)
        s = (r + c * self._x) % N
        return SchnorrProof(_pt_bytes(R).hex(), f"{s:064x}")


def verify_proof(public_hex: str, proof: SchnorrProof, context: dict[str, Any]) -> bool:
    """Check ``s*G == R + c*Y``. Pure function of public inputs."""
    try:
        Y = _pt_from_hex(public_hex)
        R = _pt_from_hex(proof.R)
        s = int(proof.s, 16)
    except (ValueError, TypeError):
        return False
    if not 0 < s < N:
        return False
    c = _challenge(Y, R, context)
    return scalar_mult(s, G) == point_add(R, scalar_mult(c, Y))


# --- capability tokens ----------------------------------------------------------
class TokenError(Exception):
    """Raised for any invalid, expired or revoked token (always deny)."""


@dataclass(frozen=True)
class Principal:
    subject: str  # pseudonym, safe to show to the LLM
    scopes: frozenset[str]
    roles: frozenset[str] = frozenset()
    attrs: dict[str, Any] = field(default_factory=dict)  # coarse ABAC attributes (no PII)
    jti: str = ""

    def llm_view(self) -> dict[str, Any]:
        """The only identity information that may enter an LLM context."""
        return {"subject": self.subject, "scopes": sorted(self.scopes)}


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class TokenAuthority:
    """Mints and verifies compact HMAC-SHA256 capability tokens."""

    def __init__(self, key: bytes | None = None, audience: str = "agentshield-x", ttl_s: int = 900) -> None:
        env = os.environ.get("SHIELD_TOKEN_KEY")  # inject from Vault in production
        self._key = key or (bytes.fromhex(env) if env else secrets.token_bytes(32))
        self.audience = audience
        self.ttl_s = ttl_s
        self._revoked: set[str] = set()
        self._lock = threading.Lock()

    def mint(self, principal: Principal, *, ttl_s: int | None = None) -> str:
        now = int(time.time())
        claims = {
            "sub": principal.subject, "scp": sorted(principal.scopes), "rol": sorted(principal.roles),
            "att": principal.attrs, "aud": self.audience, "iat": now,
            "exp": now + (ttl_s or self.ttl_s), "jti": principal.jti or secrets.token_hex(8),
        }
        body = _b64(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode())
        sig = _b64(hmac.new(self._key, body.encode(), hashlib.sha256).digest())
        return f"{body}.{sig}"

    def verify(self, token: str) -> Principal:
        try:
            body, sig = token.split(".", 1)
            expected = _b64(hmac.new(self._key, body.encode(), hashlib.sha256).digest())
            if not hmac.compare_digest(sig, expected):
                raise TokenError("bad signature")
            c = json.loads(_unb64(body))
        except (ValueError, TypeError, json.JSONDecodeError) as e:
            raise TokenError("malformed token") from e
        if c.get("aud") != self.audience:
            raise TokenError("wrong audience")
        if int(c.get("exp", 0)) < time.time():
            raise TokenError("expired")
        with self._lock:
            if c.get("jti") in self._revoked:
                raise TokenError("revoked")
        return Principal(c["sub"], frozenset(c.get("scp", ())), frozenset(c.get("rol", ())), dict(c.get("att", {})), c.get("jti", ""))

    def revoke(self, jti: str) -> None:
        with self._lock:
            self._revoked.add(jti)


# --- verifier / registry ---------------------------------------------------------
@dataclass
class Entitlement:
    scopes: frozenset[str]
    roles: frozenset[str] = frozenset()
    attrs: dict[str, Any] = field(default_factory=dict)


def pseudonym(public_hex: str) -> str:
    return hashlib.sha256(bytes.fromhex(public_hex)).hexdigest()[:16]


class ZKIdentityService:
    """Challenge/response flow: ``issue_challenge`` -> client proves -> ``verify_and_issue``."""

    def __init__(self, authority: TokenAuthority, challenge_ttl_s: int = 60) -> None:
        self.authority = authority
        self._ttl = challenge_ttl_s
        self._nonces: dict[str, float] = {}
        self._registry: dict[str, Entitlement] = {}
        self._lock = threading.Lock()

    def register_identity(self, public_hex: str, ent: Entitlement) -> str:
        _pt_from_hex(public_hex)  # validates curve membership
        with self._lock:
            self._registry[public_hex] = ent
        return pseudonym(public_hex)

    def issue_challenge(self) -> str:
        nonce = secrets.token_hex(16)
        now = time.time()
        with self._lock:
            self._nonces = {n: t for n, t in self._nonces.items() if t > now}  # opportunistic GC
            self._nonces[nonce] = now + self._ttl
        return nonce

    def context(self, nonce: str, scopes: list[str]) -> dict[str, Any]:
        """The exact context the client must bind into its proof."""
        return {"aud": self.authority.audience, "nonce": nonce, "scopes": sorted(scopes)}

    def verify_and_issue(self, public_hex: str, proof: SchnorrProof, nonce: str, requested_scopes: list[str]) -> str:
        with self._lock:  # single use: pop *before* verifying so failures also burn the nonce
            expiry = self._nonces.pop(nonce, 0.0)
            ent = self._registry.get(public_hex)
        if expiry < time.time():
            raise TokenError("unknown or expired challenge")
        if ent is None:
            raise TokenError("identity not registered")  # deny by default
        if not verify_proof(public_hex, proof, self.context(nonce, requested_scopes)):
            raise TokenError("invalid proof")
        if not set(requested_scopes) <= ent.scopes:
            raise TokenError("requested scopes exceed entitlement")
        principal = Principal(pseudonym(public_hex), frozenset(requested_scopes), ent.roles, ent.attrs)
        return self.authority.mint(principal)
