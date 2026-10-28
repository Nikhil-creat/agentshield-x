"""Provider-agnostic LLM client for the free tiers of **Groq** and **Google Gemini**, with automatic provider and model detection.

    client = LlmClient.from_env()                    # GROQ_API_KEY and/or GEMINI_API_KEY (or GOOGLE_API_KEY)
    result = client.chat([{"role": "user", "content": "hello"}])
    result.text, result.provider, result.model

Auto-detection
    provider   from the key's shape (``gsk_`` = Groq, ``AIza`` = Gemini) or from which env var is set
    model      the provider's live model list is fetched with the key, filtered to chat-capable models and ranked by a documented
               heuristic (:func:`rank_groq`, :func:`rank_gemini`); a rate-limited / retired model falls through to the next best

Security properties (all enforced in code and covered by tests)
    * endpoints are hard-coded HTTPS hosts - user input can never choose a URL (no SSRF), redirects are refused so the key cannot be
      forwarded to another host, TLS verification is never disabled
    * the key travels only in a header (never a URL), is masked in ``repr``/errors, and is scrubbed from any error text
    * request and response sizes are capped; timeouts are mandatory; auth failures stop immediately (no retry storm)
    * the transport is injectable, so tests never touch the network
"""

from __future__ import annotations

import json
import math
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Protocol, Sequence

GROQ_BASE = "https://api.groq.com/openai/v1"
GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta"
MAX_RESPONSE_BYTES = 2_000_000
MAX_PROMPT_CHARS = 60_000
DEFAULT_TIMEOUT_S = 30.0
MAX_FALLBACKS = 3


class LlmError(Exception):
    """Base error. Messages never contain the API key."""


class LlmAuthError(LlmError):
    """401/403: the key is invalid, revoked or lacks access. Never retried."""


class LlmRateLimit(LlmError):
    """429: free-tier quota exhausted for this model."""


class LlmUnavailable(LlmError):
    """Network failure, 5xx, bad response shape, or no usable model."""


# ---------------------------------------------------------------------------------------------- transport
class Transport(Protocol):
    def __call__(self, method: str, url: str, headers: Mapping[str, str], body: bytes | None, timeout: float) -> tuple[int, bytes]: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a: Any, **k: Any) -> None:  # refuse: the key must never follow a redirect to another host
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def urllib_transport(method: str, url: str, headers: Mapping[str, str], body: bytes | None, timeout: float) -> tuple[int, bytes]:
    if not url.startswith(("https://api.groq.com/", "https://generativelanguage.googleapis.com/")):
        raise LlmUnavailable("refusing to contact an unexpected host")  # defence in depth; URLs are built only from constants
    req = urllib.request.Request(url, data=body, headers=dict(headers), method=method)
    try:
        with _OPENER.open(req, timeout=timeout) as r:  # noqa: S310 - fixed https hosts checked above
            return r.status, r.read(MAX_RESPONSE_BYTES + 1)[:MAX_RESPONSE_BYTES]
    except urllib.error.HTTPError as e:
        return e.code, e.read(MAX_RESPONSE_BYTES + 1)[:MAX_RESPONSE_BYTES]
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise LlmUnavailable(f"network error: {type(e).__name__}") from None


# ---------------------------------------------------------------------------------------------- detection
def detect_provider(key: str) -> str | None:
    """'groq' for ``gsk_...``, 'gemini' for ``AIza...``, otherwise None."""
    k = key.strip()
    if k.startswith("gsk_"):
        return "groq"
    if k.startswith("AIza"):
        return "gemini"
    return None


def mask(key: str) -> str:
    return f"{key[:4]}…{key[-2:]}" if len(key) > 10 else "…"


# ---------------------------------------------------------------------------------------------- model ranking
_GROQ_EXCLUDE = re.compile(r"whisper|tts|playai|orpheus|guard|safeguard|embed|moderation|transcri|distil-whisper", re.I)
_GROQ_FAMILY = {"gpt-oss": 6, "llama": 5, "qwen": 4, "kimi": 4, "deepseek": 3, "mixtral": 2, "gemma": 1}


def _size_b(model_id: str) -> float | None:
    m = re.search(r"(\d+(?:\.\d+)?)b", model_id.lower())
    return float(m.group(1)) if m else None


def groq_score(model_id: str) -> float:
    mid = model_id.lower()
    size = _size_b(mid)
    s = math.log2(size) * 10 if size else 30.0
    s += 8 if ("versatile" in mid or "instruct" in mid) else 0
    s += 4 if "versatile" in mid else 0  # Groq's production-stable general models
    s -= 15 if "preview" in mid else 0
    s -= 20 if "specdec" in mid else 0
    s += next((w for fam, w in _GROQ_FAMILY.items() if fam in mid), 0)
    return s


def rank_groq(models: Sequence[Mapping[str, Any]]) -> list[str]:
    """Chat-capable Groq model ids, best first. Excludes speech/guard/embedding models and models flagged inactive."""
    ids = [str(m.get("id", "")) for m in models if m.get("id") and m.get("active", True) is not False and not _GROQ_EXCLUDE.search(str(m["id"]))]
    return sorted(set(ids), key=lambda i: (-groq_score(i), i))


_GEMINI_EXCLUDE = re.compile(r"embedding|imagen|veo|tts|aqa|learnlm|image|live|audio|robotics|computer-use|vision|\bexp\b|-exp-|gemma", re.I)


def gemini_score(name: str) -> float:
    n = name.lower()
    v = re.search(r"gemini-(\d+(?:\.\d+)?)", n)
    s = (float(v.group(1)) if v else 0.0) * 100
    if "flash-lite" in n:
        s += 20
    elif "flash" in n:
        s += 30  # free-tier quotas are far larger for flash than pro
    elif "pro" in n:
        s += 10
    s += 5 if n.endswith("-latest") else 0
    s -= 5 if re.search(r"-\d{3}$|-\d{2}-\d{2}$", n) else 0
    s -= 25 if "preview" in n else 0
    return s


def rank_gemini(models: Sequence[Mapping[str, Any]]) -> list[str]:
    """Gemini model ids (without the ``models/`` prefix) that support generateContent, best first for a free-tier key."""
    out = []
    for m in models:
        name = str(m.get("name", "")).removeprefix("models/")
        methods = m.get("supportedGenerationMethods") or []
        if name.startswith("gemini") and "generateContent" in methods and not _GEMINI_EXCLUDE.search(name):
            out.append(name)
    return sorted(set(out), key=lambda i: (-gemini_score(i), i))


# ---------------------------------------------------------------------------------------------- client
@dataclass
class ChatResult:
    text: str
    provider: str
    model: str
    usage: dict[str, int] = field(default_factory=dict)
    tried: list[str] = field(default_factory=list)


Message = Mapping[str, str]


class LlmClient:
    def __init__(self, key: str, provider: str | None = None, *, transport: Transport | None = None, timeout: float = DEFAULT_TIMEOUT_S) -> None:
        key = key.strip()
        self.provider = provider or detect_provider(key) or ""
        if self.provider not in ("groq", "gemini"):
            raise LlmError("could not tell which provider this key belongs to (expected a Groq 'gsk_' or a Gemini 'AIza' key)")
        if not re.fullmatch(r"[A-Za-z0-9_\-]{20,200}", key):
            raise LlmError("API key has an unexpected format")
        self._key = key
        self._t: Transport = transport or urllib_transport
        self.timeout = timeout
        self._ranked: list[str] | None = None

    def __repr__(self) -> str:
        return f"LlmClient(provider={self.provider!r}, key={mask(self._key)!r})"

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None, *, prefer: str | None = None, **kw: Any) -> "LlmClient":
        env = os.environ if env is None else env
        keys = {"groq": env.get("GROQ_API_KEY", ""), "gemini": env.get("GEMINI_API_KEY", "") or env.get("GOOGLE_API_KEY", "")}
        order = [prefer] if prefer in keys else []
        order += [p for p in ("groq", "gemini") if p not in order]
        for p in order:
            if keys[p].strip():
                return cls(keys[p], p, **kw)
        raise LlmError("no API key found: set GROQ_API_KEY or GEMINI_API_KEY")

    # -- plumbing
    def _scrub(self, text: str) -> str:
        return text.replace(self._key, "[key]")

    def _headers(self) -> dict[str, str]:
        if self.provider == "groq":
            return {"Authorization": f"Bearer {self._key}", "Content-Type": "application/json", "Accept": "application/json"}
        return {"x-goog-api-key": self._key, "Content-Type": "application/json", "Accept": "application/json"}

    def _call(self, method: str, url: str, payload: Any = None) -> Any:
        body = json.dumps(payload).encode() if payload is not None else None
        status, raw = self._t(method, url, self._headers(), body, self.timeout)
        if status in (401, 403):
            raise LlmAuthError(f"{self.provider} rejected the API key (HTTP {status})")
        if status == 429:
            raise LlmRateLimit(f"{self.provider} free-tier rate limit reached")
        if status >= 400:
            detail = ""
            try:
                detail = str(json.loads(raw).get("error", {}).get("message", ""))[:200]
            except (ValueError, AttributeError):
                pass
            err = LlmUnavailable(self._scrub(f"{self.provider} returned HTTP {status}: {detail}".strip()))
            err.status = status  # type: ignore[attr-defined]
            raise err
        try:
            return json.loads(raw)
        except ValueError:
            raise LlmUnavailable(f"{self.provider} returned a non-JSON response") from None

    # -- models
    def list_models(self) -> list[dict[str, Any]]:
        if self.provider == "groq":
            return list(self._call("GET", f"{GROQ_BASE}/models").get("data", []))
        return list(self._call("GET", f"{GEMINI_BASE}/models?pageSize=200").get("models", []))

    def ranked_models(self, refresh: bool = False) -> list[str]:
        if self._ranked is None or refresh:
            models = self.list_models()
            self._ranked = rank_groq(models) if self.provider == "groq" else rank_gemini(models)
        if not self._ranked:
            raise LlmUnavailable(f"no chat-capable {self.provider} model is available for this key")
        return self._ranked

    # -- chat
    def _chat_once(self, model: str, messages: Sequence[Message], max_tokens: int, temperature: float) -> tuple[str, dict[str, int]]:
        if self.provider == "groq":
            data = self._call("POST", f"{GROQ_BASE}/chat/completions", {"model": model, "messages": [dict(m) for m in messages],
                                                                       "max_tokens": max_tokens, "temperature": temperature})
            try:
                text = data["choices"][0]["message"]["content"] or ""
            except (KeyError, IndexError, TypeError):
                raise LlmUnavailable("unexpected Groq response shape") from None
            u = data.get("usage") or {}
            return text, {k: int(u.get(k, 0)) for k in ("prompt_tokens", "completion_tokens", "total_tokens")}
        system = "\n\n".join(m["content"] for m in messages if m["role"] == "system")
        contents = [{"role": "model" if m["role"] == "assistant" else "user", "parts": [{"text": m["content"]}]} for m in messages if m["role"] != "system"]
        payload: dict[str, Any] = {"contents": contents, "generationConfig": {"maxOutputTokens": max_tokens, "temperature": temperature}}
        if system:
            payload["systemInstruction"] = {"parts": [{"text": system}]}
        data = self._call("POST", f"{GEMINI_BASE}/models/{model}:generateContent", payload)
        try:
            parts = data["candidates"][0]["content"]["parts"]
            text = "".join(p.get("text", "") for p in parts)
        except (KeyError, IndexError, TypeError):
            reason = (data.get("promptFeedback") or {}).get("blockReason") or ((data.get("candidates") or [{}])[0].get("finishReason"))
            raise LlmUnavailable(f"Gemini returned no text ({reason or 'empty response'})") from None
        u = data.get("usageMetadata") or {}
        return text, {"prompt_tokens": int(u.get("promptTokenCount", 0)), "completion_tokens": int(u.get("candidatesTokenCount", 0)),
                      "total_tokens": int(u.get("totalTokenCount", 0))}

    def chat(self, messages: Sequence[Message], *, model: str | None = None, max_tokens: int = 700, temperature: float = 0.3) -> ChatResult:
        """Send a chat. With ``model=None`` the best available model is auto-selected and the next best is tried if it is rate-limited
        or retired. Auth errors stop immediately."""
        if not messages:
            raise LlmError("empty prompt")
        for m in messages:
            if not isinstance(m, dict) or m.get("role") not in ("system", "user", "assistant") or not isinstance(m.get("content"), str):
                raise LlmError("invalid message")
        if sum(len(m["content"]) for m in messages) > MAX_PROMPT_CHARS:
            raise LlmError("oversized prompt")
        max_tokens = max(1, min(int(max_tokens), 4096))
        candidates = [model] if model else self.ranked_models()[:MAX_FALLBACKS]
        tried: list[str] = []
        last: LlmError | None = None
        for mid in candidates:
            tried.append(mid)
            try:
                text, usage = self._chat_once(mid, messages, max_tokens, temperature)
                return ChatResult(text, self.provider, mid, usage, tried)
            except LlmAuthError:
                raise
            except LlmRateLimit as e:
                last = e
            except LlmUnavailable as e:
                if getattr(e, "status", 0) not in (400, 404, 410, 429, 503) and model:
                    raise
                last = e
            if model:
                break
        raise last or LlmUnavailable("no model could answer")


def autodetect_summary(client: LlmClient) -> dict[str, Any]:
    """What the UI/CLI shows after connecting: provider, ranked models, the one that will be used."""
    ranked = client.ranked_models()
    return {"provider": client.provider, "selected": ranked[0], "fallbacks": ranked[1:MAX_FALLBACKS], "available": len(ranked)}
