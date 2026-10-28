"""``agentshield`` command line.

    agentshield scan-text "ignore all previous instructions ..."      # or:  echo ... | agentshield scan-text -
    agentshield scan-image photo.png [--out clean.png]
    agentshield verify-ledger audit.jsonl [--anchors anchors.jsonl --ed25519-pub ed.pem [--mldsa-pub pq.pem]]
    agentshield policy-validate policies/
    agentshield redteam [--seed 1337]
    agentshield aibom > aibom.cdx.json
    agentshield keygen --out ./keys            # writes 0600 key files; never prints secrets
    agentshield serve [--host 127.0.0.1 --port 8080]
    agentshield chat [--provider groq|gemini]            # guarded docs assistant; key from GROQ_API_KEY / GEMINI_API_KEY
    agentshield mcp-proxy --subject alice --scope tools.search -- npx some-mcp-server

Exit status: 0 = ok/allowed, 1 = blocked / verification failed / red-team below threshold, 2 = usage or input error.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets
import sys
from pathlib import Path
from typing import Any

from . import __version__


def _pipeline():
    from .config import ShieldSettings
    from .pipeline import ShieldPipeline
    return ShieldPipeline(ShieldSettings.from_env())


def _dump(obj: Any) -> None:
    json.dump(obj, sys.stdout, indent=2, sort_keys=True, default=str)
    sys.stdout.write("\n")


def cmd_scan_text(a: argparse.Namespace) -> int:
    from .shield_types import TrustLevel, Verdict
    text = sys.stdin.read() if a.text == "-" else a.text
    r = _pipeline().check_input(text, trust=TrustLevel.UNTRUSTED if a.untrusted else TrustLevel.USER, multi_turn=False, audit=False)
    _dump({**r.as_dict(), "safe_text": r.text})
    return 1 if r.verdict is Verdict.BLOCK else 0


def cmd_scan_image(a: argparse.Namespace) -> int:
    from .shield_types import Verdict
    data = Path(a.path).read_bytes()
    rep = asyncio.run(_pipeline().check_image(data))
    if a.out and rep.sanitized_png is not None and rep.verdict is not Verdict.BLOCK:
        Path(a.out).write_bytes(rep.sanitized_png)
    _dump(rep.as_dict())
    return 1 if rep.verdict is Verdict.BLOCK else 0


def _load_pub(path: str):
    from cryptography.hazmat.primitives import serialization
    return serialization.load_pem_public_key(Path(path).read_bytes())


def cmd_verify_ledger(a: argparse.Namespace) -> int:
    from .audit_merkle_ledger import load_jsonl, verify_entries
    entries = load_jsonl(a.path)
    ok, why = verify_entries(entries)
    print(f"ledger: {'OK' if ok else 'FAILED'} - {why} ({len(entries)} entries)")
    if not ok:
        return 1
    if a.anchors:
        from .anchor import verify_anchors
        if not a.ed25519_pub:
            print("--anchors needs --ed25519-pub", file=sys.stderr)
            return 2
        ok2, why2 = verify_anchors(a.anchors, _load_pub(a.ed25519_pub), pq_public=_load_pub(a.mldsa_pub) if a.mldsa_pub else None, entries=entries)
        print(f"anchors: {'OK' if ok2 else 'FAILED'} - {why2}")
        return 0 if ok2 else 1
    return 0


def cmd_policy_validate(a: argparse.Namespace) -> int:
    from .policy_loader import PolicyError, load_policy_dir
    try:
        reg, rules = load_policy_dir(a.dir)
    except (PolicyError, OSError, ValueError) as e:
        print(f"INVALID: {e}", file=sys.stderr)
        return 1
    print(f"OK: {len(reg.names())} tools, {len(rules)} ABAC rules")
    return 0


def cmd_redteam(a: argparse.Namespace) -> int:
    from .redteam import run_redteam
    rep = run_redteam(_pipeline(), seed=a.seed, per_case=a.per_case)
    print(rep.summary())
    return 0 if rep.passes(a.min_detection, a.max_fp) else 1


def cmd_aibom(a: argparse.Namespace) -> int:
    from .ai_bom import AIBOM
    from .policy_engine import default_registry
    bom = AIBOM()
    bom.add_tools(default_registry())
    bom.add_python_dependencies()
    _dump(bom.snapshot())
    return 0


def cmd_keygen(a: argparse.Namespace) -> int:
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    made: list[str] = []

    def write(name: str, data: bytes, mode: int = 0o600) -> None:
        p = out / name
        if p.exists() and not a.force:
            raise FileExistsError(f"{p} exists (use --force to overwrite)")
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        made.append(str(p))

    nopw = ser.NoEncryption()
    try:
        ed = ed25519.Ed25519PrivateKey.generate()
        write("ledger_ed25519.key.pem", ed.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, nopw))
        write("ledger_ed25519.pub.pem", ed.public_key().public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo), 0o644)
        pq = mldsa.MLDSA65PrivateKey.generate()
        write("ledger_mldsa65.key.pem", pq.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, nopw))
        write("ledger_mldsa65.pub.pem", pq.public_key().public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo), 0o644)
        write("approval_key.hex", secrets.token_hex(32).encode() + b"\n")
        write("api_key_pepper.hex", secrets.token_hex(32).encode() + b"\n")
    except FileExistsError as e:
        print(e, file=sys.stderr)
        return 2
    print("wrote (private files are mode 0600; keep them out of git):")
    for m in made:
        print("  ", m)
    return 0


def cmd_serve(a: argparse.Namespace) -> int:
    try:
        import uvicorn
    except ImportError:
        print("uvicorn is not installed: pip install 'uvicorn[standard]' fastapi", file=sys.stderr)
        return 2
    uvicorn.run("agentshield.app:app", host=a.host, port=a.port, log_level="info", proxy_headers=False, server_header=False)
    return 0


def cmd_chat(a: argparse.Namespace) -> int:
    from .assistant import DocIndex, GuardedAssistant
    from .llm import LlmClient, LlmError, autodetect_summary
    try:
        client = LlmClient.from_env(os.environ, prefer=a.provider)
        info = autodetect_summary(client)
    except LlmError as e:
        print(f"error: {e}\nset GROQ_API_KEY (free: console.groq.com) or GEMINI_API_KEY (free: aistudio.google.com)", file=sys.stderr)
        return 2
    root = Path(a.docs).resolve() if a.docs else Path(__file__).resolve().parent.parent
    index = DocIndex.from_project(root)
    if not index.chunks:
        print(f"error: no docs found under {root} (use --docs DIR)", file=sys.stderr)
        return 2
    bot = GuardedAssistant(_pipeline(), client, index)
    print(f"AgentShield-X assistant | {info['provider']} | auto-selected model: {info['selected']} ({info['available']} chat models found)")
    print("type a question, /reset to clear, /quit to exit")
    while True:
        try:
            q = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if q in ("/quit", "/exit"):
            return 0
        if q == "/reset":
            bot.reset("cli")
            continue
        if q:
            r = bot.ask(q, session_id="cli")
            print(r.text + (f"\n  [{r.model}; sources: {', '.join(r.sources)}]" if r.status == "ok" else ""))


def cmd_mcp_proxy(a: argparse.Namespace) -> int:
    from .config import ShieldSettings
    from .mcp_guard import McpGuard, PinStore, run_stdio_proxy
    from .pipeline import ShieldPipeline
    from .zk_identity import Principal
    if not a.server_cmd:
        print("give the MCP server command after --", file=sys.stderr)
        return 2
    cmd = a.server_cmd[1:] if a.server_cmd[0] == "--" else a.server_cmd
    pins = PinStore.loads(Path(a.pins).read_text()) if a.pins and Path(a.pins).exists() else PinStore()
    p = ShieldPipeline(ShieldSettings.from_env())
    guard = McpGuard(p, Principal(a.subject, frozenset(a.scope), frozenset(a.role), {"clearance": a.clearance}), wait_for_approval=False,
                     strict_metadata=not a.lenient)

    async def main() -> int:
        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader(limit=4_000_000)
        await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin)
        try:
            return await run_stdio_proxy(guard, cmd, client_in=reader)
        finally:
            if a.pins:
                Path(a.pins).write_text(guard.pins.dumps())
    return asyncio.run(main())


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="agentshield", description="AgentShield-X zero-trust guard for LLM / RAG / agent systems")
    ap.add_argument("--version", action="version", version=f"agentshield-x {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan-text", help="scan text; prints verdict + the safe version")
    s.add_argument("text", help="text to scan, or - for stdin")
    s.add_argument("--untrusted", action="store_true", help="treat as third-party content (retrieved doc / tool output)")
    s.set_defaults(fn=cmd_scan_text)

    s = sub.add_parser("scan-image", help="OCR/stego/QR scan an image")
    s.add_argument("path")
    s.add_argument("--out", help="write the purified PNG here (only when not blocked)")
    s.set_defaults(fn=cmd_scan_image)

    s = sub.add_parser("verify-ledger", help="verify a JSONL audit ledger (and optionally external anchors)")
    s.add_argument("path")
    s.add_argument("--anchors")
    s.add_argument("--ed25519-pub")
    s.add_argument("--mldsa-pub")
    s.set_defaults(fn=cmd_verify_ledger)

    s = sub.add_parser("policy-validate", help="strictly validate policies/tools.yaml + abac.yaml (use in CI)")
    s.add_argument("dir", nargs="?", default="policies")
    s.set_defaults(fn=cmd_policy_validate)

    s = sub.add_parser("redteam", help="run the seeded mutation red-team suite")
    s.add_argument("--seed", type=int, default=1337)
    s.add_argument("--per-case", type=int, default=2)
    s.add_argument("--min-detection", type=float, default=0.95)
    s.add_argument("--max-fp", type=float, default=0.05)
    s.set_defaults(fn=cmd_redteam)

    s = sub.add_parser("aibom", help="emit a CycloneDX 1.6 AI-BOM")
    s.set_defaults(fn=cmd_aibom)

    s = sub.add_parser("keygen", help="generate ledger signing keys (Ed25519 + ML-DSA-65) and shared secrets")
    s.add_argument("--out", default="./keys")
    s.add_argument("--force", action="store_true")
    s.set_defaults(fn=cmd_keygen)

    s = sub.add_parser("serve", help="run the HTTP API + console (needs fastapi, uvicorn)")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8080)
    s.set_defaults(fn=cmd_serve)

    s = sub.add_parser("chat", help="guarded docs assistant using your own free Groq/Gemini key (model auto-detected)")
    s.add_argument("--provider", choices=["groq", "gemini"])
    s.add_argument("--docs", help="project root containing README.md and docs/")
    s.set_defaults(fn=cmd_chat)

    s = sub.add_parser("mcp-proxy", help="stdio policy proxy in front of an MCP server")
    s.add_argument("--subject", default="mcp-client")
    s.add_argument("--scope", action="append", default=[], help="capability granted to the agent (repeatable)")
    s.add_argument("--role", action="append", default=[])
    s.add_argument("--clearance", type=int, default=1)
    s.add_argument("--pins", help="file to load/save tool pins (rug-pull detection across runs)")
    s.add_argument("--lenient", action="store_true", help="heal poisoned tool metadata instead of dropping the tool")
    s.add_argument("server_cmd", nargs=argparse.REMAINDER)
    s.set_defaults(fn=cmd_mcp_proxy)
    return ap


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    try:
        return int(a.fn(a))
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
