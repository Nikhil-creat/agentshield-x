#!/usr/bin/env python3
"""Build the clean release archive: dist/agentshield-x-<version>.zip (+ .sha256).

Builds from a staging copy, never from the working tree in place. Excludes secrets, caches, generated files and anything not
part of the project. Refuses to produce an archive if the secret scan finds anything. Deterministic (sorted, fixed mtimes).
"""
from __future__ import annotations

import fnmatch
import hashlib
import re
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from agentshield import __version__  # noqa: E402

EXCLUDE_DIRS = {"secrets", "keys", "__pycache__", ".git", ".venv", "venv", "dist", "build", ".mypy_cache", ".ruff_cache", ".pytest_cache",
                "node_modules", "_site", "k8s", "preserved_shieldengine_api"}
EXCLUDE_PATHS = {"Dockerfile", "Dockerfile.sandbox", "requirements-dev.txt", "deploy/opa", "deploy/egress", "deploy/postgres"}
EXCLUDE_GLOBS = ["*.pyc", "*.pyo", ".env", ".env.*", "*.key", "*.key.pem", "approval_key*", "api_key_pepper*", "*.onnx", "*.zip", "*.sqlite",
                 "audit*.jsonl", "anchors*.jsonl", "*.egg-info"]
KEEP = {".env.example"}
SECRET_PATTERNS = {
    "private key block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"),
    "github token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "slack token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "openai/anthropic style key": re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_-]{32,}\b"),
    "aws secret access key": re.compile(r"aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}"),
    "long hex secret assignment": re.compile(r"(?i)(?:secret|password|token|key)\w*\s*[=:]\s*['\"]?[0-9a-f]{48,}\b"),
}
# Documented example values that appear on purpose in tests/docs (split so this file does not match itself)
ALLOWED = {"AKIA" + "IOSFODNN7EXAMPLE"}


def excluded(rel: Path) -> bool:
    if rel.as_posix() in KEEP:
        return False
    parts = rel.parts
    if any(p in EXCLUDE_DIRS for p in parts[:-1]) or (rel.is_dir() and parts[-1] in EXCLUDE_DIRS):
        return True
    posix = rel.as_posix()
    if posix in EXCLUDE_PATHS or any(posix.startswith(p + "/") for p in EXCLUDE_PATHS):
        return True
    return any(fnmatch.fnmatch(parts[-1], g) for g in EXCLUDE_GLOBS)


def stage(dst: Path) -> list[Path]:
    files = []
    for p in sorted(ROOT.rglob("*")):
        rel = p.relative_to(ROOT)
        if p.is_dir() or excluded(rel) or any(excluded(Path(*rel.parts[: i + 1])) for i in range(len(rel.parts) - 1)):
            continue
        out = dst / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(p, out)
        files.append(rel)
    return files


def scan(dst: Path, files: list[Path]) -> list[str]:
    hits = []
    for rel in files:
        try:
            text = (dst / rel).read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for name, rx in SECRET_PATTERNS.items():
            for m in rx.finditer(text):
                if m.group(0) not in ALLOWED and "CHANGE_ME" not in m.group(0):
                    hits.append(f"{rel}: {name}")
    return hits


def main() -> int:
    name = f"agentshield-x-{__version__}"
    out_dir = ROOT / "dist"
    out_dir.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        dst = Path(tmp) / name
        dst.mkdir()
        files = stage(dst)
        hits = scan(dst, files)
        if hits:
            print("REFUSING to build: secret scan hits:\n  " + "\n  ".join(hits), file=sys.stderr)
            return 1
        z = out_dir / f"{name}.zip"
        with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            for rel in files:
                info = zipfile.ZipInfo(f"{name}/{rel.as_posix()}", date_time=(2026, 1, 1, 0, 0, 0))
                info.external_attr = ((0o755 if (dst / rel).stat().st_mode & 0o111 else 0o644) << 16)
                info.compress_type = zipfile.ZIP_DEFLATED
                zf.writestr(info, (dst / rel).read_bytes())
    digest = hashlib.sha256(z.read_bytes()).hexdigest()
    (out_dir / f"{name}.zip.sha256").write_text(f"{digest}  {z.name}\n")
    print(f"{z}  ({len(files)} files, {z.stat().st_size // 1024} KiB)\nsha256 {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
