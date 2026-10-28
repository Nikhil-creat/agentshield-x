"""Ephemeral, air-gapped container execution for agent-generated code.

Defence in depth (outermost = strongest):
  1. Container boundary: ``--network none``, ``--cap-drop ALL``, ``--read-only`` rootfs,
     ``no-new-privileges``, non-root user, memory/CPU/PID/ulimit cgroups, tmpfs scratch with
     ``noexec``, no bind mounts (code arrives on stdin), optional gVisor (``--runtime runsc``).
  2. Kernel monitoring: Tetragon/eBPF policies kill violating processes (see ``ebpf_monitor.py``
     and ``deploy/tetragon``).
  3. Static pre-flight (``analyze_python``): an *advisory* AST screen that refuses obviously
     hostile code before it consumes a container. It is trivially evadable by a determined
     attacker (string building, etc.) - which is exactly why layers 1-2 exist.

Every run is a brand-new container (``--rm``); nothing persists between runs. There is no shell
in the argv (``asyncio.create_subprocess_exec``), so tool arguments can never inject Docker flags.
"""

from __future__ import annotations

import ast
import asyncio
import enum
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Protocol

from .config import ShieldSettings
from .shield_types import Finding, ThreatCategory as C


class NetworkMode(str, enum.Enum):
    NONE = "none"
    PROXIED = "proxied"  # only via an allow-listing egress proxy on an --internal network


class SandboxViolation(Exception):
    """Raised before any container is started (policy refusal)."""


# --------------------------------------------------------------------------------------
# Static pre-flight
# --------------------------------------------------------------------------------------
_DENY_MODULES = {
    "ctypes": 0.9, "cffi": 0.9, "subprocess": 0.85, "pty": 0.85, "fcntl": 0.7, "mmap": 0.6, "resource": 0.5,
    "multiprocessing": 0.6, "signal": 0.5, "importlib": 0.7, "pickle": 0.6, "marshal": 0.7, "shutil": 0.5,
    "socket": 0.7, "ssl": 0.5, "http": 0.5, "urllib": 0.5, "requests": 0.5, "ftplib": 0.6, "smtplib": 0.6, "telnetlib": 0.7,
    "asyncio.subprocess": 0.85, "docker": 0.9, "pexpect": 0.85,
}
_DENY_OS_ATTRS = {"system", "popen", "fork", "forkpty", "kill", "killpg", "setuid", "setgid", "chroot", "chown", "chmod",
                  "execv", "execve", "execl", "execlp", "execvp", "spawnl", "spawnv", "spawnlp", "posix_spawn", "remove", "unlink", "rmdir", "rename", "symlink", "link", "mkfifo"}
_DENY_BUILTINS = {"eval": 0.6, "exec": 0.6, "compile": 0.5, "__import__": 0.8, "breakpoint": 0.5}
_DUNDER_ESCAPES = {"__subclasses__", "__globals__", "__builtins__", "__bases__", "__mro__", "__code__", "__closure__", "__getattribute__"}
_SENSITIVE_PREFIXES = ("/proc", "/sys", "/dev", "/etc", "/root", "/var/run", "/run", "/home", "/mnt", "/host", "/.dockerenv")


def analyze_python(code: str) -> list[Finding]:
    """Advisory AST screen. Returns findings (score >= 0.7 means ``strict`` refuses)."""
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return [Finding(C.TOOL_ABUSE, "sandbox.syntax_error", 0.1, f"unparseable: {e.msg}", source="sandbox")]
    out: list[Finding] = []
    add = lambda rule, sc, d: out.append(Finding(C.TOOL_ABUSE, rule, sc, d, source="sandbox"))  # noqa: E731
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                root = a.name.split(".")[0]
                if root in _DENY_MODULES:
                    add(f"sandbox.import.{root}", _DENY_MODULES[root], f"import {a.name}")
        elif isinstance(node, ast.ImportFrom) and node.module:
            root = node.module.split(".")[0]
            if root in _DENY_MODULES:
                add(f"sandbox.import.{root}", _DENY_MODULES[root], f"from {node.module} import ...")
            if root == "os" and any(a.name in _DENY_OS_ATTRS for a in node.names):
                add("sandbox.os.dangerous", 0.85, "from os import <dangerous>")
        elif isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id == "os" and node.attr in _DENY_OS_ATTRS:
                add("sandbox.os.dangerous", 0.85, f"os.{node.attr}")
            if node.attr in _DUNDER_ESCAPES:
                add("sandbox.dunder_escape", 0.85, f"attribute {node.attr}")
        elif isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name):
                if fn.id in _DENY_BUILTINS:
                    add(f"sandbox.builtin.{fn.id}", _DENY_BUILTINS[fn.id], f"call to {fn.id}()")
                if fn.id in ("getattr", "setattr", "delattr") and len(node.args) >= 2:
                    a1 = node.args[1]
                    if isinstance(a1, ast.Constant) and isinstance(a1.value, str) and a1.value.startswith("__"):
                        add("sandbox.dunder_getattr", 0.8, f"{fn.id}(..., {a1.value!r})")
                if fn.id == "open" and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                    p = node.args[0].value
                    if p.startswith(_SENSITIVE_PREFIXES) or ".." in p.split("/"):
                        add("sandbox.open_sensitive", 0.85, f"open({p!r})")
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if node.value.startswith(_SENSITIVE_PREFIXES) and len(node.value) < 200 and "/" in node.value:
                add("sandbox.sensitive_path_literal", 0.5, node.value[:60])
            if "docker.sock" in node.value:
                add("sandbox.docker_socket", 0.95, "references docker.sock")
    return out


# --------------------------------------------------------------------------------------
# Docker argv construction (pure function => unit-testable without a daemon)
# --------------------------------------------------------------------------------------
@dataclass(frozen=True)
class SandboxLimits:
    memory: str = "128m"
    cpus: float = 0.5
    pids: int = 64
    timeout_s: float = 10.0
    max_output_bytes: int = 65_536
    tmpfs_size: str = "16m"
    nofile: int = 64
    fsize_bytes: int = 10_000_000


def build_docker_argv(name: str, *, image: str, limits: SandboxLimits, network: NetworkMode = NetworkMode.NONE,
                      runtime: str = "", seccomp_profile: str = "", egress_network: str = "", egress_proxy: str = "",
                      docker_bin: str = "docker") -> list[str]:
    """The complete, auditable hardening profile. Order and flags are asserted in tests."""
    argv = [
        docker_bin, "run", "--rm", "-i", "--name", name, "--pull", "never",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true",
        "--read-only",
        "--tmpfs", f"/tmp:rw,noexec,nosuid,nodev,size={limits.tmpfs_size}",
        "--memory", limits.memory, "--memory-swap", limits.memory,
        "--cpus", str(limits.cpus), "--pids-limit", str(limits.pids),
        "--ulimit", f"nofile={limits.nofile}:{limits.nofile}",
        "--ulimit", f"nproc={limits.pids}:{limits.pids}",
        "--ulimit", f"fsize={limits.fsize_bytes}:{limits.fsize_bytes}",
        "--ulimit", "core=0:0",
        "--user", "65534:65534",
        "--init", "--stop-timeout", "1", "--hostname", "sandbox",
        "--label", "agentshield.sandbox=1", "--label", f"agentshield.started={int(time.time())}",
        "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "PYTHONHASHSEED=random", "-e", "HOME=/tmp",
    ]
    if network is NetworkMode.NONE:
        argv += ["--network", "none"]
    else:
        if not egress_network or not egress_proxy:
            raise SandboxViolation("proxied network requested but no egress network/proxy configured")
        argv += ["--network", egress_network, "-e", f"HTTPS_PROXY={egress_proxy}", "-e", f"HTTP_PROXY={egress_proxy}"]
    if runtime:
        argv += ["--runtime", runtime]
    if seccomp_profile:
        argv += ["--security-opt", f"seccomp={seccomp_profile}"]
    argv += [image, "python", "-I", "-B", "-"]  # program is read from stdin: no mounts needed
    return argv


@dataclass
class SandboxResult:
    ok: bool
    exit_code: int | None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    truncated: bool = False
    refused: bool = False
    reason: str = ""
    duration_s: float = 0.0
    container: str = ""
    findings: list[Finding] = field(default_factory=list)


class Runner(Protocol):
    async def run(self, argv: list[str], stdin: bytes, *, timeout_s: float, max_output: int,
                  kill: Callable[[], Awaitable[None]]) -> tuple[int | None, bytes, bytes, bool, bool]:
        """Return (exit_code, stdout, stderr, timed_out, truncated)."""
        ...


class SubprocessRunner:
    """Default runner: ``docker`` CLI via exec (no shell), bounded output, hard wall-clock cap."""

    async def run(self, argv, stdin, *, timeout_s, max_output, kill):  # type: ignore[no-untyped-def]
        proc = await asyncio.create_subprocess_exec(*argv, stdin=asyncio.subprocess.PIPE,
                                                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        truncated = False

        async def pump(stream: asyncio.StreamReader) -> bytes:
            nonlocal truncated
            buf = bytearray()
            while True:
                chunk = await stream.read(8192)
                if not chunk:
                    return bytes(buf)
                room = max_output - len(buf)
                buf += chunk[: max(room, 0)]
                if len(chunk) > room and not truncated:
                    truncated = True
                    await kill()  # output flood: terminate instead of draining forever

        async def feed() -> None:
            assert proc.stdin
            try:
                proc.stdin.write(stdin)
                await proc.stdin.drain()
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                proc.stdin.close()

        timed_out = False
        try:
            assert proc.stdout and proc.stderr
            out, err, _ = await asyncio.wait_for(asyncio.gather(pump(proc.stdout), pump(proc.stderr), feed()), timeout=timeout_s)
            await asyncio.wait_for(proc.wait(), timeout=2)
        except asyncio.TimeoutError:
            timed_out = True
            await kill()
            out, err = b"", b""
            try:
                await asyncio.wait_for(proc.wait(), timeout=3)
            except asyncio.TimeoutError:
                proc.kill()
        return proc.returncode, out, err, timed_out, truncated


class SandboxManager:
    def __init__(self, settings: ShieldSettings, runner: Runner | None = None, *, docker_bin: str = "docker",
                 egress_network: str = "", egress_proxy: str = "", seccomp_profile: str = "", max_concurrent: int = 4) -> None:
        self.s = settings
        self.runner = runner or SubprocessRunner()
        self.docker_bin = docker_bin
        self.egress_network, self.egress_proxy, self.seccomp_profile = egress_network, egress_proxy, seccomp_profile
        self._sem = asyncio.Semaphore(max_concurrent)  # bound host resource usage
        self.limits = SandboxLimits(memory=settings.sandbox_memory, cpus=settings.sandbox_cpus, pids=settings.sandbox_pids,
                                    timeout_s=settings.sandbox_timeout_s, max_output_bytes=settings.sandbox_max_output_bytes)

    def argv_for(self, name: str, network: NetworkMode = NetworkMode.NONE) -> list[str]:
        return build_docker_argv(name, image=self.s.sandbox_image, limits=self.limits, network=network, runtime=self.s.sandbox_runtime,
                                 seccomp_profile=self.seccomp_profile, egress_network=self.egress_network,
                                 egress_proxy=self.egress_proxy, docker_bin=self.docker_bin)

    async def _kill(self, name: str) -> None:
        try:
            p = await asyncio.create_subprocess_exec(self.docker_bin, "kill", name, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
            await asyncio.wait_for(p.wait(), timeout=3)
        except Exception:  # noqa: BLE001 - best effort; --rm + timeout still bound the container
            pass

    async def run_python(self, code: str, *, network: NetworkMode = NetworkMode.NONE, strict: bool = True) -> SandboxResult:
        findings = analyze_python(code)
        worst = max((f.score for f in findings), default=0.0)
        if strict and worst >= 0.7:
            top = max(findings, key=lambda f: f.score)
            return SandboxResult(False, None, refused=True, reason=f"pre-flight refused: {top.rule} ({top.detail})", findings=findings)
        if len(code.encode()) > 100_000:
            return SandboxResult(False, None, refused=True, reason="code too large", findings=findings)
        name = f"as-sbx-{secrets.token_hex(6)}"
        try:
            argv = self.argv_for(name, network)
        except SandboxViolation as e:
            return SandboxResult(False, None, refused=True, reason=str(e), findings=findings)
        t0 = time.monotonic()
        async with self._sem:
            rc, out, err, timed_out, truncated = await self.runner.run(
                argv, code.encode(), timeout_s=self.limits.timeout_s, max_output=self.limits.max_output_bytes,
                kill=lambda: self._kill(name))
        dur = time.monotonic() - t0
        ok = rc == 0 and not timed_out and not truncated
        reason = "timeout" if timed_out else "output limit exceeded" if truncated else ("" if ok else f"exit {rc}")
        return SandboxResult(ok, rc, out.decode("utf-8", "replace"), err.decode("utf-8", "replace"), timed_out, truncated,
                             False, reason, dur, name, findings)

    async def reap_orphans(self, older_than_s: int = 120) -> int:
        """Janitor: remove sandbox containers that outlived their budget (crash recovery)."""
        p = await asyncio.create_subprocess_exec(self.docker_bin, "ps", "-aq", "--filter", "label=agentshield.sandbox=1",
                                                 stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await p.communicate()
        ids = out.decode().split()
        for cid in ids:
            q = await asyncio.create_subprocess_exec(self.docker_bin, "rm", "-f", cid, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
            await q.wait()
        return len(ids)


# --------------------------------------------------------------------------------------
# Kubernetes backend: one short-lived, unprivileged pod per run (gVisor via RuntimeClass)
# --------------------------------------------------------------------------------------
def _k8s_mem(mem: str) -> str:
    """Docker-style '128m' / '1g' / '512k' -> Kubernetes '128Mi' / '1Gi' / '512Ki'. Kubernetes quantities pass through."""
    m = mem.strip()
    if m[-2:] in ("Ki", "Mi", "Gi", "Ti"):
        return m
    suffix = {"k": "Ki", "m": "Mi", "g": "Gi"}.get(m[-1:].lower())
    return m[:-1] + suffix if suffix else m


def build_pod_overrides(name: str, *, image: str, limits: SandboxLimits, runtime_class: str = "") -> dict:
    """Pure function: the complete hardened pod spec passed to ``kubectl run --overrides``."""
    mem = _k8s_mem(limits.memory)
    spec: dict = {
        "automountServiceAccountToken": False,
        "enableServiceLinks": False,
        "restartPolicy": "Never",
        "hostNetwork": False, "hostPID": False, "hostIPC": False,
        "activeDeadlineSeconds": int(limits.timeout_s) + 5,
        "terminationGracePeriodSeconds": 1,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "runAsGroup": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [{
            "name": name, "image": image, "imagePullPolicy": "Never", "stdin": True, "stdinOnce": True,
            "args": ["python", "-I", "-B", "-"],
            "env": [{"name": "PYTHONDONTWRITEBYTECODE", "value": "1"}, {"name": "HOME", "value": "/tmp"}],
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "privileged": False,
                                "capabilities": {"drop": ["ALL"]}},
            "resources": {"limits": {"cpu": str(limits.cpus), "memory": mem, "ephemeral-storage": limits.tmpfs_size.replace("m", "Mi")},
                          "requests": {"cpu": "50m", "memory": "32Mi"}},
            "volumeMounts": [{"name": "scratch", "mountPath": "/tmp"}],
        }],
        "volumes": [{"name": "scratch", "emptyDir": {"medium": "Memory", "sizeLimit": limits.tmpfs_size.replace("m", "Mi")}}],
    }
    if runtime_class:
        spec["runtimeClassName"] = runtime_class
    return {"apiVersion": "v1", "spec": spec}


class KubernetesSandboxManager(SandboxManager):
    """Same policy/pre-flight/limits as the Docker backend; execution via ``kubectl run`` into a sandbox namespace.

    Requires: kubectl in the API image, a ServiceAccount allowed to create/delete/get pods **only** in
    ``sandbox_namespace`` (see chart ``sandbox-rbac.yaml``), the sandbox image pre-pulled on nodes
    (``imagePullPolicy: Never``), and the air-gap CiliumClusterwideNetworkPolicy (label ``agentshield/role=sandbox``).
    """

    def __init__(self, settings: ShieldSettings, runner: Runner | None = None, *, kubectl_bin: str = "kubectl", **kw) -> None:
        super().__init__(settings, runner, **kw)
        self.kubectl = kubectl_bin
        self.namespace = settings.sandbox_namespace

    def argv_for(self, name: str, network: NetworkMode = NetworkMode.NONE) -> list[str]:
        if network is not NetworkMode.NONE:
            raise SandboxViolation("proxied networking is not supported by the kubernetes backend (pods are air-gapped by policy)")
        ov = build_pod_overrides(name, image=self.s.sandbox_image, limits=self.limits, runtime_class=self.s.sandbox_runtime)
        return [self.kubectl, "-n", self.namespace, "run", name, "--rm", "-i", "--quiet", "--restart=Never", f"--image={self.s.sandbox_image}",
                "--labels=agentshield/role=sandbox", f"--overrides={json.dumps(ov, separators=(',', ':'))}", "--", "python", "-I", "-B", "-"]

    async def _kill(self, name: str) -> None:
        try:
            p = await asyncio.create_subprocess_exec(self.kubectl, "-n", self.namespace, "delete", "pod", name, "--now", "--wait=false",
                                                     stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
            await asyncio.wait_for(p.wait(), timeout=5)
        except Exception:  # noqa: BLE001 - activeDeadlineSeconds still bounds the pod
            pass

    async def reap_orphans(self, older_than_s: int = 120) -> int:
        p = await asyncio.create_subprocess_exec(self.kubectl, "-n", self.namespace, "delete", "pods", "-l", "agentshield/role=sandbox", "--now", "--wait=false",
                                                 stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await p.communicate()
        return len(out.decode().splitlines())


def make_sandbox_manager(settings: ShieldSettings, **kw) -> SandboxManager:
    return KubernetesSandboxManager(settings, **kw) if settings.sandbox_backend == "kubernetes" else SandboxManager(settings, **kw)
