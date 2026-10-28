"""Kernel-level syscall monitoring for sandboxes.

Two cooperating mechanisms:

1. **In-kernel enforcement (preferred):** Tetragon ``TracingPolicy`` objects
   (``deploy/tetragon/sandbox-tracing-policy.yaml``) attach kprobes and use the ``Sigkill``
   action, so a violating process dies *inside the kernel* before the syscall returns.
2. **User-space decision + response (this module):** consumes Tetragon (or bpftrace) JSON
   events, evaluates them against :class:`SyscallPolicy`, writes a ledger entry and kills the
   container. Used for Docker-host deployments and for audit; also the unit-testable core.

Event field names differ between Tetragon versions. ``parse_tetragon_event`` is tolerant, but
verify it against ``tetra getevents -o json`` output for the version you deploy.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Awaitable, Callable

# Deny-by-default for anything that can escape, escalate, or change kernel state.
DENIED_SYSCALLS = frozenset({
    "ptrace", "process_vm_readv", "process_vm_writev", "mount", "umount2", "pivot_root", "chroot", "unshare", "setns",
    "init_module", "finit_module", "delete_module", "kexec_load", "kexec_file_load", "bpf", "perf_event_open", "userfaultfd",
    "keyctl", "add_key", "request_key", "reboot", "swapon", "swapoff", "setuid", "setgid", "setreuid", "setregid",
    "setresuid", "setresgid", "capset", "personality", "open_by_handle_at", "name_to_handle_at", "acct", "iopl", "ioperm",
    "mknod", "mknodat", "settimeofday", "clock_settime", "sethostname", "setdomainname", "move_pages", "io_uring_setup",
})
NETWORK_SYSCALLS = frozenset({"socket", "bind", "listen", "accept", "accept4", "connect", "sendto", "sendmsg", "recvfrom"})
FS_MUTATING = frozenset({"unlink", "unlinkat", "rename", "renameat", "renameat2", "rmdir", "mkdir", "mkdirat", "chmod", "fchmodat",
                         "chown", "fchownat", "symlink", "symlinkat", "link", "linkat", "truncate", "setxattr"})
SAFE_WRITE_PREFIXES = ("/tmp/",)
O_WRONLY, O_RDWR, O_CREAT, O_TRUNC = 0o1, 0o2, 0o100, 0o1000
AF_UNIX, AF_INET, AF_INET6 = 1, 2, 10


@dataclass(frozen=True)
class SyscallEvent:
    container: str
    pid: int
    syscall: str
    args: dict[str, Any] = field(default_factory=dict)
    binary: str = ""


@dataclass(frozen=True)
class Violation:
    container: str
    pid: int
    syscall: str
    rule: str
    detail: str


class SyscallPolicy:
    """Stateful per-container evaluator. ``allow_network`` is False unless the sandbox is proxied."""

    def __init__(self, allow_network: bool = False, allowed_exec: tuple[str, ...] = ("/usr/local/bin/python", "/usr/local/bin/python3")) -> None:
        self.allow_network = allow_network
        self.allowed_exec = allowed_exec
        self._exec_count: dict[str, int] = {}

    def evaluate(self, ev: SyscallEvent) -> Violation | None:
        sc = ev.syscall.removeprefix("sys_").removeprefix("__x64_sys_").removeprefix("__arm64_sys_")
        v = lambda rule, detail: Violation(ev.container, ev.pid, sc, rule, detail)  # noqa: E731
        if sc in DENIED_SYSCALLS:
            return v("denied_syscall", f"{sc} is never permitted in a sandbox")
        if sc == "socket" and ev.args.get("domain") == AF_UNIX:  # regardless of network mode
            return v("unix_socket", "AF_UNIX sockets can reach host daemons")
        if sc in NETWORK_SYSCALLS and not self.allow_network:
            return v("network", f"{sc} with networking disabled")
        if sc == "socket" and ev.args.get("domain") not in (None, AF_INET, AF_INET6, AF_UNIX):
            return v("raw_socket", f"socket domain {ev.args.get('domain')}")
        if sc in ("execve", "execveat"):
            n = self._exec_count.get(ev.container, 0) + 1
            self._exec_count[ev.container] = n
            path = str(ev.args.get("filename", ev.args.get("path", "")))
            if n > 1 or (path and not path.startswith(self.allowed_exec)):
                return v("exec", f"unexpected execve({path!r}) #{n}")
        if sc in ("open", "openat", "openat2", "creat"):
            path = str(ev.args.get("filename", ev.args.get("path", "")))
            flags = int(ev.args.get("flags", 0) or 0)
            writes = bool(flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC)) or sc == "creat"
            if writes and not path.startswith(SAFE_WRITE_PREFIXES):
                return v("fs_write", f"write-open outside /tmp: {path}")
            if path.startswith(("/proc/1/", "/proc/sys", "/sys/kernel", "/var/run/docker.sock", "/run/docker.sock")):
                return v("fs_sensitive", f"open {path}")
        if sc in FS_MUTATING:
            path = str(ev.args.get("filename", ev.args.get("path", "")))
            if not path.startswith(SAFE_WRITE_PREFIXES):
                return v("fs_mutate", f"{sc} outside /tmp: {path}")
        return None


def parse_tetragon_event(line: str) -> SyscallEvent | None:
    """Best-effort parse of one ``tetra getevents -o json`` line (kprobe/tracepoint events)."""
    try:
        ev = json.loads(line)
    except json.JSONDecodeError:
        return None
    body = ev.get("process_kprobe") or ev.get("process_tracepoint") or ev.get("process_exec")
    if not body:
        return None
    proc = body.get("process", {})
    container = (proc.get("pod", {}).get("container", {}) or {}).get("id", "") or proc.get("docker", "")
    name = body.get("function_name") or body.get("event") or ("execve" if "process_exec" in ev else "")
    args: dict[str, Any] = {}
    for i, a in enumerate(body.get("args", []) or []):
        for key in ("string_arg", "file_arg", "path_arg", "int_arg", "size_arg"):
            if key in a:
                val = a[key]
                val = val.get("path", val) if isinstance(val, dict) else val
                args[f"arg{i}"] = val
                if key in ("string_arg", "file_arg", "path_arg"):
                    args.setdefault("filename", val)
                elif key == "int_arg":
                    args.setdefault("flags", val)
                break
    if name == "execve" or "process_exec" in ev:
        args.setdefault("filename", proc.get("binary", ""))
    return SyscallEvent(container=container, pid=int(proc.get("pid", 0) or 0), syscall=name, args=args, binary=proc.get("binary", ""))


class EbpfSyscallMonitor:
    """Consume events, enforce policy, respond. ``on_violation`` should kill the container and audit."""

    def __init__(self, policy_factory: Callable[[str], SyscallPolicy], on_violation: Callable[[Violation], Awaitable[None]]) -> None:
        self._factory = policy_factory
        self._on_violation = on_violation
        self._policies: dict[str, SyscallPolicy] = {}

    async def handle(self, ev: SyscallEvent) -> Violation | None:
        pol = self._policies.setdefault(ev.container, self._factory(ev.container))
        viol = pol.evaluate(ev)
        if viol:
            await self._on_violation(viol)
        return viol

    async def run(self, events: AsyncIterator[SyscallEvent]) -> None:
        async for ev in events:
            await self.handle(ev)


async def tetragon_events(cmd: tuple[str, ...] = ("tetra", "getevents", "-o", "json")) -> AsyncIterator[SyscallEvent]:  # pragma: no cover
    """Stream events from the Tetragon CLI (requires a running Tetragon agent)."""
    proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE)
    assert proc.stdout
    async for raw in proc.stdout:
        ev = parse_tetragon_event(raw.decode("utf-8", "ignore"))
        if ev:
            yield ev
