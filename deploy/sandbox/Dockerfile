# Minimal, unprivileged interpreter image for agent-generated code. No shell utilities beyond the base,
# no package manager at runtime, nothing writable except the --tmpfs mounted by the sandbox manager.
FROM python:3.12-alpine
RUN apk del --purge apk-tools 2>/dev/null || true \
 && rm -rf /var/cache/apk /root/.cache \
 && adduser -D -u 65534 -h /tmp sandbox 2>/dev/null || true
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 65534:65534
WORKDIR /tmp
# Entry command is supplied by SandboxManager: python -I -B -   (code arrives on stdin)
