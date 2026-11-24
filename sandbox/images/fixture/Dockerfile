# syntax=docker/dockerfile:1
# CI fixture for the sandbox runtime tests (ADR 0016): one harmless script, no tools, no
# packages. Same digest-pinned base as the root Dockerfile; Dependabot proposes both together.

FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928
LABEL org.opencontainers.image.title="attacksurf sandbox fixture" \
      org.opencontainers.image.description="CI fixture for the sandbox runtime tests. Never a real analyzer."
# The sandbox root is read-only: no bytecode cache to write.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
# 0755, not 0644: BuildKit applies the mode to the directories it creates too, and the sandbox
# user needs to traverse /opt/fixture.
COPY --chmod=0755 probe.py /opt/fixture/probe.py
# The launcher sets the same user on every run; this is the fallback for a run by hand.
USER 65532:65532
