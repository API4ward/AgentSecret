# Agent end-to-end image: the real `claude` and `codex` CLIs plus Secret Guard,
# all as one unprivileged user, the way the default (non-isolated) setup runs.
# Only synthetic canaries go in here; the model API key arrives by environment.
FROM node:22-bookworm-slim

ARG CLAUDE_CODE_VERSION=2.1.311
ARG CODEX_VERSION=0.166.0

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

# bubblewrap: Codex's Linux sandbox helper. ripgrep/git: tools both agents expect.
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-venv ca-certificates git ripgrep bubblewrap \
 && rm -rf /var/lib/apt/lists/*
RUN npm install -g --no-fund --no-audit @anthropic-ai/claude-code@${CLAUDE_CODE_VERSION} @openai/codex@${CODEX_VERSION} \
 && npm cache clean --force

WORKDIR /opt/secret-guard
COPY requirements.lock pyproject.toml ./
RUN python3 -m venv .venv && .venv/bin/pip install --no-cache-dir -r requirements.lock
COPY secret_guard ./secret_guard
COPY e2e/agent_e2e.py ./e2e/agent_e2e.py

RUN useradd -u 10010 -m -d /home/agent -s /bin/bash agent
USER agent
WORKDIR /home/agent
ENTRYPOINT ["/opt/secret-guard/.venv/bin/python", "/opt/secret-guard/e2e/agent_e2e.py"]
