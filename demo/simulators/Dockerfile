# ─────────────────────────────────────────────────────────────
#  DICOM Modality Simulator
#  Uses uv for fast, reproducible Python dependency installation.
#  uv is copied directly from its official image — no curl/wget.
# ─────────────────────────────────────────────────────────────
ARG PYTHON_VERSION=3.12
ARG UV_VERSION=0.4.18

# ── Stage 0: pull uv binary ───────────────────────────────────
FROM ghcr.io/astral-sh/uv:${UV_VERSION} AS uv

# ── Stage 1: install deps ─────────────────────────────────────
FROM python:${PYTHON_VERSION}-slim AS builder

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

COPY --from=uv /uv /usr/local/bin/uv

WORKDIR /app
COPY pyproject.toml .

RUN uv venv .venv && \
    uv pip install --python .venv/bin/python -r pyproject.toml

# ── Stage 2: lean runtime ────────────────────────────────────
FROM python:${PYTHON_VERSION}-slim

WORKDIR /app
COPY --from=builder /app/.venv /app/.venv
COPY simulator.py patients.csv ./

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1

CMD ["python", "-u", "simulator.py"]
