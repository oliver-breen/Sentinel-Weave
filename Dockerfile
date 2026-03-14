# ──────────────────────────────────────────────────────────────────────────────
# SentinelWeave — Dockerfile
#
# Produces a lean, production-ready image that runs the live threat-metrics
# dashboard on port 5000.
#
# Build:
#   docker build -t sentinel-weave .
#
# Run:
#   docker run -p 5000:5000 sentinel-weave
#   docker run -p 5000:5000 --env-file .env sentinel-weave
# ──────────────────────────────────────────────────────────────────────────────

# ── Stage 1: dependency builder ───────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# System packages needed to compile native extensions (capstone, yara-python)
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libssl-dev \
        libffi-dev \
        automake \
        libtool \
    && rm -rf /var/lib/apt/lists/*

# Copy only the dependency manifests first so Docker can cache this layer
COPY requirements.txt ./

# Install all runtime deps into a prefix we can copy into the final stage
RUN pip install --upgrade pip \
 && pip install --prefix=/install --no-cache-dir -r requirements.txt


# ── Stage 2: runtime image ────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="SentinelWeave" \
      org.opencontainers.image.description="AI-powered cybersecurity threat detection with post-quantum secure reporting" \
      org.opencontainers.image.version="0.4.0" \
      org.opencontainers.image.authors="Oliver Breen"

# Minimal runtime OS deps (yara-python links against libyara at runtime)
RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 \
        libffi8 \
    && rm -rf /var/lib/apt/lists/*

# Bring in pre-built Python packages from the builder stage
COPY --from=builder /install /usr/local

WORKDIR /app

# Copy the application source — only what is needed at runtime
COPY sentinel_weave/ ./sentinel_weave/
COPY dashboard/      ./dashboard/
COPY quantaweave/    ./quantaweave/

# Add the app directory to PYTHONPATH so packages resolve without install
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# ── Optional Azure / feature credentials ─────────────────────────────────────
# Pass these at runtime via --env-file or -e flags; leave blank to disable.
ENV AZURE_STORAGE_CONNECTION_STRING=""
ENV AZURE_TEXT_ANALYTICS_ENDPOINT=""
ENV AZURE_TEXT_ANALYTICS_KEY=""
ENV AZURE_APPINSIGHTS_CONNECTION_STRING=""
ENV SENTINELWEAVE_AZURE_ENDPOINT=""
ENV SENTINELWEAVE_AZURE_API_KEY=""

EXPOSE 5000

# Health-check: poll the /health endpoint every 30 s
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')"

# Default: start the live dashboard bound to all interfaces
CMD ["python", "-m", "dashboard", "--host", "0.0.0.0", "--port", "5000"]
