# =============================================================================
# Fackel — Multi-stage Docker build
# =============================================================================
# Builds a production image with all external tool dependencies pre-installed.
#
# Usage:
#   docker build -t fackel .
#   docker run --rm --env-file .env fackel example.com
#
# Minimal build (core tools only — nmap, subfinder, naabu, nuclei, httpx, katana):
#   docker build --build-arg INSTALL_MODE=minimal -t fackel:minimal .
#
# Stages:
#   1. go-builder   — compiles Go-based CLI tools
#   2. rust-builder  — compiles feroxbuster
#   3. runtime       — slim final image with Python + all binaries
# =============================================================================

# ---------------------------------------------------------------------------
# Args
# ---------------------------------------------------------------------------
ARG PYTHON_VERSION=3.12
ARG GO_VERSION=1.23
ARG RUST_VERSION=1.82
ARG INSTALL_MODE=full

# ===========================================================================
# Stage 1 — Go tool compilation
# ===========================================================================
FROM golang:${GO_VERSION}-bookworm AS go-builder

ARG INSTALL_MODE

ENV CGO_ENABLED=0
ENV GOBIN=/go/tools

RUN mkdir -p "$GOBIN"

# Core tools (always installed)
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
 && go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
 && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
 && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
 && go install github.com/projectdiscovery/katana/cmd/katana@latest

# Extended tools (full mode only)
RUN if [ "$INSTALL_MODE" = "full" ]; then \
      go install github.com/lc/gau/v2/cmd/gau@latest \
   && go install github.com/hahwul/dalfox/v2@latest \
   && go install github.com/owasp-amass/amass/v4/...@master \
   && go install github.com/PentestPad/subzy@latest \
   && go install github.com/0xsha/CloudBrute@latest \
   && go install github.com/sa7mon/S3Scanner@latest \
   && go install github.com/ffuf/ffuf/v2@latest; \
    fi

# Normalise case-sensitive binaries
RUN cd "$GOBIN" \
 && [ -f CloudBrute ] && ln -sf CloudBrute cloudbrute || true \
 && [ -f S3Scanner ]  && ln -sf S3Scanner  s3scanner  || true

# ===========================================================================
# Stage 2 — Rust tool compilation (full mode only)
# ===========================================================================
FROM rust:${RUST_VERSION}-bookworm AS rust-builder

ARG INSTALL_MODE

RUN if [ "$INSTALL_MODE" = "full" ]; then \
      cargo install feroxbuster --locked; \
    else \
      mkdir -p /usr/local/cargo/bin; \
    fi

# ===========================================================================
# Stage 3 — Runtime
# ===========================================================================
FROM python:${PYTHON_VERSION}-slim-bookworm AS runtime

ARG INSTALL_MODE

LABEL maintainer="Fackel Team" \
      description="Fackel — Autonomous OSINT and security intelligence agent" \
      org.opencontainers.image.source="https://github.com/fackel-team/fackel"

# Prevent Python from writing .pyc and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# ---------------------------------------------------------------------------
# System packages
# ---------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        whois \
        git \
        curl \
        ca-certificates \
        libpcap0.8 \
        ruby \
        seclists \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# Copy Go binaries from builder
# ---------------------------------------------------------------------------
COPY --from=go-builder /go/tools/ /usr/local/bin/

# ---------------------------------------------------------------------------
# Copy Rust binaries from builder
# ---------------------------------------------------------------------------
COPY --from=rust-builder /usr/local/cargo/bin/feroxbuster* /usr/local/bin/

# ---------------------------------------------------------------------------
# Git-clone tools (testssl.sh, whatweb)
# ---------------------------------------------------------------------------
RUN if [ "$INSTALL_MODE" = "full" ]; then \
      git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl \
   && ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh \
   && git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb \
   && ln -s /opt/whatweb/whatweb /usr/local/bin/whatweb; \
    fi

# ---------------------------------------------------------------------------
# Python tools (wafw00f, paramspider, corsy, linkfinder, sqlmap)
# ---------------------------------------------------------------------------
RUN if [ "$INSTALL_MODE" = "full" ]; then \
      pip install --no-cache-dir wafw00f \
   && pip install --no-cache-dir sqlmap \
   && pip install --no-cache-dir "git+https://github.com/devanshbatham/ParamSpider.git" \
   && git clone --depth 1 https://github.com/GerbenJavado/LinkFinder.git /opt/linkfinder \
   && pip install --no-cache-dir -r /opt/linkfinder/requirements.txt \
   && printf '#!/usr/bin/env bash\nexec python3 /opt/linkfinder/linkfinder.py "$@"\n' \
        > /usr/local/bin/linkfinder && chmod +x /usr/local/bin/linkfinder \
   && git clone --depth 1 https://github.com/s0md3v/Corsy.git /opt/corsy \
   && pip install --no-cache-dir requests \
   && printf '#!/usr/bin/env bash\nexec python3 /opt/corsy/corsy.py "$@"\n' \
        > /usr/local/bin/corsy && chmod +x /usr/local/bin/corsy; \
    fi

# ---------------------------------------------------------------------------
# Ruby tools (wpscan)
# ---------------------------------------------------------------------------
RUN if [ "$INSTALL_MODE" = "full" ]; then \
      gem install wpscan --no-document; \
    fi

# ---------------------------------------------------------------------------
# TruffleHog
# ---------------------------------------------------------------------------
RUN if [ "$INSTALL_MODE" = "full" ]; then \
      curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
        | sh -s -- -b /usr/local/bin; \
    fi

# ---------------------------------------------------------------------------
# Install Fackel
# ---------------------------------------------------------------------------
WORKDIR /app

# Copy dependency files first for layer caching
COPY pyproject.toml README.md LICENSE ./
COPY src/ src/

RUN pip install --no-cache-dir .

# ---------------------------------------------------------------------------
# Runtime configuration
# ---------------------------------------------------------------------------

# Default checkpoint DB location inside the container
ENV FACKEL_CHECKPOINT_DB=/data/checkpoints.db

# Create data directory for checkpoints and reports
RUN mkdir -p /data /app/reports

VOLUME ["/data", "/app/reports"]

ENTRYPOINT ["fackel"]
CMD ["--help"]
