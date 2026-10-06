# AirBL - AirVPN DroneBL Checker with built-in WireGuard speedtests
# Multi-stage build for smaller final image

FROM python:3.11-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY requirements.txt /tmp/
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Final image
FROM python:3.11-slim

LABEL maintainer="AirBL"
LABEL description="AirVPN DroneBL Checker with VPN integration"

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Networking tools
    iputils-ping \
    # Time zones: TZ (compose) sets local time for scan schedules and timestamps
    tzdata \
    iproute2 \
    iptables \
    dnsutils \
    procps \
    curl \
    wget \
    tini \
    # WireGuard
    wireguard-tools \
    openresolv \
    # capsh (NET_ADMIN check in the entrypoint)
    libcap2-bin \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install official Ookla Speedtest CLI (multi-arch), checksum-pinned to 1.2.0
# (update the hashes together with the version)
ARG SPEEDTEST_VERSION=1.2.0
RUN ARCH=$(dpkg --print-architecture) && \
    case "$ARCH" in \
        amd64)   OOKLA_ARCH="x86_64";  SHA256="5690596c54ff9bed63fa3732f818a05dbc2db19ad36ed68f21ca5f64d5cfeeb7" ;; \
        arm64)   OOKLA_ARCH="aarch64"; SHA256="3953d231da3783e2bf8904b6dd72767c5c6e533e163d3742fd0437affa431bd3" ;; \
        armhf)   OOKLA_ARCH="armhf";   SHA256="e45fcdebbd8a185553535533dd032d6b10bc8c64eee4139b1147b9c09835d08d" ;; \
        *)       echo "Unsupported architecture: $ARCH" && exit 1 ;; \
    esac && \
    curl -fsSL "https://install.speedtest.net/app/cli/ookla-speedtest-${SPEEDTEST_VERSION}-linux-${OOKLA_ARCH}.tgz" \
        -o /tmp/speedtest.tgz && \
    echo "${SHA256}  /tmp/speedtest.tgz" | sha256sum -c - && \
    tar -xzf /tmp/speedtest.tgz -C /usr/local/bin speedtest && \
    chmod +x /usr/local/bin/speedtest && \
    rm /tmp/speedtest.tgz

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Create app directory
WORKDIR /app

# Copy application code
COPY airbl/ /app/airbl/
COPY main.py /app/
COPY requirements.txt /app/

# Clean any Python cache
RUN find /app -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true && \
    find /app -name "*.pyc" -delete 2>/dev/null || true && \
    find /app -name "*.pyo" -delete 2>/dev/null || true

# Create directories
RUN mkdir -p /app/conf /app/data

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV AIRBL_CONFIG_DIR=/app/conf
ENV AIRBL_CACHE_DIR=/app/data
# Dashboard port: read by the web server, the healthcheck, the dashboard routing
# exception and the kill switch, so set it here (or in compose) rather than via --port
ENV PORT=5665

# Copy entrypoint script
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Expose web GUI port
EXPOSE 5665

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f "http://localhost:${PORT:-5665}/api/status" || exit 1

# Root is required: the tester creates WireGuard interfaces, policy routes and the
# iptables kill switch (needs NET_ADMIN, which only root gets via cap_add). It only
# affects this container's own network namespace.
USER root

ENTRYPOINT ["/usr/bin/tini", "--", "/entrypoint.sh"]
CMD ["web"]

