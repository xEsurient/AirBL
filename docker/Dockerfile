# AirBL - AirVPN DroneBL Checker with Hummingbird VPN
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
RUN pip install --no-cache-dir -r /tmp/requirements.txt \
    && pip install --no-cache-dir uvicorn fastapi speedtest-cli

# Final image
FROM python:3.11-slim

LABEL maintainer="AirBL"
LABEL description="AirVPN DroneBL Checker with VPN integration"

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Networking tools
    iputils-ping \
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
    # For Hummingbird
    libcap2-bin \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

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
RUN mkdir -p /app/conf /app/data /etc/wireguard

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV AIRBL_CONFIG_DIR=/app/conf
ENV AIRBL_CACHE_DIR=/app/data

# Download Hummingbird (AirVPN's WireGuard client)
# Note: You need to download Hummingbird from AirVPN and place it in the build context
# or modify this to download from your preferred location
ARG HUMMINGBIRD_VERSION=1.2.0
RUN echo "Note: Hummingbird binary needs to be added manually if you plan on using it instead of wg-quick"

# Copy entrypoint script
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Expose web GUI port
EXPOSE 5665

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5665/api/status || exit 1

# Run as root for network operations
# In production, use proper user isolation with capabilities
USER root

ENTRYPOINT ["/usr/bin/tini", "--", "/entrypoint.sh"]
CMD ["web", "--port", "5665", "--auto-scan"]

