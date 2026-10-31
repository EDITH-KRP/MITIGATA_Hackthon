# ==============================================================================
# CyberForge CART — Autonomous VAPT Engine Container
# Controlled Autonomous Red Teaming & Assessment Engine under PTES
# ==============================================================================

FROM python:3.11-slim

# Prevent Python from writing .pyc files and buffer I/O
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# Install essential assessment tools:
# - nmap: Network & open-service host discovery
# - binutils: strings, readelf, and objdump for binary security audits
# - curl, iproute2, procps, ca-certificates: network verification & health
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    binutils \
    curl \
    iproute2 \
    procps \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy project specification & source tree
COPY pyproject.toml README.md ./
COPY src/ ./src/
COPY target_binaries/ ./target_binaries/
COPY docs/ ./docs/
COPY reports/ ./reports/

# Install CART package
RUN pip install --no-cache-dir -e .

# Create reports and database mount points
RUN mkdir -p /app/reports/patches /app/data

# Expose VAPT Web UI & REST API port
EXPOSE 8080

# Default entrypoint starts the universal assessment dashboard
CMD ["python", "-m", "cart.cli", "ui", "--host", "0.0.0.0", "--port", "8080"]

