# ==============================================================================
# THF (Threat Hunting Framework) - Docker Image
# ==============================================================================
# Multi-stage build for optimized image size and security
# ==============================================================================

# ==============================================================================
# Stage 1: Base Image
# ==============================================================================
FROM python:3.11-slim as base

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# ==============================================================================
# Stage 2: Dependencies Builder
# ==============================================================================
FROM base as builder

# Install system dependencies required for building Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    build-essential \
    libssl-dev \
    libffi-dev \
    cargo \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements file
COPY requirements.txt .

# Install Python dependencies
RUN pip install --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# ==============================================================================
# Stage 3: Runtime Image
# ==============================================================================
FROM base as runtime

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Set PATH to use virtual environment
ENV PATH="/opt/venv/bin:$PATH"

# Create non-root user for security
RUN groupadd -r thf && useradd -r -g thf thf

# Create application directory
WORKDIR /app

# Copy application files
COPY --chown=thf:thf . .

# Fix line endings and make entrypoint executable (must be done before switching to non-root user)
RUN if [ -f /app/docker-entrypoint.sh ]; then \
        sed -i 's/\r$//' /app/docker-entrypoint.sh && \
        chmod +x /app/docker-entrypoint.sh; \
    fi

# Create directory for logs
RUN mkdir -p /app/logs && chown -R thf:thf /app/logs

# Switch to non-root user
USER thf

# Expose ports
# 8000: FastAPI backend
# 8501: Streamlit UI
EXPOSE 8000 8501

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Set entrypoint script
ENTRYPOINT ["/app/docker-entrypoint.sh"]
