#!/bin/bash
# ==============================================================================
# THF (Threat Hunting Framework) - Docker Entrypoint Script
# ==============================================================================
# This script starts both the FastAPI backend and Streamlit UI
# ==============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ==============================================================================
# Helper Functions
# ==============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# ==============================================================================
# Validate Required Environment Variables
# ==============================================================================

log_info "Validating environment configuration..."

REQUIRED_VARS=(
    "ANTHROPIC_API_KEY"
    "OPENSEARCH_HOST"
    "OPENSEARCH_PORT"
    "OPENSEARCH_USER"
    "OPENSEARCH_PASSWORD"
)

MISSING_VARS=()

for var in "${REQUIRED_VARS[@]}"; do
    if [ -z "${!var}" ]; then
        MISSING_VARS+=("$var")
    fi
done

if [ ${#MISSING_VARS[@]} -ne 0 ]; then
    log_error "Missing required environment variables:"
    for var in "${MISSING_VARS[@]}"; do
        echo "  - $var"
    done
    log_error "Please check your .env file and ensure all required variables are set."
    exit 1
fi

log_success "All required environment variables are set"

# ==============================================================================
# Display Configuration (without exposing secrets)
# ==============================================================================

log_info "Starting THF (Threat Hunting Framework)..."
echo ""
echo "=========================================="
echo "  Configuration Summary"
echo "=========================================="
echo "  OpenSearch Host: ${OPENSEARCH_HOST}"
echo "  OpenSearch Port: ${OPENSEARCH_PORT}"
echo "  OpenSearch User: ${OPENSEARCH_USER}"
echo "  API Host: ${API_HOST:-0.0.0.0}"
echo "  API Port: ${API_PORT:-8000}"
echo "  Log Level: ${LOG_LEVEL:-INFO}"
echo "  Environment: ${ENVIRONMENT:-development}"
echo "=========================================="
echo ""

# ==============================================================================
# Signal Handling for Graceful Shutdown
# ==============================================================================

cleanup() {
    log_warning "Received shutdown signal. Stopping services..."

    # Kill background processes
    if [ ! -z "$FASTAPI_PID" ]; then
        log_info "Stopping FastAPI backend (PID: $FASTAPI_PID)..."
        kill -TERM "$FASTAPI_PID" 2>/dev/null || true
    fi

    if [ ! -z "$STREAMLIT_PID" ]; then
        log_info "Stopping Streamlit UI (PID: $STREAMLIT_PID)..."
        kill -TERM "$STREAMLIT_PID" 2>/dev/null || true
    fi

    # Wait for processes to terminate
    wait 2>/dev/null || true

    log_success "All services stopped gracefully"
    exit 0
}

trap cleanup SIGTERM SIGINT SIGQUIT

# ==============================================================================
# Start FastAPI Backend
# ==============================================================================

log_info "Starting FastAPI backend on port ${API_PORT:-8000}..."

uvicorn main:app \
    --host "${API_HOST:-0.0.0.0}" \
    --port "${API_PORT:-8000}" \
    --log-level "${LOG_LEVEL:-info}" \
    --no-access-log \
    2>&1 | sed 's/^/[FastAPI] /' &

FASTAPI_PID=$!
log_success "FastAPI backend started (PID: $FASTAPI_PID)"

# Wait a few seconds for FastAPI to initialize
sleep 5

# ==============================================================================
# Health Check for FastAPI
# ==============================================================================

log_info "Checking FastAPI backend health..."

MAX_RETRIES=10
RETRY_COUNT=0

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if curl -sf "http://localhost:${API_PORT:-8000}/health" > /dev/null 2>&1; then
        log_success "FastAPI backend is healthy"
        break
    fi

    RETRY_COUNT=$((RETRY_COUNT + 1))

    if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
        log_error "FastAPI backend failed to start properly"
        log_error "Check logs for more details"
        cleanup
        exit 1
    fi

    log_warning "Waiting for FastAPI to be ready... (Attempt $RETRY_COUNT/$MAX_RETRIES)"
    sleep 3
done

# ==============================================================================
# Start Streamlit UI
# ==============================================================================

log_info "Starting Streamlit UI on port 8501..."

streamlit run streamlit_ui.py \
    --server.port 8501 \
    --server.address 0.0.0.0 \
    --server.headless true \
    --browser.gatherUsageStats false \
    --server.fileWatcherType none \
    2>&1 | sed 's/^/[Streamlit] /' &

STREAMLIT_PID=$!
log_success "Streamlit UI started (PID: $STREAMLIT_PID)"

# ==============================================================================
# Display Access Information
# ==============================================================================

sleep 3

echo ""
echo "=========================================="
echo "  🛡️  THF is Ready!"
echo "=========================================="
echo ""
echo "  🌐 Streamlit UI:     http://localhost:8501"
echo "  📡 FastAPI Backend:  http://localhost:${API_PORT:-8000}"
echo "  📚 API Docs:         http://localhost:${API_PORT:-8000}/docs"
echo "  ❤️  Health Check:    http://localhost:${API_PORT:-8000}/health"
echo ""
echo "=========================================="
echo "  Press Ctrl+C to stop all services"
echo "=========================================="
echo ""

# ==============================================================================
# Keep Container Running and Monitor Processes
# ==============================================================================

while true; do
    # Check if FastAPI is still running
    if ! kill -0 "$FASTAPI_PID" 2>/dev/null; then
        log_error "FastAPI backend has stopped unexpectedly"
        cleanup
        exit 1
    fi

    # Check if Streamlit is still running
    if ! kill -0 "$STREAMLIT_PID" 2>/dev/null; then
        log_error "Streamlit UI has stopped unexpectedly"
        cleanup
        exit 1
    fi

    # Wait before next check
    sleep 10
done
