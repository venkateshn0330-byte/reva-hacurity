# ==============================================================================
# AgentShield Production Multi-Stage Container Image
# ==============================================================================

# Stage 1: Build React/Vite Frontend
FROM node:20-alpine AS frontend-builder
WORKDIR /build/frontend
COPY agentshield/frontend/package*.json ./
RUN npm ci
COPY agentshield/frontend/ ./
RUN npm run build

# Stage 2: Production Python Runtime
FROM python:3.11-slim AS production

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    AGENTSHIELD_ENV=production \
    AGENTSHIELD_DB_PATH=/var/lib/agentshield/data/events.db \
    HOST=0.0.0.0 \
    PORT=8000

# Create dedicated non-root application user
RUN groupadd -r agentshield && useradd -r -g agentshield -d /home/agentshield -m agentshield

# Install security utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Setup persistent directory for SQLite database
RUN mkdir -p /var/lib/agentshield/data && chown -R agentshield:agentshield /var/lib/agentshield

# Copy backend application source
COPY agentshield/ /app/agentshield/

# Copy compiled frontend assets from Stage 1 into production bundle
COPY --from=frontend-builder /build/frontend/dist /app/agentshield/frontend/dist

# Ensure permissions
RUN chown -R agentshield:agentshield /app

USER agentshield

VOLUME ["/var/lib/agentshield/data"]

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://127.0.0.1:${PORT:-8000}/health || exit 1

CMD ["python3", "/app/agentshield/backend/app/main.py"]
