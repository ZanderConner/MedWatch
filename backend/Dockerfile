# MedWatch backend: ingest API + read API + admin/analytics/security
# for the demo range. Node 22.5+ needed for the built-in node:sqlite
# module (no native deps to compile).
FROM node:22-bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends dumb-init \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install deps first so this layer caches across source-only changes.
COPY backend/package.json backend/package-lock.json ./
RUN npm ci --omit=dev

COPY backend/ ./

# Runs as non-root; SQLite file lives under /app/data, which the compose
# volume mount below should point at a persistent path.
RUN useradd --system --create-home --shell /usr/sbin/nologin medwatch \
    && mkdir -p /app/data \
    && chown -R medwatch:medwatch /app
USER medwatch

ENV NODE_ENV=production
EXPOSE 8080

ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "server.js"]
