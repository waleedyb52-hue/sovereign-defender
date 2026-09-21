# =============================================================================
# Sovereign Defender — container image
#
# Everything in this image is open source: Node.js (MIT) on Debian slim, and
# the corpus lives in SQLite (public domain) embedded in Node itself. There is
# no proprietary runtime, no managed database and no vendor service to sign up
# for, so the whole platform can be stood up on hardware you control.
#
# Build:  docker build -t sovereign-defender .
# Run:    docker run -p 3000:3000 -v sovereign-data:/app/data sovereign-defender
# =============================================================================

# ---- build stage: compile the frontend and bundle the server ----------------
FROM node:24-bookworm-slim AS build

WORKDIR /app

# Install dependencies against the lockfile first so this layer is cached
# whenever only source changes.
COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

# ---- runtime stage: production dependencies only ----------------------------
FROM node:24-bookworm-slim AS runtime

# curl is kept for the healthcheck below; nothing else is added.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

ENV NODE_ENV=production \
    PORT=3000 \
    # Sovereign by default: no cloud inference, no outbound webhooks.
    AI_CLOUD_ENABLED=false

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

# Built artefacts and the pieces the server reads at runtime.
COPY --from=build /app/dist ./dist
COPY --from=build /app/ebpf ./ebpf
COPY --from=build /app/scripts ./scripts
COPY --from=build /app/server ./server

# The corpus is a mounted volume so it survives image rebuilds — the whole
# point of persisting it in the first place.
RUN mkdir -p /app/data /app/fim_sandbox /app/sensitive_store \
    && chown -R node:node /app

# Drop privileges: nothing here needs root, and a defence platform running as
# root is the first thing a reviewer will object to.
USER node

VOLUME ["/app/data"]
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1:3000/api/health || exit 1

CMD ["node", "dist/server.cjs"]
