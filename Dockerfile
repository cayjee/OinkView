# ── Build stage ───────────────────────────────────────────────────────────────
FROM node:20-slim AS deps

WORKDIR /app

COPY package*.json ./
RUN npm install --omit=dev --no-audit --no-fund

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM node:20-slim

WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY package*.json ./
COPY server.js ./
COPY public/ ./public/

# Runtime deps for Snort 3 binary (mounted from host via volume)
RUN apt-get update && apt-get install -y --no-install-recommends \
      libpcap0.8 libpcre2-8-0 libssl3 libhwloc15 libdumbnet1 \
      liblzma5 libunwind8 libluajit-5.1-2 libuuid1 libnuma1 \
    && rm -rf /var/lib/apt/lists/*

# Config and logs are mounted as volumes at runtime
RUN mkdir -p config logs

EXPOSE 3000

ENV NODE_ENV=production \
    PORT=3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:3000/api/settings > /dev/null || exit 1

CMD ["node", "server.js"]
