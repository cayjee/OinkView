# ── Build stage ───────────────────────────────────────────────────────────────
FROM node:20-alpine AS deps

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM node:20-alpine

WORKDIR /app

# Non-root user for security
RUN addgroup -S oinkview && adduser -S oinkview -G oinkview

COPY --from=deps /app/node_modules ./node_modules
COPY package*.json ./
COPY server.js ./
COPY public/ ./public/

# Config and logs are mounted as volumes at runtime
RUN mkdir -p config logs && chown -R oinkview:oinkview /app

USER oinkview

EXPOSE 3000

ENV NODE_ENV=production \
    PORT=3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:3000/api/settings > /dev/null || exit 1

CMD ["node", "server.js"]
