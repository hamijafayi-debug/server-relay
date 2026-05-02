# ═══════════════════════════════════════════════════════════════════
# Dockerfile — France Relay for Coolify / Docker
# Node.js 22 Alpine — کوچک و سریع
# ═══════════════════════════════════════════════════════════════════

FROM node:22-alpine

# wget برای healthcheck داخلی Docker
RUN apk add --no-cache wget

WORKDIR /app

# اجرا با user غیر root
RUN chown node:node /app
USER node

# اول فقط package.json — تا Docker layer cache کار کنه
COPY --chown=node:node package.json .

# نصب فقط production dependencies
RUN npm install --omit=dev --no-audit --no-fund

# کپی کد اصلی
COPY --chown=node:node relay.js .

# پورت
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://localhost:3000/health || exit 1

# اجرا
CMD ["node", "relay.js"]
