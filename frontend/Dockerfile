# ============================================================
# Stage 1 — Build: install deps and create production bundle
# ============================================================
FROM node:20-alpine AS builder

ARG VITE_API_BASE_URL=/api/v1
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL

WORKDIR /app

COPY package*.json ./
RUN npm ci --legacy-peer-deps

COPY index.html ./
COPY tsconfig*.json vite.config.ts ./
COPY public/ public/
COPY src/ src/

RUN npm run build

# ============================================================
# Stage 2 — Runtime: nginx serving the static SPA
# ============================================================
FROM nginx:1.27-alpine

RUN apk add --no-cache wget

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/dist /usr/share/nginx/html

EXPOSE 80

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://localhost/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
