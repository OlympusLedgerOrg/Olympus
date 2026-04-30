# Multi-stage build for the Olympus public verification UI.
#
# Stage 1: build static assets with Vite.
# Stage 2: serve them from a hardened nginx image. The image is designed
# to run with --read-only / readOnlyRootFilesystem; nginx is configured
# below to write its caches and pid file under tmpfs paths.

# --- Build Stage ---
FROM node:20-alpine AS build

WORKDIR /src

# Install dependencies first so layer caching works on source-only edits.
COPY package.json package-lock.json* ./
RUN npm ci --no-audit --no-fund

# Copy source after deps are cached.
COPY tsconfig.json tsconfig.app.json tsconfig.node.json vite.config.ts eslint.config.js index.html ./
COPY public ./public
COPY src ./src

RUN npm run build

# --- Runtime Stage ---
# nginx:1.27-alpine is small (~25 MB) and patched. We override the default
# config with one that serves the SPA and writes only to /tmp paths so the
# container can run with a read-only root filesystem.
FROM nginx:1.27-alpine

# Drop the stock default config so it can't accidentally shadow ours.
RUN rm /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/nginx.conf

COPY --from=build /src/dist /usr/share/nginx/html

# Run as the unprivileged "nginx" user that the official image already
# creates (UID 101). Combined with read_only + the listen-on-8080 config,
# this means the container does not need any capabilities at runtime.
USER 101:101

EXPOSE 8080

# Use the daemon-off form so docker can supervise the foreground process.
CMD ["nginx", "-g", "daemon off;"]
