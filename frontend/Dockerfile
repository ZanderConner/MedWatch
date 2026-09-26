# MedWatch frontend: static Vite build served by nginx. Talks to the
# backend's read API directly from the browser (VITE_API_URL baked in
# at build time — see demo/docker-compose.yml for the value used in the
# range, matching the backend's published host port).
FROM node:22-bookworm-slim AS build
WORKDIR /app
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
ARG VITE_API_URL=http://localhost:9000
ENV VITE_API_URL=${VITE_API_URL}
ARG VITE_ADMIN_API_KEY=change-me
ENV VITE_ADMIN_API_KEY=${VITE_ADMIN_API_KEY}
RUN npm run build

FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
