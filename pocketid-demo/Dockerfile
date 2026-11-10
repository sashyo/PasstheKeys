# App image for the PasstheKeys demo: pure Node, no dependencies.
# Serves the public origin and reverse-proxies /api/* to the Pocket ID sidecar.
FROM node:20-alpine
WORKDIR /app
COPY server.mjs ./
COPY public ./public
ENV PORT=8080
EXPOSE 8080
CMD ["node", "server.mjs"]
