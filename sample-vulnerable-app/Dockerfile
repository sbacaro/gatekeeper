FROM node:18-alpine
EXPOSE 3000
USER node
COPY --chown=node:node . /app
HEALTHCHECK --interval=30s CMD wget -qO- http://localhost:3000/health || exit 1
CMD ["node", "server.js"]
