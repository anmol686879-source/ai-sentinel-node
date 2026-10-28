FROM node:22-alpine
RUN apk add --no-cache tzdata su-exec
# TZ matters: off-hours detection uses the server clock. Change it to your bank's timezone.
ENV NODE_ENV=production DATA_DIR=/app/data PORT=3000 TZ=Asia/Kolkata SEED_DEMO=0 SIMULATE=0
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY server.js engine.js storage.js ./
COPY public ./public
COPY seed ./seed
COPY scripts ./scripts
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh && mkdir -p /app/data && chown -R node:node /app
VOLUME /app/data
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s CMD node -e "fetch('http://localhost:'+process.env.PORT+'/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["node","--no-warnings","server.js"]
