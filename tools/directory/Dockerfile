# Directory service container image.
FROM node:20-alpine

WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --production
COPY server.js ./

EXPOSE 8787
ENV PORT=8787

CMD ["node", "server.js"]
