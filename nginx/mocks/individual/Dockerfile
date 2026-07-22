FROM node:20-alpine

RUN apk add --no-cache openssl \
    && mkdir -p /etc/ssl/certs /etc/ssl/private \
    && openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
        -keyout /etc/ssl/private/mock.key -out /etc/ssl/certs/mock.crt \
        -subj "/CN=individual-mock"

WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
COPY server.js ./

EXPOSE 8080 8443
CMD ["node", "server.js"]
