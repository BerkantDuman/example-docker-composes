FROM nginx:alpine

RUN apk add --no-cache ca-certificates

COPY nginx.conf /etc/nginx/nginx.conf
COPY html /usr/share/nginx/html
