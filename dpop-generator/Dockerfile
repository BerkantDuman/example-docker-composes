# Builder
FROM golang:1.21 AS builder
WORKDIR /app

RUN mkdir -p static && chmod 777 static
COPY . .

# Statik olarak derle
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o dpopapi

# Runtime: glibc yok, tamamen temiz
FROM scratch
WORKDIR /app
COPY --from=builder /app/dpopapi .
EXPOSE 5000
USER 1000
CMD ["./dpopapi"]
