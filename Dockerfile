FROM golang:1.25-alpine AS builder

RUN apk add --no-cache \
    gcc \
    musl-dev \
    sqlite-dev

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
    go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/mint-ca \
    ./cmd/server

FROM alpine:3.19

RUN apk add --no-cache \
    ca-certificates \
    sqlite-libs \
    tzdata

RUN addgroup -g 1001 -S mintca && \
    adduser  -u 1001 -S mintca -G mintca

RUN mkdir -p /data /certs && \
    chown -R mintca:mintca /data /certs

COPY --from=builder /out/mint-ca /usr/local/bin/mint-ca
RUN chmod +x /usr/local/bin/mint-ca

USER mintca

VOLUME ["/data"]

EXPOSE 8443

HEALTHCHECK \
    --interval=30s \
    --timeout=5s \
    --start-period=10s \
    --retries=3 \
    CMD wget -qO- --no-check-certificate https://localhost:8443/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/mint-ca"]