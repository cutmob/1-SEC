# ── Stage 1: Build ──────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
    -o /bin/1sec \
    ./cmd/1sec

# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM scratch

# OCI image labels
LABEL org.opencontainers.image.title="1SEC" \
      org.opencontainers.image.description="All-in-one cybersecurity defense platform" \
      org.opencontainers.image.url="https://1-sec.dev" \
      org.opencontainers.image.source="https://github.com/cutmob/1-SEC" \
      org.opencontainers.image.vendor="1SEC" \
      org.opencontainers.image.licenses="AGPL-3.0"

# TLS certs + timezone data from builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Create writable directories for non-root operation
COPY --from=builder /tmp /tmp

COPY --from=builder /bin/1sec /bin/1sec

# Default config — override by mounting /etc/1sec/config.yaml
COPY configs/default.yaml /etc/1sec/config.yaml

WORKDIR /

# Run as non-root (nobody:nogroup)
USER 65534:65534

# API port
EXPOSE 1780
# NATS embedded port
EXPOSE 4222
# Syslog ingestion (UDP/TCP)
EXPOSE 1514/udp
EXPOSE 1514/tcp

# Persist NATS JetStream data
VOLUME ["/data/nats"]

ENTRYPOINT ["/bin/1sec"]
CMD ["up", "--config", "/etc/1sec/config.yaml"]
