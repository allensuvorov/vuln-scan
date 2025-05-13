# -------- Stage 1: Build the Go application --------
    FROM golang:1.24.3-bookworm AS builder

    # Install SQLite dev headers for CGO build
    RUN apt-get update && apt-get install -y libsqlite3-dev
    
    WORKDIR /app
    COPY go.mod go.sum ./
    RUN go mod download
    COPY . .
    
    # Enable CGO (needed by go-sqlite3)
    ENV CGO_ENABLED=1
    RUN go build -o vuln-scan-query ./cmd/api
    
    # -------- Stage 2: Runtime image with libsqlite3 --------
    FROM debian:stable-slim
    
    # Install libsqlite3 runtime
    RUN apt-get update && apt-get install -y libsqlite3-0 ca-certificates && rm -rf /var/lib/apt/lists/*
    
    WORKDIR /app
    COPY --from=builder /app/vuln-scan-query .
    
    EXPOSE 8080
    CMD ["./vuln-scan-query"]