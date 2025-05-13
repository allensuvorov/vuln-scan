# -------- Stage 1: Build the Go application --------
FROM golang:1.24-bookworm AS builder

    # Set the working directory inside the builder container
    WORKDIR /app
    
    # Copy dependency files and download dependencies
    COPY go.mod go.sum ./
    RUN go mod download
    
    # Copy the rest of the source code
    COPY . .
    
    # Build the Go application (disable CGO for static binary)
    RUN CGO_ENABLED=0 GOOS=linux go build -o vuln-scan-query ./cmd/vulnscanquery
    
    # -------- Stage 2: Create a minimal runtime image --------
    FROM gcr.io/distroless/static:nonroot
    
    # Copy the compiled binary from the builder stage
    COPY --from=builder /app/vuln-scan-query /
    
    # Expose the HTTP port (adjust if needed)
    EXPOSE 8080
    
    # Run the binary as non-root user (UID 65532 is 'nonroot')
    USER nonroot:nonroot
    ENTRYPOINT ["/vuln-scan-query"]