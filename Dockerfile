# Stage 1: Build the Go application
FROM golang:1.24-bookworm AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the entire source code
COPY . .

# Build the Go application
RUN go build -o vuln-scan-query ./cmd/vulnscanquery

# Stage 2: Create a minimal runtime image
FROM debian:stable-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the compiled binary from the builder stage
COPY --from=builder /app/vuln-scan-query .

# Copy any necessary static files (if applicable)
# COPY --from=builder /app/static ./static

# Expose the port the application listens on (adjust if different)
EXPOSE 8080

# Command to run the executable
CMD ["./vuln-scan-query"]