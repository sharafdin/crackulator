# Build stage
FROM golang:1.24-alpine AS builder

# Set working directory
WORKDIR /app

# Copy go.mod and go.sum
COPY go.mod ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o crackulator

# Final stage
FROM alpine:latest

# Install necessary packages for TLS certificates
RUN apk --no-cache add ca-certificates

# Set working directory
WORKDIR /root/

# Copy the binary from the build stage
COPY --from=builder /app/crackulator .

# Set the binary as the entrypoint
ENTRYPOINT ["./crackulator"] 