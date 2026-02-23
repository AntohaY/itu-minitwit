# ==========================================
# STAGE 1: Build the app
# ==========================================
FROM golang:1.24 AS builder
WORKDIR /usr/src/app

# Copy your code into the builder
COPY new/ .

# Build the Go binary securely for Linux
RUN CGO_ENABLED=0 GOOS=linux go build -o minitwit-server main.go

# ==========================================
# STAGE 2: Create the tiny production image
# ==========================================
FROM alpine:latest
WORKDIR /usr/src/app

# Copy ONLY the compiled binary from Stage 1
COPY --from=builder /usr/src/app/minitwit-server .

# Copy your static files and templates (adjust paths if they differ)
COPY --from=builder /usr/src/app/templates/ ./templates/
COPY --from=builder /usr/src/app/static/ ./static/

# Run the binary
CMD [ "./minitwit-server" ]