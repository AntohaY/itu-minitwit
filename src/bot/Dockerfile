# ==========================================
# STAGE 1: Build the app
# ==========================================
FROM golang:1.25.10 AS builder
WORKDIR /usr/src/app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build the Go binary securely for Linux
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o discordbot main.go

# ==========================================
# STAGE 2: Create the production image
# ==========================================
FROM alpine:3.23
# Install CA certificates and set up a non-root user
RUN apk --no-cache add ca-certificates=20260413-r0 && \
    addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /usr/src/app

RUN mkdir -p /app && chown -R appuser:appgroup /app /usr/src/app

# Copy only the binary into the final image
COPY --from=builder --chown=appuser:appgroup /usr/src/app/discordbot .

# Switch to the non-root user
USER appuser

CMD ["./discordbot"]