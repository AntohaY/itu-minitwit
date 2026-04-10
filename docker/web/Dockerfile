# ==========================================
# STAGE 1: Build the app
# ==========================================
FROM golang:1.25 AS builder
WORKDIR /usr/src/app

# Cache dependencies first (Assuming go.mod is inside 'new/')
COPY new/go.mod new/go.sum ./
RUN go mod download

# Now copy the rest of the code
COPY new/ .

# Build the Go binary securely for Linux
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o minitwit-server main.go

# ==========================================
# STAGE 2: Create the production image
# ==========================================
FROM alpine:3.19
# Install CA certificates and set up a non-root user
# hadolint ignore=DL3018
RUN apk --no-cache add ca-certificates && \
    addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /usr/src/app

# Change ownership to the non-root user
COPY --from=builder --chown=appuser:appgroup /usr/src/app/minitwit-server .
COPY --from=builder --chown=appuser:appgroup /usr/src/app/templates/ ./templates/
COPY --from=builder --chown=appuser:appgroup /usr/src/app/static/ ./static/

# Switch to the non-root user
USER appuser

# Document the port (Change 8080 to your actual port)
EXPOSE 8080

CMD [ "./minitwit-server" ]