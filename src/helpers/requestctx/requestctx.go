package requestctx

import (
	"context"
	"net/http"
)

type contextKey string

const requestIDKey contextKey = "request_id"

func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDKey, requestID)
}

func RequestID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	requestID, ok := ctx.Value(requestIDKey).(string)
	if !ok {
		return ""
	}
	return requestID
}

func RequestIDFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	return RequestID(r.Context())
}
