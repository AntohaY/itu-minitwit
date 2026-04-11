package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"minitwit/app"
	"minitwit/helpers"
	"minitwit/helpers/requestctx"
	"minitwit/types"
	"net/http"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func BeforeAfterMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = generateRequestID()
		}
		w.Header().Set("X-Request-ID", requestID)

		slog.Debug("request start", "method", r.Method, "path", r.URL.Path, "request_id", requestID)
		ctx := requestctx.WithRequestID(r.Context(), requestID)
		var currentUser *types.User
		session, err := app.Store.Get(r, "minitwit-session")
		if err != nil {
			slog.Warn("failed to load session", "request_id", requestID, "error", err)
		} else if val, ok := session.Values["user_id"]; ok {
			userIDStr, ok := val.(string)
			if !ok {
				slog.Warn("session user_id has invalid type", "request_id", requestID)
			} else {
				oid, err := primitive.ObjectIDFromHex(userIDStr)
				if err != nil {
					slog.Warn("invalid session user_id", "request_id", requestID, "user_id", userIDStr, "error", err)
				} else {
					user := new(types.User)
					err := app.DB.Collection("user").FindOne(ctx, bson.M{"_id": oid}).Decode(user)
					if err == nil {
						currentUser = user
					}
				}
			}
		}

		ctx = context.WithValue(ctx, helpers.UserContextKey, currentUser)
		r = r.WithContext(ctx)

		// Call the next handler in the chain
		next.ServeHTTP(w, r)

		slog.Debug("request end", "method", r.Method, "path", r.URL.Path, "request_id", requestID)
	})
}

func generateRequestID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err == nil {
		return hex.EncodeToString(b)
	}
	return hex.EncodeToString([]byte(time.Now().Format("20060102150405.000000000")))
}
