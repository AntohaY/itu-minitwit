package middleware

import (
	"context"
	"log/slog"
	"minitwit/helpers"
	"minitwit/helpers/requestctx"
	"net/http"

	"minitwit/types"

	"github.com/gorilla/sessions"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// AuthMiddleware verify user
func AuthMiddleware(store *sessions.CookieStore, db *mongo.Database) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, _ := store.Get(r, "minitwit-session")
			requestID := requestctx.RequestIDFromRequest(r)

			// 2. Check if "user_id" exists in the session
			if userIDStr, ok := session.Values["user_id"].(string); ok {
				slog.Debug("session contains user id", "request_id", requestID)
				// 3. Find the User in DB
				currentUser := new(types.User)
				objID, err := primitive.ObjectIDFromHex(userIDStr)
				if err != nil {
					slog.Warn("invalid user id in session", "request_id", requestID)
					next.ServeHTTP(w, r)
					return
				}

				err = db.Collection("user").FindOne(context.TODO(), bson.M{"_id": objID}).Decode(currentUser)

				if err == nil {
					ctx := context.WithValue(r.Context(), helpers.UserContextKey, currentUser) // we create updated context
					r = r.WithContext(ctx)                                                     // update the request with the new context
				} else {
					slog.Warn("failed to resolve user from session", "request_id", requestID)
				}
			}

			// 5. Pass the request to the next handler
			next.ServeHTTP(w, r)
		})
	}
}
