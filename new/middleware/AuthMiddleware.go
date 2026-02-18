package middleware

import (
	"context"
	"fmt"
	"net/http"

	. "minitwit/types"

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

			// 2. Check if "user_id" exists in the session
			if userIDStr, ok := session.Values["user_id"].(string); ok {
				fmt.Println("User ID found in session:", userIDStr)
				// 3. Find the User in DB
				var currentUser User
				objID, _ := primitive.ObjectIDFromHex(userIDStr)

				err := db.Collection("user").FindOne(context.TODO(), bson.M{"_id": objID}).Decode(&currentUser)

				if err == nil {
					ctx := context.WithValue(r.Context(), "user", currentUser) // we create updated context
					r = r.WithContext(ctx)                                     // update the request with the new context
				}
			}

			// 5. Pass the request to the next handler
            next.ServeHTTP(w, r)
        })
    }
}