package middleware

import (
	"context"
	"fmt"
	"net/http"
)

func BeforeAfterMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Executing before request logic")
		ctx := context.WithValue(r.Context(), "user", nil)
		r = r.WithContext(ctx)

		// Call the next handler in the chain
		next.ServeHTTP(w, r)

		fmt.Println("Executing after request logic")
	})
}