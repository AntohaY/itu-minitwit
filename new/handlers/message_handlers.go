package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"minitwit/app"
	"minitwit/domains"
	. "minitwit/helpers/flashes"
	"minitwit/helpers/requestctx"

	//	. "minitwit/types"

	"go.mongodb.org/mongo-driver/bson"
)

// AddMessageHandler handles posting new messages
func AddMessageHandler(w http.ResponseWriter, r *http.Request) {
	requestID := requestctx.RequestIDFromRequest(r)
	slog.Debug("message create handler called", "method", r.Method, "request_id", requestID)

	if r.Method != http.MethodPost {
		slog.Warn("message create invalid method", "method", r.Method, "request_id", requestID)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	userVal := r.Context().Value("user")
	if userVal == nil {
		slog.Warn("unauthorized message create attempt", "request_id", requestID)
		app.LogFollowError("POST ERROR: Unauthorized user tried to create a post")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	currentUser := userVal.(domains.User)
	slog.Debug("message create attempt", "request_id", requestID)

	text := strings.TrimSpace(r.FormValue("text"))
	if text == "" {
		slog.Info("message create skipped empty text", "request_id", requestID)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	collection := app.DB.Collection("message")

	doc := bson.M{
		"author_id": currentUser.ID,
		"text":      text,
		"pub_date":  time.Now().Unix(),
		"flagged":   false,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := collection.InsertOne(ctx, doc)
	if err != nil {
		if err == context.DeadlineExceeded {
			slog.Error("message create database timeout", "request_id", requestID)
			app.LogFollowError("POST DB TIMEOUT: Message creation took >5s")
		} else {
			slog.Error("message create database error", "error", err.Error(), "request_id", requestID)
			app.LogFollowError("POST DB ERROR: Failed to insert message")
		}
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	slog.Info("message create successful", "request_id", requestID, "text_length", len(text), "author_id", currentUser.ID.Hex())
	SetFlash(w, "Your message was recorded")
	http.Redirect(w, r, "/", http.StatusFound)
}
