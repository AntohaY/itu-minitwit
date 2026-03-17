package handlers

import (
	"context"
	"log"
	"net/http"
	"strings"
	"time"

	"minitwit/app"
	. "minitwit/helpers/flashes"
	. "minitwit/types"

	"go.mongodb.org/mongo-driver/bson"
)

// AddMessageHandler handles posting new messages
func AddMessageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	userVal := r.Context().Value("user")
	if userVal == nil {
		app.LogFollowError("POST ERROR: Unauthorized user tried to create a post")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	currentUser := userVal.(User)

	text := strings.TrimSpace(r.FormValue("text"))
	if text == "" {
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
			app.LogFollowError("POST DB TIMEOUT: Message creation took >5s for user " + currentUser.Username)
		} else {
			app.LogFollowError("POST DB ERROR: Failed to insert message for " + currentUser.Username + ": " + err.Error())
		}
		http.Error(w, "Database error", http.StatusInternalServerError)
		log.Println("Insert error:", err)
		return
	}

	SetFlash(w, "Your message was recorded")
	http.Redirect(w, r, "/", http.StatusFound)
}
