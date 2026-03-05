package handlers

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"minitwit/app"
	. "minitwit/helpers/flashes"
	. "minitwit/types"

	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// PublicTimelineHandler displays the public timeline with all messages
func PublicTimelineHandler(w http.ResponseWriter, r *http.Request) {
	msgs, err := app.QueryDatabaseForMessages(app.PER_PAGE)
	if err != nil {
		http.Error(w, "Database error: "+err.Error(), 500)
		return
	}

	var currUser *User
	if u := r.Context().Value("user"); u != nil {
		val := u.(User)
		currUser = &val
	}

	data := TimelineUserData{
		PageTitle:   "Public Timeline",
		PageID:      "public",
		Messages:    msgs,
		CurrentUser: currUser,
		ProfileUser: nil,
		Flashes:     GetFlash(w, r),
	}

	app.RenderTemplate(w, "timeline.html", data)
}

// PersonalTimelineHandler displays the logged-in user's personal timeline
func PersonalTimelineHandler(w http.ResponseWriter, r *http.Request) {
	var currUser *User
	if u := r.Context().Value("user"); u != nil {
		val := u.(User)
		currUser = &val
	}

	if currUser == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	msgs, _ := app.GetFollowedMessages(currUser.ID, app.PER_PAGE)

	data := TimelineUserData{
		PageTitle:   "My Timeline",
		PageID:      "personal",
		Messages:    msgs,
		CurrentUser: currUser,
		ProfileUser: currUser,
	}

	app.RenderTemplate(w, "timeline.html", data)
}

// UserTimelineHandler displays a specific user's timeline
func UserTimelineHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var profileUser User
	err := app.DB.Collection("user").FindOne(ctx, bson.M{"username": username}).Decode(&profileUser)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	var currUser *User
	if u := r.Context().Value("user"); u != nil {
		val := u.(User)
		currUser = &val
	}

	followed := false
	if currUser != nil {
		var result struct{}
		err := app.DB.Collection("follower").FindOne(ctx, bson.M{
			"who_id":  currUser.ID,
			"whom_id": profileUser.ID,
		}).Decode(&result)
		if err == nil {
			followed = true
		}
	}

	opts := options.Find().SetSort(bson.M{"pub_date": -1}).SetLimit(app.PER_PAGE)

	cursor, err := app.DB.Collection("message").Find(ctx, bson.M{
		"author_id": profileUser.ID,
		"flagged":   false,
	}, opts)

	var messages []Message

	if err == nil {
		var rawResults []struct {
			Text     string             `bson:"text"`
			PubDate  int64              `bson:"pub_date"`
			AuthorID primitive.ObjectID `bson:"author_id"`
			Flagged  bool               `bson:"flagged"`
		}

		if err := cursor.All(ctx, &rawResults); err != nil {
			fmt.Println("Decoding error:", err)
		}

		for _, raw := range rawResults {
			msg := Message{
				Text:     raw.Text,
				PubDate:  int(raw.PubDate),
				Username: profileUser.Username,
			}
			messages = append(messages, msg)
		}
	}

	data := TimelineUserData{
		PageTitle:   profileUser.Username + "'s Timeline",
		PageID:      "user",
		Messages:    messages,
		ProfileUser: &profileUser,
		CurrentUser: currUser,
		IsFollowing: followed,
		Flashes:     GetFlash(w, r),
	}

	app.RenderTemplate(w, "timeline.html", data)
}
