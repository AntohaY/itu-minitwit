package handlers

import (
	"context"
	"fmt"
	"log"
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
	skip, page := app.GetPageAndSkip(r.URL.Query().Get("page"))

	// 1. Get Messages
	// (Assuming queryDatabaseForMessages returns []Message)
	msgs, err := app.QueryDatabaseForMessages(app.PER_PAGE, skip)
	if err != nil {
		http.Error(w, "Database error: "+err.Error(), 500)
		return
	}

	// 2. Get Current User (if logged in)
	var currUser *User
	if u := r.Context().Value("user"); u != nil {
		val := u.(User) // Cast interface{} to User struct
		currUser = &val
	}

	// 3. Determine next/prev pages
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// CHANGED: We only filter out flagged messages for the public total count
	filter := bson.M{
		"flagged": false,
	}

	totalMessages, _ := app.DB.Collection("message").CountDocuments(ctx, filter)
	nextPage, prevPage := app.CalculateNextPage(totalMessages, page)

	// 4. Setup Data
	data := TimelineUserData{
		PageTitle:   "Public Timeline",
		PageID:      "public", // Matches {{if eq .PageID "public"}} in template
		Messages:    msgs,
		CurrentUser: currUser,
		ProfileUser: nil,            // Not viewing a specific profile
		Flashes:     GetFlash(w, r), // Your flash helper
		Page:        page,
		NextPage:    nextPage,
		PrevPage:    prevPage,
	}

	app.RenderTemplate(w, "timeline.html", data)
}

func PersonalTimelineHandler(w http.ResponseWriter, r *http.Request) {
	skip, page := app.GetPageAndSkip(r.URL.Query().Get("page"))

	// 1. Get Current User (Security check)
	var currUser *User
	if u := r.Context().Value("user"); u != nil {
		val := u.(User)
		currUser = &val
	}

	if currUser == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// 2. Logic: Get messages from user AND people they follow
	// (You likely have a DB function for this, e.g., getFollowedMessages)
	msgs, err := app.GetFollowedMessages(currUser.ID, app.PER_PAGE, skip)
	if err != nil {
		log.Printf("error fetching followed messages for user %s: %v", currUser.ID.Hex(), err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// 3. Determine next/prev pages accurately!
	totalMessages, _ := app.CountFollowedMessages(currUser.ID)
	nextPage, prevPage := app.CalculateNextPage(totalMessages, page)

	// 4. Render
	data := TimelineUserData{
		PageTitle:   "My Timeline",
		PageID:      "personal", // <--- CRITICAL: Triggers the Input Box in HTML
		Messages:    msgs,
		CurrentUser: currUser,
		ProfileUser: currUser,
		Page:        page,
		NextPage:    nextPage,
		PrevPage:    prevPage,
	}

	app.RenderTemplate(w, "timeline.html", data)
}

// UserTimelineHandler displays a specific user's timeline
func UserTimelineHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]

	skip, page := app.GetPageAndSkip(r.URL.Query().Get("page"))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Find the Profile User
	var profileUser User
	err := app.DB.Collection("user").FindOne(ctx, bson.M{"username": username}).Decode(&profileUser)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// 2. Get Current User (if any)
	var currUser *User
	if u := r.Context().Value("user"); u != nil {
		val := u.(User)
		currUser = &val
	}

	// 3. Check "Following" status
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

	filter := bson.M{
		"author_id": profileUser.ID,
		"flagged":   false,
	}
	// 4. Get Messages & Fill Missing Data
	opts := options.Find().SetSort(bson.D{{Key: "pub_date", Value: -1}, {Key: "_id", Value: -1}}).SetSkip(int64(skip)).SetLimit(int64(app.PER_PAGE))

	totalMessages, _ := app.DB.Collection("message").CountDocuments(ctx, filter)

	cursor, err := app.DB.Collection("message").Find(ctx, bson.M{
		"author_id": profileUser.ID,
		"flagged":   false,
	}, opts)

	var messages []Message

	if err == nil {
		// A. Define a temporary struct that matches MongoDB types EXACTLY
		var rawResults []struct {
			Text     string             `bson:"text"`
			PubDate  int64              `bson:"pub_date"`  // DB uses int64
			AuthorID primitive.ObjectID `bson:"author_id"` // DB uses ObjectID
			Flagged  bool               `bson:"flagged"`   // DB uses bool
		}

		// B. Decode into this safe struct first
		// If this fails, we will now see the error!
		if err := cursor.All(ctx, &rawResults); err != nil {
			fmt.Println("Decoding error:", err) // Check your terminal if empty!
		}

		// C. Manually map to your view struct (just like PublicTimeline)
		for _, raw := range rawResults {
			msg := Message{
				Text:     raw.Text,
				PubDate:  int(raw.PubDate), // Convert int64 -> int
				Username: profileUser.Username,
				//Email:    profileUser.Email,
			}
			messages = append(messages, msg)
		}
	}

	// 5. Determine next/prev pages
	nextPage, prevPage := app.CalculateNextPage(totalMessages, page)

	// 6. Render
	data := TimelineUserData{
		PageTitle:   profileUser.Username + "'s Timeline",
		PageID:      "user",
		Messages:    messages,
		ProfileUser: &profileUser,
		CurrentUser: currUser,
		IsFollowing: followed,
		Flashes:     GetFlash(w, r),
		Page:        page,
		NextPage:    nextPage,
		PrevPage:    prevPage,
	}

	app.RenderTemplate(w, "timeline.html", data)
}
