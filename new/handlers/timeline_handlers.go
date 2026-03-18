package handlers

import (
	"context"
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

func PublicTimelineHandler(w http.ResponseWriter, r *http.Request) {
	skip, page := app.GetPageAndSkip(r.URL.Query().Get("page"))

	msgs, err := app.QueryDatabaseForMessages(app.PER_PAGE, skip)
	if err != nil {
		http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var currUser *User
	if u := r.Context().Value("user"); u != nil {
		val := u.(User)
		currUser = &val
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{
		"flagged": false,
	}

	totalMessages, err := app.DB.Collection("message").CountDocuments(ctx, filter)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	totalPages, prevPage, nextPage, visiblePages := app.GetPaginationInfo(totalMessages, page, app.PER_PAGE, 5)

	data := TimelineUserData{
		PageTitle:    "Public Timeline",
		PageID:       "public",
		Messages:     msgs,
		CurrentUser:  currUser,
		ProfileUser:  nil,
		Flashes:      GetFlash(w, r),
		Page:         page,
		NextPage:     nextPage,
		PrevPage:     prevPage,
		TotalPages:   totalPages,
		VisiblePages: visiblePages,
	}

	app.RenderTemplate(w, "timeline.html", data)
}

func PersonalTimelineHandler(w http.ResponseWriter, r *http.Request) {
	skip, page := app.GetPageAndSkip(r.URL.Query().Get("page"))

	var currUser *User
	if u := r.Context().Value("user"); u != nil {
		val := u.(User)
		currUser = &val
	}

	if currUser == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	msgs, err := app.GetFollowedMessages(currUser.ID, app.PER_PAGE, skip)
	if err != nil {
		log.Printf("error fetching followed messages for user %s: %v", currUser.ID.Hex(), err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	totalMessages, err := app.CountFollowedMessages(currUser.ID)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	totalPages, prevPage, nextPage, visiblePages := app.GetPaginationInfo(totalMessages, page, app.PER_PAGE, 5)

	data := TimelineUserData{
		PageTitle:    "My Timeline",
		PageID:       "personal",
		Messages:     msgs,
		CurrentUser:  currUser,
		ProfileUser:  currUser,
		Page:         page,
		NextPage:     nextPage,
		PrevPage:     prevPage,
		Flashes:      GetFlash(w, r),
		TotalPages:   totalPages,
		VisiblePages: visiblePages,
	}

	app.RenderTemplate(w, "timeline.html", data)
}

func UserTimelineHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]

	skip, page := app.GetPageAndSkip(r.URL.Query().Get("page"))

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

	filter := bson.M{
		"author_id": profileUser.ID,
		"flagged":   false,
	}

	opts := options.Find().
		SetSort(bson.D{{Key: "pub_date", Value: -1}, {Key: "_id", Value: -1}}).
		SetSkip(int64(skip)).
		SetLimit(int64(app.PER_PAGE))

	totalMessages, err := app.DB.Collection("message").CountDocuments(ctx, filter)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	cursor, err := app.DB.Collection("message").Find(ctx, filter, opts)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	var rawResults []struct {
		Text     string             `bson:"text"`
		PubDate  int64              `bson:"pub_date"`
		AuthorID primitive.ObjectID `bson:"author_id"`
		Flagged  bool               `bson:"flagged"`
	}

	if err := cursor.All(ctx, &rawResults); err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	var messages []Message
	for _, raw := range rawResults {
		msg := Message{
			Text:     raw.Text,
			PubDate:  int(raw.PubDate),
			Username: profileUser.Username,
		}
		messages = append(messages, msg)
	}

	totalPages, prevPage, nextPage, visiblePages := app.GetPaginationInfo(totalMessages, page, app.PER_PAGE, 5)

	data := TimelineUserData{
		PageTitle:    profileUser.Username + "'s Timeline",
		PageID:       "user",
		Messages:     messages,
		ProfileUser:  &profileUser,
		CurrentUser:  currUser,
		IsFollowing:  followed,
		Flashes:      GetFlash(w, r),
		Page:         page,
		NextPage:     nextPage,
		PrevPage:     prevPage,
		TotalPages:   totalPages,
		VisiblePages: visiblePages,
	}

	app.RenderTemplate(w, "timeline.html", data)
}

func NotFoundHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)

	var currUser *User
	if u := r.Context().Value("user"); u != nil {
		val := u.(User)
		currUser = &val
	}

	data := TimelineUserData{
		PageTitle:   "Page Not Found",
		CurrentUser: currUser,
	}

	app.RenderTemplate(w, "404.html", data)
}
