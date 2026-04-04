package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"minitwit/app"
	"minitwit/domains"
	. "minitwit/helpers/flashes"
	"minitwit/helpers/requestctx"
	. "minitwit/types"

	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func PublicTimelineHandler(w http.ResponseWriter, r *http.Request) {
	skip, page := app.GetPageAndSkip(r.URL.Query().Get("page"))
	requestID := requestctx.RequestIDFromRequest(r)
	slog.Debug("public timeline handler called", "page", page, "skip", skip, "request_id", requestID)

	msgs, err := app.QueryDatabaseForMessages(app.PER_PAGE, skip)
	if err != nil {
		slog.Error("public timeline messages query failed", "error", err.Error(), "request_id", requestID)
		http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var currUser *domains.User
	if u := r.Context().Value("user"); u != nil {
		val := u.(domains.User)
		currUser = &val
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{
		"flagged": false,
	}

	totalMessages, err := app.DB.Collection("message").CountDocuments(ctx, filter)
	if err != nil {
		slog.Error("public timeline count failed", "error", err.Error(), "request_id", requestID)
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

	slog.Debug("public timeline render", "messages", len(msgs), "page", page, "request_id", requestID)
	app.RenderTemplate(w, "timeline.html", data)
}

func PersonalTimelineHandler(w http.ResponseWriter, r *http.Request) {
	skip, page := app.GetPageAndSkip(r.URL.Query().Get("page"))
	requestID := requestctx.RequestIDFromRequest(r)
	slog.Debug("personal timeline handler called", "page", page, "skip", skip, "request_id", requestID)

	var currUser *domains.User
	if u := r.Context().Value("user"); u != nil {
		val := u.(domains.User)
		currUser = &val
	}

	if currUser == nil {
		slog.Info("personal timeline redirect anonymous user", "request_id", requestID)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	msgs, err := app.GetFollowedMessages(currUser.ID, app.PER_PAGE, skip)
	if err != nil {
		slog.Error("failed to fetch followed messages", "error", err.Error(), "request_id", requestID)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	totalMessages, err := app.CountFollowedMessages(currUser.ID)
	if err != nil {
		slog.Error("failed to count followed messages", "error", err.Error(), "request_id", requestID)
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

	slog.Debug("personal timeline render", "messages", len(msgs), "page", page, "request_id", requestID)
	app.RenderTemplate(w, "timeline.html", data)
}

func UserTimelineHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]
	requestID := requestctx.RequestIDFromRequest(r)

	skip, page := app.GetPageAndSkip(r.URL.Query().Get("page"))
	slog.Debug("user timeline handler called", "username", username, "page", page, "skip", skip, "request_id", requestID)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var profileUser domains.User
	err := app.DB.Collection("user").FindOne(ctx, bson.M{"username": username}).Decode(&profileUser)
	if err != nil {
		slog.Warn("user timeline profile not found", "username", username, "request_id", requestID)
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	var currUser *domains.User
	if u := r.Context().Value("user"); u != nil {
		val := u.(domains.User)
		currUser = &val
	}

	followed := false
	if currUser != nil {
		var result struct{}
		err := app.DB.Collection("follow").FindOne(ctx, bson.M{
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
		slog.Error("user timeline count failed", "username", username, "error", err.Error(), "request_id", requestID)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	cursor, err := app.DB.Collection("message").Find(ctx, filter, opts)
	if err != nil {
		slog.Error("user timeline query failed", "username", username, "error", err.Error(), "request_id", requestID)
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
		slog.Error("user timeline decode failed", "username", username, "error", err.Error(), "request_id", requestID)
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

	slog.Debug("user timeline render", "username", username, "messages", len(messages), "page", page, "request_id", requestID)
	app.RenderTemplate(w, "timeline.html", data)
}

func NotFoundHandler(w http.ResponseWriter, r *http.Request) {
	requestID := requestctx.RequestIDFromRequest(r)
	slog.Warn("not found handler called", "path", r.URL.Path, "request_id", requestID)
	w.WriteHeader(http.StatusNotFound)

	var currUser *domains.User
	if u := r.Context().Value("user"); u != nil {
		val := u.(domains.User)
		currUser = &val
	}

	data := TimelineUserData{
		PageTitle:   "Page Not Found",
		CurrentUser: currUser,
	}

	slog.Debug("not found render", "request_id", requestID)
	app.RenderTemplate(w, "404.html", data)
}
