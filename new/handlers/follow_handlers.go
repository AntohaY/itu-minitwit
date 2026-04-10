package handlers

import (
	"context"
	"log/slog"
	"minitwit/app"
	"minitwit/helpers"
	"minitwit/helpers/requestctx"
	"minitwit/types"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// FollowUser handles following another user
func FollowUser(w http.ResponseWriter, r *http.Request) {
	requestID := requestctx.RequestIDFromRequest(r)
	slog.Debug("follow handler called", "request_id", requestID)

	currentUser := r.Context().Value(helpers.UserContextKey)
	if currentUser == nil {
		slog.Warn("follow unauthorized", "request_id", requestID)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		app.LogFollowError("Unauthorized user tried to follow another user")
		return
	}

	user, ok := currentUser.(*types.User)
	if !ok || user == nil {
		slog.Warn("follow user assertion failed", "request_id", requestID)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	username := mux.Vars(r)["username"]
	slog.Debug("follow attempt", "username", username, "request_id", requestID)

	var profileUser types.User
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := app.DB.Collection("user").FindOne(ctx, bson.M{"username": username}).Decode(&profileUser)
	if err != nil {
		if err == context.DeadlineExceeded {
			slog.Error("follow lookup timeout", "username", username, "request_id", requestID)
			app.LogFollowError("DB timeout while looking up user to follow")
		} else {
			slog.Warn("follow target not found", "username", username, "request_id", requestID)
			app.LogFollowError("Could not find user to follow")
		}
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	if user.ID == profileUser.ID {
		slog.Warn("follow self blocked", "username", username, "request_id", requestID)
		app.LogFollowError("User tried to follow themselves")
		http.Redirect(w, r, "/user/"+username, http.StatusSeeOther)
		return
	}

	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, insertErr := app.DB.Collection("follower").InsertOne(ctx, bson.M{
		"who_id":  user.ID,
		"whom_id": profileUser.ID,
	})
	if insertErr != nil {
		if mongo.IsDuplicateKeyError(insertErr) {
			slog.Info("follow duplicate", "username", username, "request_id", requestID)
			session, cookiesErr := app.Store.Get(r, "minitwit-session")
			if cookiesErr == nil {
				session.AddFlash("You are already following \"" + username + "\"")
				_ = session.Save(r, w)
			}
			http.Redirect(w, r, "/user/"+username, http.StatusSeeOther)
			return
		}

		slog.Error("follow database error", "username", username, "error", insertErr.Error(), "request_id", requestID)
		app.LogFollowError("DB error while following user")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	session, cookiesErr := app.Store.Get(r, "minitwit-session")
	if cookiesErr != nil {
		slog.Error("follow session error", "username", username, "error", cookiesErr.Error(), "request_id", requestID)
		app.LogFollowError("Session error while saving follow flash")
	} else {
		session.AddFlash("You are now following \"" + username + "\"")
		_ = session.Save(r, w)
	}
	slog.Info("follow successful", "username", username, "request_id", requestID)

	http.Redirect(w, r, "/user/"+username, http.StatusSeeOther)
}

// UnfollowUser handles unfollowing another user
func UnfollowUser(w http.ResponseWriter, r *http.Request) {
	requestID := requestctx.RequestIDFromRequest(r)
	slog.Debug("unfollow handler called", "request_id", requestID)

	currentUser := r.Context().Value(helpers.UserContextKey)
	if currentUser == nil {
		slog.Warn("unfollow unauthorized", "request_id", requestID)
		app.LogFollowError("Unauthorized user tried to unfollow without login")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	user, ok := currentUser.(*types.User)
	if !ok || user == nil {
		slog.Warn("unfollow user assertion failed", "request_id", requestID)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	username := mux.Vars(r)["username"]
	slog.Debug("unfollow attempt", "username", username, "request_id", requestID)

	var profileUser types.User
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := app.DB.Collection("user").FindOne(ctx, bson.M{"username": username}).Decode(&profileUser)
	if err != nil {
		if err == context.DeadlineExceeded {
			slog.Error("unfollow lookup timeout", "username", username, "request_id", requestID)
			app.LogFollowError("DB timeout while looking up user to unfollow")
		} else {
			slog.Warn("unfollow target not found", "username", username, "request_id", requestID)
			app.LogFollowError("Could not find user to unfollow")
		}
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, deleteErr := app.DB.Collection("follower").DeleteOne(ctx, bson.M{
		"who_id":  user.ID,
		"whom_id": profileUser.ID,
	})
	if deleteErr != nil {
		slog.Error("unfollow database error", "username", username, "error", deleteErr.Error(), "request_id", requestID)
		app.LogFollowError("DB error while unfollowing user")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	session, cookiesErr := app.Store.Get(r, "minitwit-session")
	if cookiesErr != nil {
		slog.Error("unfollow session error", "username", username, "error", cookiesErr.Error(), "request_id", requestID)
		app.LogFollowError("Session error while saving unfollow flash")
	} else {
		if res.DeletedCount == 0 {
			slog.Info("unfollow noop", "username", username, "request_id", requestID)
			session.AddFlash("You were not following \"" + username + "\"")
		} else {
			slog.Info("unfollow successful", "username", username, "request_id", requestID)
			session.AddFlash("You are no longer following \"" + username + "\"")
		}
		_ = session.Save(r, w)
	}

	http.Redirect(w, r, "/user/"+username, http.StatusSeeOther)
}
