package handlers

import (
	"context"
	"net/http"
	"time"

	"minitwit/app"
	. "minitwit/types"

	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// FollowUser handles following another user
func FollowUser(w http.ResponseWriter, r *http.Request) {
	currentUser := r.Context().Value("user")
	if currentUser == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		app.LogFollowError("Unauthorized user tried to follow another user")
		return
	}

	user := currentUser.(User)
	username := mux.Vars(r)["username"]

	var profileUser User
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := app.DB.Collection("user").FindOne(ctx, bson.M{"username": username}).Decode(&profileUser)
	if err != nil {
		if err == context.DeadlineExceeded {
			app.LogFollowError("DB timeout while looking up user " + username)
		} else {
			app.LogFollowError("Could not find user to follow: " + username)
		}
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	if user.ID == profileUser.ID {
		app.LogFollowError("User tried to follow themselves: " + username)
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
			session, cookiesErr := app.Store.Get(r, "minitwit-session")
			if cookiesErr == nil {
				session.AddFlash("You are already following \"" + username + "\"")
				_ = session.Save(r, w)
			}
			http.Redirect(w, r, "/user/"+username, http.StatusSeeOther)
			return
		}

		app.LogFollowError("DB error while following " + username + ": " + insertErr.Error())
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	session, cookiesErr := app.Store.Get(r, "minitwit-session")
	if cookiesErr != nil {
		app.LogFollowError("Session error while saving follow flash for " + username)
	} else {
		session.AddFlash("You are now following \"" + username + "\"")
		_ = session.Save(r, w)
	}

	http.Redirect(w, r, "/user/"+username, http.StatusSeeOther)
}

// UnfollowUser handles unfollowing another user
func UnfollowUser(w http.ResponseWriter, r *http.Request) {
	currentUser := r.Context().Value("user")
	if currentUser == nil {
		app.LogFollowError("Unauthorized user tried to unfollow without login")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	user := currentUser.(User)
	username := mux.Vars(r)["username"]

	var profileUser User
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := app.DB.Collection("user").FindOne(ctx, bson.M{"username": username}).Decode(&profileUser)
	if err != nil {
		if err == context.DeadlineExceeded {
			app.LogFollowError("DB timeout while looking up user to unfollow: " + username)
		} else {
			app.LogFollowError("Could not find user to unfollow: " + username)
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
		app.LogFollowError("DB error while unfollowing " + username + ": " + deleteErr.Error())
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	session, cookiesErr := app.Store.Get(r, "minitwit-session")
	if cookiesErr != nil {
		app.LogFollowError("Session error while saving unfollow flash for " + username)
	} else {
		if res.DeletedCount == 0 {
			session.AddFlash("You were not following \"" + username + "\"")
		} else {
			session.AddFlash("You are no longer following \"" + username + "\"")
		}
		_ = session.Save(r, w)
	}

	http.Redirect(w, r, "/user/"+username, http.StatusSeeOther)
}
