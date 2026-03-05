package handlers

import (
	"context"
	"log"
	"net/http"
	"time"

	"minitwit/app"
	. "minitwit/types"

	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
)

// FollowUser handles following another user
func FollowUser(w http.ResponseWriter, r *http.Request) {
	currentUser := r.Context().Value("user")
	if currentUser == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	user := currentUser.(User)
	username := mux.Vars(r)["username"]
	log.Println("we reded username: " + username)

	var profileUser User
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := app.DB.Collection("user").FindOne(ctx, bson.M{"username": username}).Decode(&profileUser)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	whomID := profileUser.ID

	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	app.DB.Collection("follower").InsertOne(ctx, bson.M{
		"who_id":  user.ID,
		"whom_id": whomID,
	})

	session, _ := app.Store.Get(r, "minitwit-session")
	session.AddFlash("You are now following \"" + username + "\"")
	session.Save(r, w)

	http.Redirect(w, r, "/user/"+username, http.StatusSeeOther)
}

// UnfollowUser handles unfollowing another user
func UnfollowUser(w http.ResponseWriter, r *http.Request) {
	currentUser := r.Context().Value("user")
	if currentUser == nil {
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
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	whomID := profileUser.ID

	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	app.DB.Collection("follower").DeleteOne(ctx, bson.M{
		"who_id":  user.ID,
		"whom_id": whomID,
	})

	session, _ := app.Store.Get(r, "minitwit-session")
	session.AddFlash("You are no longer following \"" + username + "\"")
	session.Save(r, w)

	http.Redirect(w, r, "/user/"+username, http.StatusSeeOther)
}
