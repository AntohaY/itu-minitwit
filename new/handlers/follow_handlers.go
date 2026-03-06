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
		http.Error(w, "Unauthorized", http.StatusUnauthorized) // abort(401)
		app.LogFollowError("Unauthorized user (user not found) tried to follow another user or DB problem")
		return
	}
	user := currentUser.(User)
	username := mux.Vars(r)["username"]
	log.Println("we reded username: " + username)

	// whom_id = get_user_id(username)
	var profileUser User
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := app.DB.Collection("user").FindOne(ctx, bson.M{"username": username}).Decode(&profileUser)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		if err == context.DeadlineExceeded {
			app.LogFollowError("DB Timeout: FindOne took more than 5s for user")
		} else {
			app.LogFollowError("Not found: we couldnt follow some user because he/she doesnt exsit")
		}
		return
	}

	if user.ID == profileUser.ID {
		app.LogFollowError("Logic Error: User (Some user) tried to follow themselves")
		http.Redirect(w, r, "/user/"+username, http.StatusSeeOther)
		return
	}

	whomID := profileUser.ID
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, insertErr := app.DB.Collection("follower").InsertOne(ctx, bson.M{
		"who_id":  user.ID,
		"whom_id": whomID,
	})
	if insertErr != nil {
		app.LogFollowError("DB Error: InsertOne failed for following (some user)")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// g.db.commit() - MongoDB auto-commits
	session, cookies_error := app.Store.Get(r, "minitwit-session")
	if cookies_error != nil {
		app.LogFollowError("error on cookies (flash)")
	} else {
		session.AddFlash("You are now following \"" + username + "\"")
		session.Save(r, w)
	}
	http.Redirect(w, r, "/user/"+username, http.StatusSeeOther)
}

// UnfollowUser handles unfollowing another user
func UnfollowUser(w http.ResponseWriter, r *http.Request) {
	// 1. Auth Check
	currentUser := r.Context().Value("user")
	if currentUser == nil {
		app.LogFollowError("Unauthorized: Someone tried to unfollow without login")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	user := currentUser.(User)
	username := mux.Vars(r)["username"]

	// 2. Find the user to unfollow
	var profileUser User
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel() // Ensures the timer is stopped when function returns

	err := app.DB.Collection("user").FindOne(ctx, bson.M{"username": username}).Decode(&profileUser)
	if err != nil {
		if err == context.DeadlineExceeded {
			app.LogFollowError("DB Timeout: FindOne took more than 5s for user (some user)")
		} else {
			app.LogFollowError("Not Found: Could not unfollow (some user) because they do not exist")
		}
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// 3. Delete the relationship
	// Re-initializing context/cancel for the second DB operation
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, deleteErr := app.DB.Collection("follower").DeleteOne(ctx, bson.M{
		"who_id":  user.ID,
		"whom_id": profileUser.ID,
	})

	if deleteErr != nil {
		app.LogFollowError("DB Error: DeleteOne failed for unfollowing " + username)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return // Prevents redirecting if the deletion failed
	}

	// 4. Handle Flash Messages and Redirect
	session, cookies_error := app.Store.Get(r, "minitwit-session")
	if cookies_error != nil {
		app.LogFollowError("Session Error: Failed to get session for unfollow flash")
	} else {
		session.AddFlash("You are no longer following \"" + username + "\"")
		session.Save(r, w)
	}

	http.Redirect(w, r, "/user/"+username, http.StatusSeeOther)
}
