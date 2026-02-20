package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// We redefine minimal structs here so we don't need to import 'main'
type User struct {
	ID       primitive.ObjectID `bson:"_id,omitempty"`
	Username string             `bson:"username"`
	Email    string             `bson:"email"`
	PW       string             `bson:"pw"`
	HashedPW string             `bson:"hashedpw"`
}

// APIHandler holds the dependencies our API routes need
type APIHandler struct {
	DB          *mongo.Database
	LatestValue int
	LatestMutex sync.RWMutex
}

// NewAPI initializes the API handler with your database connection
func NewAPI(db *mongo.Database) *APIHandler {
	return &APIHandler{
		DB:          db,
		LatestValue: -1,
	}
}

// updateLatest safely updates the global state
func (a *APIHandler) updateLatest(r *http.Request) {
	if latestStr := r.URL.Query().Get("latest"); latestStr != "" {
		if parsed, err := strconv.Atoi(latestStr); err == nil {
			a.LatestMutex.Lock()
			a.LatestValue = parsed
			a.LatestMutex.Unlock()
		}
	}
}

// AuthMiddleware enforces Simulator Auth
func (a *APIHandler) AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a.updateLatest(r)

		if r.Header.Get("Authorization") != "Basic c2ltdWxhdG9yOnN1cGVyX3NhZmUh" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":    403,
				"error_msg": "You are not authorized to use this resource!",
			})
			return
		}
		next.ServeHTTP(w, r)
	}
}

// --- ENDPOINTS ---

func (a *APIHandler) GetLatestHandler(w http.ResponseWriter, r *http.Request) {
	a.LatestMutex.RLock()
	val := a.LatestValue
	a.LatestMutex.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"latest": val})
}

func (a *APIHandler) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	a.updateLatest(r)
	w.Header().Set("Content-Type", "application/json")

	var payload struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Pwd      string `json:"pwd"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"status": 400, "error_msg": "Bad Request"})
		return
	}

	var errMsg string
	if payload.Username == "" {
		errMsg = "You have to enter a username"
	} else if payload.Email == "" || !strings.Contains(payload.Email, "@") {
		errMsg = "You have to enter a valid email address"
	} else if payload.Pwd == "" {
		errMsg = "You have to enter a password"
	} else {
		// Check if user exists
		var existing User
		err := a.DB.Collection("user").FindOne(context.TODO(), bson.M{"username": payload.Username}).Decode(&existing)
		if err == nil { // User found
			errMsg = "The username is already taken"
		}
	}

	if errMsg != "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"status": 400, "error_msg": errMsg})
		return
	}

	newUser := User{
		Username: payload.Username,
		Email:    payload.Email,
		PW:       payload.Pwd,
		HashedPW: payload.Pwd,
	}
	a.DB.Collection("user").InsertOne(context.TODO(), newUser)
	w.WriteHeader(http.StatusNoContent)
}

func (a *APIHandler) GetMessagesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	limit := 100
	if parsed, err := strconv.Atoi(r.URL.Query().Get("no")); err == nil {
		limit = parsed
	}

	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.D{{Key: "flagged", Value: false}}}},
		{{Key: "$sort", Value: bson.D{{Key: "pub_date", Value: -1}}}},
		{{Key: "$limit", Value: limit}},
		{{Key: "$lookup", Value: bson.D{
			{Key: "from", Value: "user"},
			{Key: "localField", Value: "author_id"},
			{Key: "foreignField", Value: "_id"},
			{Key: "as", Value: "author_info"},
		}}},
		{{Key: "$unwind", Value: "$author_info"}},
	}

	cursor, _ := a.DB.Collection("message").Aggregate(context.TODO(), pipeline)

	type ApiMsg struct {
		Content string `json:"content"`
		PubDate string `json:"pub_date"`
		User    string `json:"user"`
	}
	response := []ApiMsg{}

	for cursor.Next(context.TODO()) {
		var result struct {
			Text    string `bson:"text"`
			PubDate int64  `bson:"pub_date"`
			Author  struct {
				Username string `bson:"username"`
			} `bson:"author_info"`
		}
		if err := cursor.Decode(&result); err == nil {
			// Simplified timezone format for API
			t := time.Unix(result.PubDate, 0).UTC().Format("2006-01-02 @ 15:04")
			response = append(response, ApiMsg{Content: result.Text, PubDate: t, User: result.Author.Username})
		}
	}
	json.NewEncoder(w).Encode(response)
}

// UserMessagesHandler handles fetching and posting messages for a specific user.
func (a *APIHandler) UserMessagesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	username := vars["username"]

	// 1. Verify the user exists
	var profileUser User
	err := a.DB.Collection("user").FindOne(context.TODO(), bson.M{"username": username}).Decode(&profileUser)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	if r.Method == http.MethodGet {
		// GET: Fetch timeline for this user
		limit := 100
		if parsed, err := strconv.Atoi(r.URL.Query().Get("no")); err == nil {
			limit = parsed
		}

		opts := options.Find().SetSort(bson.M{"pub_date": -1}).SetLimit(int64(limit))
		cursor, _ := a.DB.Collection("message").Find(context.TODO(), bson.M{
			"author_id": profileUser.ID,
			"flagged":   false,
		}, opts)

		type ApiMsg struct {
			Content string `json:"content"`
			PubDate string `json:"pub_date"`
			User    string `json:"user"`
		}

		// Initialize as empty slice to ensure JSON returns [] instead of null if empty
		response := []ApiMsg{}

		for cursor.Next(context.TODO()) {
			var raw struct {
				Text    string `bson:"text"`
				PubDate int64  `bson:"pub_date"`
			}
			if err := cursor.Decode(&raw); err == nil {
				// Ensure the date matches what the Python version output
				t := time.Unix(raw.PubDate, 0).UTC().Format("2006-01-02 @ 15:04")
				response = append(response, ApiMsg{
					Content: raw.Text,
					PubDate: t,
					User:    profileUser.Username,
				})
			}
		}
		json.NewEncoder(w).Encode(response)

	} else if r.Method == http.MethodPost {
		// POST: Add a new message as this user
		var payload struct {
			Content string `json:"content"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		doc := bson.M{
			"author_id": profileUser.ID,
			"text":      payload.Content,
			"pub_date":  time.Now().Unix(),
			"flagged":   false,
		}
		a.DB.Collection("message").InsertOne(context.TODO(), doc)
		w.WriteHeader(http.StatusNoContent) // 204 Success, No Content
	}
}

// FollowsHandler manages fetching followers and handling follow/unfollow requests.
func (a *APIHandler) FollowsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	username := vars["username"]

	var profileUser User
	err := a.DB.Collection("user").FindOne(context.TODO(), bson.M{"username": username}).Decode(&profileUser)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	if r.Method == http.MethodGet {
		// GET: Fetch list of usernames this user follows
		limit := 100
		if parsed, err := strconv.Atoi(r.URL.Query().Get("no")); err == nil {
			limit = parsed
		}

		opts := options.Find().SetLimit(int64(limit))
		cursor, _ := a.DB.Collection("follower").Find(context.TODO(), bson.M{"who_id": profileUser.ID}, opts)

		follows := []string{} // Initialize as empty slice
		for cursor.Next(context.TODO()) {
			var rel struct {
				WhomID primitive.ObjectID `bson:"whom_id"`
			}
			if err := cursor.Decode(&rel); err == nil {
				// Lookup the username for each whom_id
				var target User
				if a.DB.Collection("user").FindOne(context.TODO(), bson.M{"_id": rel.WhomID}).Decode(&target) == nil {
					follows = append(follows, target.Username)
				}
			}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"follows": follows})

	} else if r.Method == http.MethodPost {
		// POST: Follow or Unfollow
		var payload map[string]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Check if the payload is a "follow" request
		if followTarget, ok := payload["follow"]; ok {
			var target User
			if a.DB.Collection("user").FindOne(context.TODO(), bson.M{"username": followTarget}).Decode(&target) == nil {
				a.DB.Collection("follower").InsertOne(context.TODO(), bson.M{
					"who_id":  profileUser.ID,
					"whom_id": target.ID,
				})
			} else {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			// Check if the payload is an "unfollow" request
		} else if unfollowTarget, ok := payload["unfollow"]; ok {
			var target User
			if a.DB.Collection("user").FindOne(context.TODO(), bson.M{"username": unfollowTarget}).Decode(&target) == nil {
				a.DB.Collection("follower").DeleteOne(context.TODO(), bson.M{
					"who_id":  profileUser.ID,
					"whom_id": target.ID,
				})
			} else {
				w.WriteHeader(http.StatusNotFound)
				return
			}
		}

		w.WriteHeader(http.StatusNoContent) // 204 Success, No Content
	}
}
