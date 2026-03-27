package api

import (
	"context"
	"encoding/json"
	"log/slog"
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

func requestIDFromRequest(r *http.Request) string {
	if rid := strings.TrimSpace(r.Header.Get("X-Request-ID")); rid != "" {
		return rid
	}
	return "-"
}

// updateLatest safely updates the global state
func (a *APIHandler) updateLatest(r *http.Request) {
	if latestStr := r.URL.Query().Get("latest"); latestStr != "" {
		if parsed, err := strconv.Atoi(latestStr); err == nil {
			a.LatestMutex.Lock()
			a.LatestValue = parsed
			a.LatestMutex.Unlock()
			slog.Debug("api latest updated", "latest", parsed, "request_id", requestIDFromRequest(r))
		}
	}
}

// AuthMiddleware enforces Simulator Auth
func (a *APIHandler) AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestID := requestIDFromRequest(r)
		slog.Debug("api auth middleware called", "path", r.URL.Path, "method", r.Method, "request_id", requestID)
		a.updateLatest(r)

		// Built-in Go helper to extract credentials
		user, pass, ok := r.BasicAuth()

		// Check if the credentials match "simulator" and "super_safe!"
		if !ok || user != "simulator" || pass != "super_safe!" {
			slog.Warn("api auth failed", "path", r.URL.Path, "method", r.Method, "request_id", requestID)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":    403,
				"error_msg": "You are not authorized to use this resource!",
			})
			return
		}
		slog.Debug("api auth passed", "path", r.URL.Path, "method", r.Method, "request_id", requestID)
		next.ServeHTTP(w, r)
	}
}

// --- ENDPOINTS ---

func (a *APIHandler) GetLatestHandler(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromRequest(r)
	a.LatestMutex.RLock()
	val := a.LatestValue
	a.LatestMutex.RUnlock()
	slog.Debug("api get latest", "latest", val, "request_id", requestID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"latest": val})
}

func (a *APIHandler) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromRequest(r)
	a.updateLatest(r)
	slog.Debug("api register called", "request_id", requestID)
	w.Header().Set("Content-Type", "application/json")

	var payload struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Pwd      string `json:"pwd"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		slog.Warn("api register bad payload", "error", err.Error(), "request_id", requestID)
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
		slog.Warn("api register validation failed", "reason", errMsg, "request_id", requestID)
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
	if _, err := a.DB.Collection("user").InsertOne(context.TODO(), newUser); err != nil {
		slog.Error("api register insert failed", "error", err.Error(), "request_id", requestID)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"status": 500, "error_msg": "Internal Server Error"})
		return
	}
	slog.Info("api register successful", "username", payload.Username, "request_id", requestID)
	w.WriteHeader(http.StatusNoContent)
}

func (a *APIHandler) GetMessagesHandler(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromRequest(r)
	w.Header().Set("Content-Type", "application/json")
	limit := 100
	if parsed, err := strconv.Atoi(r.URL.Query().Get("no")); err == nil {
		limit = parsed
	}
	slog.Debug("api get messages called", "limit", limit, "request_id", requestID)

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

	cursor, err := a.DB.Collection("message").Aggregate(context.TODO(), pipeline)
	if err != nil {
		slog.Error("api get messages query failed", "error", err.Error(), "request_id", requestID)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"status": 500, "error_msg": "Internal Server Error"})
		return
	}
	defer cursor.Close(context.TODO())

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
	slog.Debug("api get messages response", "count", len(response), "request_id", requestID)
	json.NewEncoder(w).Encode(response)
}

// UserMessagesHandler handles fetching and posting messages for a specific user.
func (a *APIHandler) UserMessagesHandler(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromRequest(r)
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	username := vars["username"]
	slog.Debug("api user messages called", "method", r.Method, "username", username, "request_id", requestID)

	// 1. Verify the user exists
	var profileUser User
	err := a.DB.Collection("user").FindOne(context.TODO(), bson.M{"username": username}).Decode(&profileUser)
	if err != nil {
		slog.Warn("api user messages profile not found", "username", username, "request_id", requestID)
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
		cursor, err := a.DB.Collection("message").Find(context.TODO(), bson.M{
			"author_id": profileUser.ID,
			"flagged":   false,
		}, opts)
		if err != nil {
			slog.Error("api user messages query failed", "username", username, "error", err.Error(), "request_id", requestID)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer cursor.Close(context.TODO())

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
		slog.Debug("api user messages response", "username", username, "count", len(response), "request_id", requestID)
		json.NewEncoder(w).Encode(response)

	} else if r.Method == http.MethodPost {
		// POST: Add a new message as this user
		var payload struct {
			Content string `json:"content"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			slog.Warn("api user message bad payload", "username", username, "error", err.Error(), "request_id", requestID)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		doc := bson.M{
			"author_id": profileUser.ID,
			"text":      payload.Content,
			"pub_date":  time.Now().Unix(),
			"flagged":   false,
		}
		if _, err := a.DB.Collection("message").InsertOne(context.TODO(), doc); err != nil {
			slog.Error("api user message insert failed", "username", username, "error", err.Error(), "request_id", requestID)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		slog.Info("api user message created", "username", username, "text_length", len(payload.Content), "request_id", requestID)
		w.WriteHeader(http.StatusNoContent) // 204 Success, No Content
	}
}

// FollowsHandler manages fetching followers and handling follow/unfollow requests.
func (a *APIHandler) FollowsHandler(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromRequest(r)
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	username := vars["username"]
	slog.Debug("api follows called", "method", r.Method, "username", username, "request_id", requestID)

	var profileUser User
	err := a.DB.Collection("user").FindOne(context.TODO(), bson.M{"username": username}).Decode(&profileUser)
	if err != nil {
		slog.Warn("api follows profile not found", "username", username, "request_id", requestID)
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
		cursor, err := a.DB.Collection("follower").Find(context.TODO(), bson.M{"who_id": profileUser.ID}, opts)
		if err != nil {
			slog.Error("api follows list query failed", "username", username, "error", err.Error(), "request_id", requestID)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer cursor.Close(context.TODO())

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
		slog.Debug("api follows list response", "username", username, "count", len(follows), "request_id", requestID)
		json.NewEncoder(w).Encode(map[string]interface{}{"follows": follows})

	} else if r.Method == http.MethodPost {
		// POST: Follow or Unfollow
		var payload map[string]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			slog.Warn("api follows bad payload", "username", username, "error", err.Error(), "request_id", requestID)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Check if the payload is a "follow" request
		if followTarget, ok := payload["follow"]; ok {
			var target User
			if a.DB.Collection("user").FindOne(context.TODO(), bson.M{"username": followTarget}).Decode(&target) == nil {
				if _, err := a.DB.Collection("follower").InsertOne(context.TODO(), bson.M{
					"who_id":  profileUser.ID,
					"whom_id": target.ID,
				}); err != nil {
					slog.Error("api follow insert failed", "username", username, "target", followTarget, "error", err.Error(), "request_id", requestID)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				slog.Info("api follow successful", "username", username, "target", followTarget, "request_id", requestID)
			} else {
				slog.Warn("api follow target not found", "username", username, "target", followTarget, "request_id", requestID)
				w.WriteHeader(http.StatusNotFound)
				return
			}
			// Check if the payload is an "unfollow" request
		} else if unfollowTarget, ok := payload["unfollow"]; ok {
			var target User
			if a.DB.Collection("user").FindOne(context.TODO(), bson.M{"username": unfollowTarget}).Decode(&target) == nil {
				if _, err := a.DB.Collection("follower").DeleteOne(context.TODO(), bson.M{
					"who_id":  profileUser.ID,
					"whom_id": target.ID,
				}); err != nil {
					slog.Error("api unfollow delete failed", "username", username, "target", unfollowTarget, "error", err.Error(), "request_id", requestID)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				slog.Info("api unfollow successful", "username", username, "target", unfollowTarget, "request_id", requestID)
			} else {
				slog.Warn("api unfollow target not found", "username", username, "target", unfollowTarget, "request_id", requestID)
				w.WriteHeader(http.StatusNotFound)
				return
			}
		} else {
			slog.Warn("api follows invalid action payload", "username", username, "request_id", requestID)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		slog.Debug("api follows mutation completed", "username", username, "request_id", requestID)
		w.WriteHeader(http.StatusNoContent) // 204 Success, No Content
	}
}
