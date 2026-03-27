package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"minitwit/app"
	. "minitwit/helpers/flashes"
	"minitwit/helpers/requestctx"
	. "minitwit/types"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// RegisterHandler manages user sign-ups by validating form data and saving new users to the DB.
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	requestID := requestctx.RequestIDFromRequest(r)
	slog.Debug("register handler called", "method", r.Method, "request_id", requestID)

	user := r.Context().Value("user")
	if user != nil {
		slog.Info("register skipped for authenticated user", "request_id", requestID)
		SetFlash(w, "You are already logged in as "+user.(User).Username)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	errMsg := ""
	if r.Method == http.MethodPost {
		r.ParseForm()
		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")
		password2 := r.FormValue("password2")
		slog.Debug("register attempt", "username", username, "request_id", requestID)

		if username == "" {
			errMsg = "You have to enter a username"
		} else if email == "" || !strings.Contains(email, "@") {
			errMsg = "You have to enter a valid email address"
		} else if password == "" {
			errMsg = "You have to enter a password"
		} else if password != password2 {
			errMsg = "The two passwords do not match"
		} else if app.GetUserID(username) != primitive.NilObjectID {
			errMsg = "The username is already taken"
		} else {
			newUser := User{
				Username: username,
				Email:    email,
				PW:       password,
				HashedPW: password,
			}
			if _, err := app.DB.Collection("user").InsertOne(ctx, newUser); err != nil {
				slog.Error("registration database error", "error", err.Error(), "request_id", requestID)
				data := TimelineUserData{
					PageTitle: "Register",
					Flashes:   []string{"Database error occurred"},
				}
				app.RenderTemplate(w, "register.html", data)
				return
			}
			slog.Info("registration successful", "username", username, "request_id", requestID)
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
	}

	data := TimelineUserData{
		PageTitle: "Register",
		Flashes:   []string{},
	}

	if errMsg != "" {
		slog.Warn("registration validation failed", "reason", errMsg, "request_id", requestID)
		data.Flashes = append(data.Flashes, errMsg)
	}
	slog.Debug("render register page", "request_id", requestID)
	app.RenderTemplate(w, "register.html", data)
}

// LoginHandler handles user authentication
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	requestID := requestctx.RequestIDFromRequest(r)
	slog.Debug("login handler called", "method", r.Method, "request_id", requestID)

	user := r.Context().Value("user")
	if user != nil {
		slog.Info("login skipped for authenticated user", "request_id", requestID)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	var flashes []string

	if r.Method == http.MethodPost {
		r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")
		slog.Debug("login attempt", "username", username, "request_id", requestID)

		var foundUser User
		filter := bson.M{"username": username}

		dberr := app.DB.Collection("user").FindOne(ctx, filter).Decode(&foundUser)
		if dberr != nil {
			if dberr == mongo.ErrNoDocuments {
				slog.Warn("login failed", "reason", "user_not_found", "request_id", requestID)
				flashes = append(flashes, "Invalid username")
			} else {
				flashes = append(flashes, "Database error occurred")
				slog.Error("login database error", "error", dberr.Error(), "request_id", requestID)
			}
		} else {
			if !app.CheckPasswordHash(password, foundUser.HashedPW) {
				slog.Warn("login failed", "reason", "invalid_password", "request_id", requestID)
				flashes = append(flashes, "Invalid password")
			} else {
				session, _ := app.Store.Get(r, "minitwit-session")
				session.Values["user_id"] = foundUser.ID.Hex()
				session.Save(r, w)
				slog.Info("login successful", "request_id", requestID)
				http.Redirect(w, r, "/", http.StatusFound)
				return
			}
		}
	}

	slog.Debug("render login page", "request_id", requestID)
	app.RenderTemplate(w, "login.html", nil)
}

// LogoutHandler handles user logout
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	requestID := requestctx.RequestIDFromRequest(r)
	slog.Debug("logout handler called", "request_id", requestID)
	session, _ := app.Store.Get(r, "minitwit-session")
	session.AddFlash("You were logged out")
	for k := range session.Values {
		delete(session.Values, k)
	}
	if err := session.Save(r, w); err != nil {
		slog.Error("logout session save error", "error", err.Error(), "request_id", requestID)
	} else {
		slog.Info("logout successful", "request_id", requestID)
	}
	http.Redirect(w, r, "/", http.StatusFound)
}
